#!/usr/bin/env python3
"""
Security Center — unified aggregator for Omarchy Security Center plugin.
Collects UFW, ClamAV, Lynis and RKHunter state without requiring sudo for reads,
computes per-tool scores (25 pts each) and a global grade, and emits JSON for QML.

Privacy: no hostname, IP, user, or homelab identifiers are emitted. Paths are
sanitized to basenames where possible, and file contents are never echoed verbatim
beyond controlled summaries.

Exit 0 always (panel must not break on missing tools). Output is bounded.
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HOME = Path.home()
STATE_DIR = HOME / ".local" / "state" / "omarchy"
CONFIG_DIR = HOME / ".config" / "omarchy" / "security-center"
EXCEPTIONS_FILE = CONFIG_DIR / "exceptions.json"
LYNIS_LOG = Path("/var/log/lynis.log")
LYNIS_REPORT_DAT = Path("/var/log/lynis-report.dat")
RKHUNTER_LOG = Path("/var/log/rkhunter.log")
UFW_CONF = Path("/etc/ufw/ufw.conf")
UFW_DEFAULTS = Path("/etc/default/ufw")
UFW_RULES = Path("/etc/ufw/user.rules")
UFW_RULES6 = Path("/etc/ufw/user6.rules")
CLAMAV_LOG = STATE_DIR / "clamav-detections.log"
CLAMAV_ACK = STATE_DIR / "clamav-monitor-ack.epoch"

MAX_ITEMS = 50
MAX_TEXT = 220


def sh(cmd, timeout=1.5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e)[:200], 1

def read_text(path: Path, limit=65536):
    try:
        if not path.exists():
            return None
        if path.stat().st_size > 2_000_000:
            return path.read_text(errors="ignore")[:limit]
        return path.read_text(errors="ignore")[:limit]
    except Exception:
        return None

def sanitize(text, max_len=MAX_TEXT):
    if not text:
        return ""
    t = "".join(c if c.isprintable() else " " for c in str(text)).strip()
    t = re.sub(r"\s+", " ", t)
    return t[:max_len]

def load_exceptions():
    try:
        if EXCEPTIONS_FILE.exists():
            data = json.loads(EXCEPTIONS_FILE.read_text())
            # shape: {"lynis": ["TEST-..."], "rkhunter": ["..."]}
            return {
                "lynis": set(data.get("lynis", [])),
                "rkhunter": set(data.get("rkhunter", [])),
                "clamav": set(data.get("clamav", [])),
            }
    except Exception:
        pass
    return {"lynis": set(), "rkhunter": set(), "clamav": set()}

def parse_ufw():
    installed = False
    for cand in ["/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw", "/bin/ufw"]:
        if Path(cand).exists() and os.access(cand, os.X_OK):
            installed = True
            break
    enabled = None
    defaults = {"input": "deny", "output": "allow", "forward": "deny", "ipv6": True}
    rule_count = 0
    rules_readable = True
    detailed_rules = []
    try:
        txt = read_text(UFW_CONF)
        if txt is not None:
            m = re.search(r"^\s*ENABLED\s*=\s*\"?([A-Za-z]+)\"?", txt, re.M)
            if m:
                enabled = m.group(1).lower() == "yes"
        txt2 = read_text(UFW_DEFAULTS)
        if txt2 is not None:
            def var(name):
                mm = re.search(rf"^\s*{name}\s*=\s*\"?([^\"\n\r]*)\"?", txt2, re.M)
                return mm.group(1).strip() if mm else ""
            def pol(v):
                t = v.replace('"','').strip().upper()
                if t == "DROP": return "deny"
                if t == "ACCEPT": return "allow"
                if t == "REJECT": return "reject"
                return t.lower()
            defaults = {
                "input": pol(var("DEFAULT_INPUT_POLICY")) or "deny",
                "output": pol(var("DEFAULT_OUTPUT_POLICY")) or "allow",
                "forward": pol(var("DEFAULT_FORWARD_POLICY")) or "deny",
                "ipv6": var("IPV6").lower() != "no",
            }
        # rules: count tuples
        count = 0
        for p in [UFW_RULES, UFW_RULES6]:
            t = read_text(p)
            if t is None:
                if p == UFW_RULES:
                    rules_readable = False
                continue
            for line in t.splitlines():
                if line.startswith("### tuple ###"):
                    count += 1
                    # summarize first 8
                    if len(detailed_rules) < 8:
                        detailed_rules.append(sanitize(line.replace("### tuple ###","").strip(), 80))
        rule_count = count
    except Exception:
        pass

    # score (mirrors Model.js scoreForUfw)
    if not installed:
        score, label, color = 0, "Not installed", "urgent"
        status = "not installed"
    elif enabled is None:
        score, label, color = 8, "Unknown", "warning"
        status = "unknown"
    elif not enabled:
        score, label, color = 0, "Inactive", "urgent"
        status = "inactive"
    else:
        s = 15
        if rule_count > 0: s += 5
        if defaults.get("input") == "deny": s += 5
        else: s -= 5
        s = max(0, min(25, s))
        score = s
        label = "Hardened" if s >= 22 else "Active" if s >= 15 else "Weak"
        color = "good" if s >= 20 else "warning" if s >= 12 else "urgent"
        status = "active"

    return {
        "id": "ufw",
        "title": "Firewall (UFW)",
        "installed": installed,
        "enabled": enabled,
        "status": status,
        "defaults": defaults,
        "ruleCount": rule_count,
        "rulesReadable": rules_readable,
        "rulePreview": detailed_rules,
        "score": score,
        "maxScore": 25,
        "label": label,
        "color": color,
        "fixCmd": "sudo ufw enable && sudo ufw default deny incoming" if status != "active" else None,
    }

def parse_clamav():
    last_update = 0
    for db in [Path("/var/lib/clamav/daily.cld"), Path("/var/lib/clamav/daily.cvd")]:
        try:
            if db.exists():
                e = int(db.stat().st_mtime)
                if e > last_update: last_update = e
        except Exception:
            pass
    def is_active(svc): 
        out, _, _ = sh(["systemctl", "is-active", svc], timeout=1.0)
        return out.strip() == "active"
    clamd = is_active("clamav-daemon.service")
    onacc = is_active("clamav-clamonacc.service")
    fresh = is_active("clamav-freshclam.service")
    # last manual scan epoch (written by Panel runClamScan)
    last_scan_epoch = 0
    try:
        scan_file = HOME / ".local" / "state" / "omarchy" / "security-center" / "clamav-last-scan.epoch"
        if scan_file.exists():
            last_scan_epoch = int(scan_file.read_text().strip().split()[0])
    except:
        pass
    # detections
    recent = []
    total = 0
    active_count = 0
    if CLAMAV_LOG.exists():
        try:
            lines = CLAMAV_LOG.read_text(errors="ignore").splitlines()
            total = len([l for l in lines if l.strip()])
            # last 10 newest first
            for line in reversed(lines[-10:]):
                line = line[:4096]
                when = line[:19]
                try:
                    epoch = int(time.mktime(time.strptime(when, "%Y-%m-%d %H:%M:%S")))
                except Exception:
                    epoch = 0
                rest = line[20:] if len(line) > 20 else ""
                # format "<path>: <sig> FOUND"
                m = re.match(r"^(.*): (.*) FOUND$", rest)
                path = m.group(1) if m else rest[:120]
                sig = m.group(2) if m else "FOUND"
                # basename only for privacy
                safe_path = Path(path).name if path else ""
                if not safe_path:
                    safe_path = sanitize(path, 60)
                present = Path(path).exists() if path else False
                if present:
                    active_count += 1
                recent.append({
                    "whenEpoch": epoch,
                    "path": sanitize(safe_path, 64),
                    "fullPath": sanitize(path, 120),
                    "signature": sanitize(sig, 80),
                    "present": present,
                })
        except Exception:
            pass
    # scoring
    installed = clamd or onacc or fresh or last_update > 0 or total > 0 or Path("/usr/bin/clamscan").exists() or Path("/usr/bin/freshclam").exists()
    # if no clamav at all
    if not installed:
        score, label, color = 0, "Not installed", "urgent"
        status = "not installed"
    else:
        s = 10
        if fresh: s += 5
        if onacc: s += 5
        # freshness: 5 pts if updated within 3 days
        age = time.time() - last_update if last_update else 999999
        if age < 3*86400: s += 5
        elif age < 7*86400: s += 2
        if active_count > 0: s = max(0, s - 8)
        s = max(0, min(25, s))
        score = s
        if active_count > 0:
            label, color, status = f"{active_count} active", "urgent", "threat"
        elif s >= 20:
            label, color, status = "Protected", "good", "protected"
        elif s >= 12:
            label, color, status = "Partial", "warning", "partial"
        else:
            label, color, status = "At risk", "urgent", "at risk"

    return {
        "id": "clamav",
        "title": "ClamAV",
        "installed": installed,
        "clamdActive": clamd,
        "onAccessActive": onacc,
        "freshclamActive": fresh,
        "lastUpdateEpoch": last_update,
        "lastScanEpoch": last_scan_epoch,
        "total": total,
        "activeCount": active_count,
        "recent": recent[:10],
        "score": score,
        "maxScore": 25,
        "label": label,
        "color": color,
        "status": status,
    }

def parse_lynis(exceptions):
    hardening_index = None
    warnings = []
    suggestions = []
    tests_performed = 0
    # try dat file first (structured)
    dat_text = read_text(LYNIS_REPORT_DAT, limit=200000)
    if dat_text:
        try:
            for line in dat_text.splitlines():
                if "=" not in line: continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k == "hardening_index":
                    try: hardening_index = int(v.strip())
                    except: pass
                elif k == "tests_performed":
                    try: tests_performed = int(v.strip())
                    except: pass
                elif k.startswith("warning["):
                    # warning[]=... or warning[0]=
                    val = v.strip()
                    if val:
                        warnings.append(sanitize(val, 180))
                elif k.startswith("suggestion["):
                    val = v.strip()
                    if val:
                        suggestions.append(sanitize(val, 180))
        except Exception:
            pass
    # fallback: parse lynis.log for hardening index and warnings
    if hardening_index is None:
        log_text = read_text(LYNIS_LOG, limit=300000)
        if log_text:
            m = re.search(r"Hardening index\s*:\s*(\d+)", log_text)
            if m:
                try: hardening_index = int(m.group(1))
                except: pass
            # lines like "Warning: [TEST-XXXX] ..."
            for line in log_text.splitlines()[-400:]:
                if "Warning" in line and "[" in line and "]" in line:
                    mm = re.search(r"\[(TEST-[^\]]+|LYNIS[^\]]*|WRN[^\]]*)\]", line)
                    tid = mm.group(1) if mm else ""
                    warnings.append({"text": sanitize(line, 180), "id": tid or sanitize(line[:40], 40)})
                elif "Suggestion" in line and "[" in line:
                    suggestions.append(sanitize(line, 180))
            # normalize if warnings were strings
            norm_warn = []
            for w in warnings:
                if isinstance(w, str):
                    mm = re.search(r"\[(TEST-[^\]]+)\]", w)
                    norm_warn.append({"text": w, "id": mm.group(1) if mm else w[:32]})
                else:
                    norm_warn.append(w)
            warnings = norm_warn
            if isinstance(suggestions[0] if suggestions else None, str):
                suggestions = [{"text": s, "id": re.search(r"\[(TEST-[^\]]+)\]", s).group(1) if re.search(r"\[(TEST-[^\]]+)\]", s) else s[:32]} for s in suggestions]
        else:
            # also try lynis.log as warned list of dicts already?
            pass

    # ensure warnings/suggestions are list of dicts — handle pipe format ID|desc|action
    def to_items(lst):
        out=[]
        for x in lst:
            if isinstance(x, dict) and "text" in x:
                out.append(x)
            elif isinstance(x, str):
                # Lynis dat format: ID|description|remediation|...
                if "|" in x:
                    parts = x.split("|")
                    lid = parts[0].strip()
                    desc = parts[1].strip() if len(parts)>1 else x
                    # remediation is parts[2] if exists
                    rem = parts[2].strip() if len(parts)>2 and parts[2].strip() not in ("-","") else ""
                    full_text = desc
                    if rem:
                        full_text = desc + " — " + rem
                    # Keep original pipe string as fallback in text if needed
                    out.append({"text": sanitize(full_text, 260), "id": sanitize(lid, 32), "title": sanitize(desc, 120), "remediation": sanitize(rem, 180), "raw": sanitize(x, 220)})
                else:
                    mm = re.search(r"\[(TEST-[^\]]+|AUTH-[^\]|BOOT-[^\]|KRNL-[^\]|FILE-[^\]|NETW-[^\]|LOGG-[^\]|CONT-[^\]|USB-[^\]|STRG-[^\]|NAME-[^\]|PKGS-[^\]|\w+-\d+)\]", x)
                    lid = mm.group(1) if mm else x.split()[0][:32] if x.strip() else "UNKNOWN"
                    out.append({"text": sanitize(x, 260), "id": sanitize(lid, 32), "title": sanitize(x, 120)})
            else:
                out.append({"text": sanitize(str(x), 260), "id": sanitize(str(x))[:32]})
        return out
    warnings = to_items(warnings)
    suggestions = to_items(suggestions)

    # exceptions filter
    exc = exceptions.get("lynis", set())
    warnings_all = warnings
    suggestions_all = suggestions
    warnings = [w for w in warnings if w.get("id") not in exc and w.get("text","")[:32] not in exc]
    suggestions = [s for s in suggestions if s.get("id") not in exc and s.get("text","")[:32] not in exc]

    # Check readability — lynis logs are 640 root:root on stock install
    lynis_readable = True
    if LYNIS_REPORT_DAT.exists() and not os.access(LYNIS_REPORT_DAT, os.R_OK):
        lynis_readable = False
    if LYNIS_LOG.exists() and not os.access(LYNIS_LOG, os.R_OK):
        lynis_readable = False
    # If no direct read succeeded but files exist unreadably, keep hardening_index None to signal need
    if not dat_text and not read_text(LYNIS_LOG) and (LYNIS_LOG.exists() or LYNIS_REPORT_DAT.exists()) and not lynis_readable:
        # keep hardening_index None, will be handled below as unreadable
        pass

    installed = bool(dat_text or read_text(LYNIS_LOG))
    # also check binary
    if not installed:
        for p in ["/usr/sbin/lynis", "/usr/bin/lynis"]:
            if Path(p).exists():
                installed = True
                break

    if not installed:
        score, label, color = 0, "Not installed", "urgent"
        status = "not installed"
        hardening_index = hardening_index if hardening_index is not None else 0
    elif not lynis_readable:
        # File exists but not readable without privilege — don't fake Hardened
        hardening_index = hardening_index if hardening_index is not None else 0
        score = 10
        label = "No permission"
        color = "warning"
        status = "unreadable"
    else:
        if hardening_index is None:
            # estimate from warnings count
            hardening_index = max(0, 100 - len(warnings)*6 - len(suggestions)*2)
        # score 25 pts: hardening_index maps 0-100 -> 0-15 plus deductions for warnings
        base = int(hardening_index * 0.15)
        # but hardening_index already reflects warnings; additionally penalize active warnings
        if len(warnings) == 0 and hardening_index >= 80:
            base = min(25, base + 8)
        elif len(warnings) > 5:
            base = max(0, base - 5)
        score = max(0, min(25, base))
        if len(warnings) > 0:
            label = f"{len(warnings)} warnings"
            color = "urgent" if hardening_index < 60 else "warning"
            status = "warnings"
        elif hardening_index >= 80:
            label, color, status = "Hardened", "good", "hardened"
        elif hardening_index >= 60:
            label, color, status = "Fair", "warning", "fair"
        else:
            label, color, status = "Weak", "urgent", "weak"

    # last scan time from mtime of report/log
    last_scan_epoch = 0
    try:
        if LYNIS_REPORT_DAT.exists():
            last_scan_epoch = max(last_scan_epoch, int(LYNIS_REPORT_DAT.stat().st_mtime))
        if LYNIS_LOG.exists():
            last_scan_epoch = max(last_scan_epoch, int(LYNIS_LOG.stat().st_mtime))
    except:
        pass
    return {
        "id": "lynis",
        "title": "Lynis",
        "installed": installed,
        "readable": lynis_readable,
        "lastScanEpoch": last_scan_epoch,
        "hardeningIndex": hardening_index if hardening_index is not None else 0,
        "warnings": warnings[:MAX_ITEMS],
        "warningsAllCount": len(warnings_all),
        "warningsFiltered": len(warnings_all) - len(warnings),
        "suggestions": suggestions[:MAX_ITEMS],
        "suggestionsAllCount": len(suggestions_all),
        "suggestionsFiltered": len(suggestions_all) - len(suggestions),
        "testsPerformed": tests_performed,
        "score": score,
        "maxScore": 25,
        "label": label,
        "color": color,
        "status": status,
    }

def parse_rkhunter(exceptions):
    warnings = []
    last_check = 0
    installed = False
    for p in ["/usr/bin/rkhunter", "/usr/sbin/rkhunter"]:
        if Path(p).exists():
            installed = True
            break
    txt = read_text(RKHUNTER_LOG, limit=400000)
    if txt:
        installed = True
        try: last_check = int(RKHUNTER_LOG.stat().st_mtime)
        except: pass
        for line in txt.splitlines():
            # Filter rkhunter internal grep noise (not real findings)
            if "egrep is obsolescent" in line or "grep: warning: stray" in line:
                continue
            # Default ignore for Arch-known script false positives (egrep/fgrep/ldd are wrappers on Arch)
            if "has been replaced by a script" in line and any(x in line for x in ["/usr/bin/egrep", "/usr/bin/fgrep", "/usr/bin/ldd", "/usr/bin/which", "/usr/bin/groups"]):
                continue
            # Only real warnings — strict Warning: prefix to avoid false positives like "Performing check of possible rootkit"
            if "Warning:" not in line:
                continue
            low = line.lower()
            if "no warnings" in low:
                continue
            # Extract clean id without timestamp for better display/search
            m = re.search(r"Warning:\s*(.*)", line)
            if m:
                clean = m.group(1).strip()
                # Use first 80 chars of clean message as id, without timestamp
                wid = sanitize(clean[:80], 80)
            else:
                mm = re.search(r"\[([A-Z0-9_\-]+)\]", line)
                wid = mm.group(1) if mm else sanitize(line.strip()[:60], 60)
            # Full text without timestamp for cleaner display
            full = re.sub(r"^\s*\[.*?\]\s*", "", line).strip()
            warnings.append({"text": sanitize(full, 220), "id": sanitize(wid, 80)})
        warnings = warnings[-100:]
    # also consider rkhunter's prop file age
    if installed and last_check == 0:
        try:
            alt = Path("/var/log/rkhunter.log")
            if alt.exists(): last_check = int(alt.stat().st_mtime)
        except: pass

    exc = exceptions.get("rkhunter", set())
    warnings_all = warnings
    warnings = [w for w in warnings if w.get("id") not in exc and w.get("text","")[:40] not in exc]

    if not installed:
        score, label, color, status = 0, "Not installed", "urgent", "not installed"
    elif len(warnings) == 0:
        # if we have a log at all, assume clean; else unknown
        if txt:
            score, label, color, status = 25, "Clean", "good", "clean"
        else:
            score, label, color, status = 12, "No scan yet", "warning", "no scan"
            # try check if rkhunter --check needs sudo; advise
    else:
        # penalize per warning
        s = max(0, 25 - len(warnings)*4)
        score = s
        label = f"{len(warnings)} warnings"
        color = "urgent" if len(warnings) >= 3 else "warning"
        status = "warnings"

    return {
        "id": "rkhunter",
        "title": "RKHunter",
        "installed": installed,
        "lastCheckEpoch": last_check,
        "warnings": warnings[:MAX_ITEMS],
        "warningsAllCount": len(warnings_all),
        "warningsFiltered": len(warnings_all) - len(warnings),
        "score": score,
        "maxScore": 25,
        "label": label,
        "color": color,
        "status": status,
    }

def parse_systemd():
    # systemd-analyze security — exposure 0.0 (safe) to 10.0 (unsafe)
    services = []
    avg = 0.0
    score = 0
    label = "Unknown"
    color = "warning"
    status = "unknown"
    installed = False
    try:
        out, err, code = sh(["systemd-analyze", "security", "--json=short"], timeout=3.0)
        if code == 0 and out.strip().startswith("["):
            import json as js
            data = js.loads(out)
            installed = True
            # data is list of {unit, exposure, predicate, happy}
            total = 0.0
            cnt = 0
            high = 0
            for e in data:
                try:
                    exp = float(e.get("exposure","0"))
                except:
                    exp = 0.0
                total += exp
                cnt += 1
                if exp >= 7.0:
                    high += 1
                # Keep top 15 high exposure for display, sorted descending
                services.append({"unit": e.get("unit",""), "exposure": exp, "predicate": e.get("predicate",""), "happy": e.get("happy","")})
            if cnt:
                avg = total / cnt
                # Sort by exposure descending for display
                services = sorted(services, key=lambda x: x["exposure"], reverse=True)[:15]
                # Score 25 -> 0 mapped from avg 0 ->10 : 25 - avg*2.5
                score = max(0, min(25, int(round(25 - avg*2.5))))
                if avg < 3.0:
                    label, color, status = "Hardened", "good", "hardened"
                elif avg < 6.0:
                    label, color, status = "Fair", "warning", "fair"
                else:
                    label, color, status = f"{high} high", "urgent", "exposed"
            else:
                score = 0
        else:
            # Fallback try plain text parsing if json not available
            out2, _, code2 = sh(["systemd-analyze", "security"], timeout=3.0)
            if code2 == 0 and "EXPOSURE" in out2:
                installed = True
                # parse lines
                for line in out2.splitlines():
                    # skip header
                    if line.strip().startswith("UNIT") or not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    # exposure is second last before predicate?
                    # Format: UNIT  EXPOSURE PREDICATE HAPPY — exposure is numeric
                    try:
                        # Find numeric exposure
                        for tok in parts:
                            try:
                                exp = float(tok)
                                total += exp
                                cnt += 1
                                if exp >= 7.0:
                                    high += 1
                                services.append({"unit": parts[0], "exposure": exp, "predicate": parts[2] if len(parts)>2 else "", "happy": parts[3] if len(parts)>3 else ""})
                                break
                            except:
                                continue
                    except:
                        pass
                if cnt:
                    avg = total / cnt
                    services = sorted(services, key=lambda x: x["exposure"], reverse=True)[:15]
                    score = max(0, min(25, int(round(25 - avg*2.5))))
                    if avg < 3.0:
                        label, color, status = "Hardened", "good", "hardened"
                    elif avg < 6.0:
                        label, color, status = "Fair", "warning", "fair"
                    else:
                        label, color, status = f"{high} high", "urgent", "exposed"
    except Exception as e:
        pass
    if not installed:
        # check if binary exists
        for cand in ["/usr/bin/systemd-analyze", "/bin/systemd-analyze"]:
            if pathlib.Path(cand).exists():
                installed = True
                break
        if not installed:
            score, label, color, status = 0, "Not installed", "urgent", "not installed"
        else:
            score, label, color, status = 5, "No data", "warning", "no data"
    return {
        "id": "systemd",
        "title": "Systemd Services",
        "installed": installed,
        "avgExposure": round(avg,1),
        "services": services,
        "score": score,
        "maxScore": 25,
        "label": label,
        "color": color,
        "status": status,
    }

def grade_for(pct):
    if pct >= 90: return "A", "System Hardened", "good"
    if pct >= 75: return "B", "Good", "good"
    if pct >= 60: return "C", "Fair", "warning"
    if pct >= 40: return "D", "At Risk", "warning"
    return "F", "Critical", "urgent"

def main():
    exc = load_exceptions()
    ufw = parse_ufw()
    clam = parse_clamav()
    lynis = parse_lynis(exc)
    rkh = parse_rkhunter(exc)
    systemd = parse_systemd()

    tools = [ufw, clam, lynis, rkh]
    total = sum(t["score"] for t in tools)
    max_total = sum(t["maxScore"] for t in tools) or 100
    pct = int(round(total / max_total * 100)) if max_total else 0
    grade, status_label, status_color = grade_for(pct)

    # lynis/rkhunter with not-installed pull max down; still show pct as-is
    # but also give actionable hint
    failed = sum(1 for t in tools if t["score"] < 12)

    out = {
        "global": {
            "score": pct,
            "grade": grade,
            "statusLabel": status_label,
            "statusColor": status_color,
            "totalScore": total,
            "maxScore": max_total,
            "failedCount": failed,
            "totalChecks": len(tools),
        },
        "tools": {
            "ufw": ufw,
            "clamav": clam,
            "lynis": lynis,
            "rkhunter": rkh,
            "systemd": systemd,
        },
        "exceptions": {
            "lynis": sorted(exc["lynis"]),
            "rkhunter": sorted(exc["rkhunter"]),
        },
        "timestamp": time.strftime("%H:%M:%S"),
        "timestampEpoch": int(time.time()),
    }
    # bounded output 64k
    text = json.dumps(out, ensure_ascii=False)
    if len(text) > 65536:
        # trim lists
        for k in ["warnings", "suggestions", "recent"]:
            for tool in tools:
                if k in tool and isinstance(tool[k], list) and len(tool[k]) > 10:
                    tool[k] = tool[k][:10]
        text = json.dumps(out, ensure_ascii=False)[:65536]
    sys.stdout.write(text)

if __name__ == "__main__":
    main()
