.pragma library

// Pure UFW file parsing — copied and trimmed from srozen.ufw Model.js (MIT)
// plus small helpers for score computation. No I/O, safe to unit-test with node.
//
// Files read by the panel (world-readable on stock ufw installs):
//   /etc/ufw/ufw.conf      ENABLED
//   /etc/default/ufw       default policies
//   /etc/ufw/user.rules    v4 tuples
//   /etc/ufw/user6.rules   v6 tuples

var GLYPH_WALL_FIRE = String.fromCodePoint(0xF1A11)
var GLYPH_WALL = String.fromCodePoint(0xF07FE)
var GLYPH_ALLOW = String.fromCodePoint(0xF0565)
var GLYPH_DENY = String.fromCodePoint(0xF0ADC)
var GLYPH_REJECT = String.fromCodePoint(0xF0ECC)
var GLYPH_LIMIT = String.fromCodePoint(0xF04C5)
var GLYPH_INBOUND = String.fromCodePoint(0xF072E)
var GLYPH_OUTBOUND = String.fromCodePoint(0xF0737)
var GLYPH_ROUTED = String.fromCodePoint(0xF04E1)
var GLYPH_SHIELD = String.fromCodePoint(0xF0498)
var GLYPH_REFRESH = String.fromCodePoint(0xF0450)

var ANY_V4 = "0.0.0.0/0"
var ANY_V6 = "::/0"

function parseEnabled(text) {
    var m = /^[ \t]*ENABLED[ \t]*=[ \t]*"?([A-Za-z]+)"?/m.exec(String(text || ""))
    if (!m) return null
    return m[1].toLowerCase() === "yes"
}
function parseLogLevel(text) {
    var m = /^[ \t]*LOGLEVEL[ \t]*=[ \t]*"?([A-Za-z]+)"?/m.exec(String(text || ""))
    return m ? m[1].toLowerCase() : ""
}
function policyWord(v) {
    var t = String(v || "").replace(/"/g, "").trim().toUpperCase()
    if (t === "DROP") return "deny"
    if (t === "ACCEPT") return "allow"
    if (t === "REJECT") return "reject"
    return t.toLowerCase()
}
function readVariable(text, name) {
    var pat = new RegExp("^[ \\t]*" + name + "[ \\t]*=[ \\t]*\"?([^\"\\n\\r]*)\"?", "m")
    var mm = pat.exec(String(text || ""))
    return mm ? mm[1].trim() : ""
}
function parseDefaults(text) {
    return {
        input: policyWord(readVariable(text, "DEFAULT_INPUT_POLICY")) || "deny",
        output: policyWord(readVariable(text, "DEFAULT_OUTPUT_POLICY")) || "allow",
        forward: policyWord(readVariable(text, "DEFAULT_FORWARD_POLICY")) || "deny",
        ipv6: String(readVariable(text, "IPV6")).toLowerCase() !== "no"
    }
}
function decodeComment(hex) {
    var text = String(hex || "").trim()
    if (text === "" || !/^([0-9a-fA-F]{2})+$/.test(text)) return ""
    var out = ""
    for (var i = 0; i < text.length; i += 2) out += String.fromCharCode(parseInt(text.substr(i, 2), 16))
    try {
        return decodeURIComponent(out.split("").map(function(ch) {
            return "%" + ("0" + ch.charCodeAt(0).toString(16)).slice(-2)
        }).join(""))
    } catch (e) { return out }
}
function parseTuple(line, v6) {
    var raw = String(line || "")
    if (!/^###[ \t]*tuple[ \t]*###/.test(raw)) return null
    var comment = ""
    var body = raw
    var at = body.indexOf(" comment=")
    if (at !== -1) { comment = decodeComment(body.substring(at + " comment=".length)); body = body.substring(0, at) }
    body = body.replace(/^###[ \t]*tuple[ \t]*###[ \t]*/, "").replace(/^\s+|\s+$/g, "")
    if (body === "") return null
    var fields = body.split(/\s+/)
    if (fields.length < 6 || fields.length > 9) return null
    var direction = "in"
    if (fields.length === 7 || fields.length === 9) {
        var ifaces = fields[fields.length - 1]
        direction = ifaces.split("_")[0]
        if (ifaces.indexOf("_") !== -1) {
            if (ifaces.indexOf("!") !== -1 && /in_\w+/.test(ifaces) && /out_\w+/.test(ifaces)) return null
            if (ifaces.indexOf("in_") !== 0 && ifaces.indexOf("out_") !== 0 && ifaces.indexOf("_") !== -1) return null
        }
    }
    var action = fields[0]
    var forward = false
    if (action.indexOf(":") !== -1) { forward = true; action = action.split(":")[1] }
    var logType = ""
    if (action.indexOf("_") !== -1) { var p = action.split("_"); action = p[0]; logType = p[1] || "" }
    if (action === "") return null
    var dapp = "", sapp = ""
    if (fields.length >= 8) {
        if (fields[6] !== "-") dapp = fields[6].replace(/%20/g, " ")
        if (fields[7] !== "-") sapp = fields[7].replace(/%20/g, " ")
    }
    return { action: action, logType: logType, forward: forward, protocol: fields[1], dport: fields[2], dst: fields[3], sport: fields[4], src: fields[5], dapp: dapp, sapp: sapp, direction: direction, comment: comment, v6: v6 === true }
}
function parseRules(text, v6) {
    var lines = String(text || "").split(/\r?\n/)
    var rules = []
    for (var i = 0; i < lines.length; i++) { var r = parseTuple(lines[i], v6); if (r) rules.push(r) }
    return rules
}
function isAnyAddress(a) { return a === ANY_V4 || a === ANY_V6 }
function locationFor(rule, which) {
    var isDst = which === "dst"
    var address = isDst ? rule.dst : rule.src
    var port = isDst ? rule.dport : rule.sport
    var app = isDst ? rule.dapp : rule.sapp
    var showProto = true
    if (app !== "") { showProto = false; port = app; if (rule.v6 && address === ANY_V6) port += " (v6)" }
    var loc = isAnyAddress(address) ? "" : address
    if (port !== "any") {
        loc = loc === "" ? port : loc + " " + port
        if (showProto && rule.protocol !== "any") loc += "/" + rule.protocol
        if (rule.v6 && rule.src === ANY_V6 && rule.dst === ANY_V6 && loc.indexOf(" (v6)") === -1) loc += " (v6)"
    } else if (isAnyAddress(address)) {
        loc = "Anywhere"
        if (showProto && rule.protocol !== "any" && rule.dst === rule.src && rule.dport === rule.sport) loc += "/" + rule.protocol
        if (address === ANY_V6) loc += " (v6)"
    } else if (showProto && rule.protocol !== "any" && rule.dport === rule.sport) loc += "/" + rule.protocol
    return loc
}
function directionLabel(rule) { if (rule.forward) return "FWD"; return String(rule.direction).toUpperCase() }
function actionGlyph(a) {
    if (a === "allow") return GLYPH_ALLOW
    if (a === "deny") return GLYPH_DENY
    if (a === "reject") return GLYPH_REJECT
    if (a === "limit") return GLYPH_LIMIT
    return GLYPH_SHIELD
}
function directionGlyph(rule) { if (rule.forward) return GLYPH_ROUTED; return rule.direction === "out" ? GLYPH_OUTBOUND : GLYPH_INBOUND }
function describeRule(rule, index) {
    var to = locationFor(rule, "dst")
    var from = locationFor(rule, "src")
    var verb = String(rule.action).toUpperCase() + " " + directionLabel(rule)
    var notes = ["from " + from]
    if (rule.logType !== "") notes.push(rule.logType.toLowerCase())
    if (rule.comment !== "") notes.push("# " + rule.comment)
    return { key: "rule:" + (rule.v6 ? "6" : "4") + ":" + index, label: to, verb: verb, detail: notes.join("  ·  "), glyph: actionGlyph(rule.action), directionGlyph: directionGlyph(rule), action: rule.action, v6: rule.v6 === true, text: to + "  " + verb + "  " + from + (rule.comment !== "" ? "  # " + rule.comment : "") }
}
function buildRuleRows(v4Text, v6Text) {
    var rules = parseRules(v4Text, false).concat(parseRules(v6Text, true))
    var seen = {}
    var rows = []
    for (var i = 0; i < rules.length; i++) {
        var r = rules[i]
        if (r.dapp !== "" || r.sapp !== "") { var k = r.dapp + " " + r.dst + " " + r.sapp + " " + r.src; if (seen[k]) continue; seen[k] = true }
        rows.push(describeRule(r, i))
    }
    return rows
}
function statusWord(installed, enabled) {
    if (!installed) return "not installed"
    if (enabled === null || enabled === undefined) return "unknown"
    return enabled ? "active" : "inactive"
}
function barSummary(installed, enabled, ruleCount) {
    if (!installed) return "ufw not installed"
    if (enabled === null || enabled === undefined) return "status unknown"
    if (!enabled) return "inactive — nothing filtered"
    return "active — " + ruleCount + (ruleCount === 1 ? " rule" : " rules")
}
function scoreForUfw(installed, enabled, ruleCount, defaults) {
    if (!installed) return { score: 0, max: 25, label: "Not installed", color: "urgent" }
    if (enabled === null) return { score: 8, max: 25, label: "Unknown", color: "warning" }
    if (!enabled) return { score: 0, max: 25, label: "Inactive", color: "urgent" }
    var s = 15
    if (ruleCount > 0) s += 5
    if (defaults && defaults.input === "deny") s += 5
    else s -= 5
    s = Math.max(0, Math.min(25, s))
    var label = s >= 22 ? "Hardened" : s >= 15 ? "Active" : "Weak rules"
    return { score: s, max: 25, label: label, color: s >= 20 ? "good" : s >= 12 ? "warning" : "urgent" }
}
if (typeof module !== "undefined") {
    module.exports = { parseEnabled: parseEnabled, parseLogLevel: parseLogLevel, parseDefaults: parseDefaults, parseTuple: parseTuple, parseRules: parseRules, buildRuleRows: buildRuleRows, statusWord: statusWord, barSummary: barSummary, scoreForUfw: scoreForUfw }
}
