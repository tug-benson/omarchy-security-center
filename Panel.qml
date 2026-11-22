pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
    id: root
    moduleName: "io.github.tug-benson.security-center"
    manageIpc: false

    property var anchorItem: null
    property var hostWidget: null
    property var bar: null

    // Settings from manifest
    readonly property int refreshIntervalSec: setting("refreshIntervalSec", 300)
    readonly property bool cveEnabled: setting("cveEnabled", true)
    readonly property int cveMaxItems: setting("cveMaxItems", 8)
    readonly property string clamavScanPaths: setting("clamavScanPaths", "~/Downloads")
    readonly property bool lynisShowAll: setting("lynisShowAll", false)

    // State
    property var secData: null
    property var cveData: ({ items: [] })
    property bool isScanning: false
    property string lastScanTime: ""
    property string barForeground: bar ? bar.foreground : Color.foreground
    property string barUrgent: bar ? bar.urgent : Color.urgent
    property string barFontFamily: bar ? bar.fontFamily : Style.font.family
    readonly property string homePath: Quickshell.env("HOME")

    // Derived globals
    readonly property bool globalScoreReady: secData !== null && secData.global !== undefined
    readonly property int globalScore: globalScoreReady ? secData.global.score : 0
    readonly property string globalGrade: globalScoreReady ? secData.global.grade : "--"
    readonly property string globalLabel: globalScoreReady ? secData.global.statusLabel : "Scanning…"
    readonly property string globalColor: globalScoreReady ? secData.global.statusColor : "normal"

    // Expand toggles
    property bool showLynis: true
    property bool showSystemd: true
    property bool showClamav: true
    property bool showUfw: true
    property bool showUfwRules: false
    property string lynisDetailText: ""
    property string lynisDetailId: ""
    property string detailKind: ""
    property string detailText: ""
    property string detailId: ""
    property bool showRkhunter: true
    property bool showCve: false
    property bool cveLinuxOnly: false
    property bool cvePaused: false
    property bool showSettings: false

    property string copiedNotice: ""
    property string lastError: ""

    // Helpers
    function gradeColor(c) {
        if (c === "good") return Color.accent
        if (c === "warning") return Color.accent
        if (c === "urgent") return root.barUrgent
        return root.barForeground
    }
    function scoreColor(score) {
        if (score >= 75) return Color.accent
        if (score >= 50) return Color.accent
        return root.barUrgent
    }
    function formatEpoch(e) {
        if (!e) return "Never"
        var d = new Date(e * 1000)
        return d.toLocaleString(Qt.locale(), Locale.ShortFormat)
    }
    function ago(epoch) {
        if (!epoch) return "Unknown"
        var diff = Math.floor(Date.now()/1000 - epoch)
        if (diff < 60) return "Just now"
        if (diff < 3600) return Math.floor(diff/60) + " min ago"
        if (diff < 86400) return Math.floor(diff/3600) + " h ago"
        return Math.floor(diff/86400) + " d ago"
    }
    function copyToClipboard(text) {
        if (!text) return
        Quickshell.execDetached(["wl-copy","--", text])
        root.copiedNotice = text
        noticeTimer.restart()
    }
    function refresh() {
        if (secProc.running) return
        root.isScanning = true
        secProc.running = true
        if (root.cveEnabled) cveProc.running = true
    }
    function runClamScan(path) {
        if (!root.bar) return
        var p = path || "~/Downloads"
        if (p.startsWith("~/")) p = root.homePath + p.substring(1)
        else if (p === "~") p = root.homePath
        // record scan time for hero last-scan display
        Quickshell.execDetached(["bash","-c","mkdir -p ~/.local/state/omarchy/security-center && date +%s > ~/.local/state/omarchy/security-center/clamav-last-scan.epoch"])
        var cmd = "p=" + Util.shellQuote(p) + "; [ -e \"$p\" ] || p=" + Util.shellQuote(root.homePath) + "; echo \"Scanning: $p\"; clamscan -r --infected \"$p\" 2>&1 | head -n 400; echo \"--- Done. Press Enter to close.\"; read"
        root.bar.run("omarchy-launch-floating-terminal-with-presentation " + Util.shellQuote(cmd))
    }
    function addException(kind, id) {
        var raw = String(id).substring(0, 64)
        if (!raw) return
        // Use argv to avoid shell quoting issues and keep full id
        var script = "import sys, json, pathlib; p=pathlib.Path.home()/'.config/omarchy/security-center/exceptions.json'; p.parent.mkdir(parents=True, exist_ok=True); d=json.loads(p.read_text()) if p.exists() else {}; k=sys.argv[1]; v=sys.argv[2]; s=set(d.get(k,[])); s.add(v); s.add(v[:40]); d[k]=sorted(s); p.write_text(json.dumps(d,indent=2))"
        excProc.command = ["python3","-c", script, kind, raw]
        excProc.running = true
        root._pendingExcKind = kind
        root._pendingExcId = raw
    }
    property string _pendingExcKind: ""
    property string _pendingExcId: ""
    function openLynisDetail(id, text) { root.lynisDetailId = id; root.lynisDetailText = text; root.detailKind="lynis"; root.detailId=id; root.detailText=text }
    function closeLynisDetail() { root.lynisDetailId = ""; root.lynisDetailText = ""; root.detailKind=""; root.detailId=""; root.detailText="" }
    function openRkhDetail(id, text) { root.detailKind="rkhunter"; root.detailId=id; root.detailText=text; root.lynisDetailId=id; root.lynisDetailText=text }
    function closeDetail() { root.closeLynisDetail() }

    function toolData(id) {
        if (!root.secData || !root.secData.tools) return null
        return root.secData.tools[id]
    }
    readonly property var cveFiltered: {
        if (!root.cveData || !root.cveData.items) return []
        var items = root.cveData.items
        if (!root.cveLinuxOnly) return items
        var out = []
        var re = /linux|kernel|ubuntu|debian|arch|suse|fedora|red\s*hat|alpine|systemd|grub|openssl|wayland|hyprland/i
        for (var i=0;i<items.length;i++) { var it=items[i]; var txt=(it.title||"")+" "+(it.description||""); if(re.test(txt)) out.push(it) }
        return out.length>0 ? out : items
    }
    readonly property string cveTickerText: {
        var f = root.cveFiltered
        if (!f || f.length===0) return "  \u2022  No CVE items (offline or filtered)  \u2022  "
        var parts=[]
        for(var i=0;i<f.length;i++) parts.push(f[i].cve + " — " + f[i].title)
        return "  \u2022  " + parts.join("   \u2022   ") + "   \u2022   "
    }

    // Processes
    Process {
        id: secProc
        command: ["python3", Qt.resolvedUrl("scripts/security-center.py").toString().replace(/^file:\/\//,"")]
        stdout: StdioCollector { waitForEnd:true; onStreamFinished: {
            try {
                var data = JSON.parse(text)
                root.secData = data
                root.lastScanTime = data.timestamp || ""
                root.lastError = ""
            } catch(e) { root.lastError = "Parse error"; }
            root.isScanning = false
        }}
        stderr: StdioCollector { waitForEnd:true; onStreamFinished: if(text) console.log("security-center stderr:", text) }
        onExited: function(c){ root.isScanning=false }
    }
    Process {
        id: cveProc
        command: ["python3", Qt.resolvedUrl("scripts/cve-feed.py").toString().replace(/^file:\/\//,""), String(root.cveMaxItems)]
        stdout: StdioCollector { waitForEnd:true; onStreamFinished: {
            try { root.cveData = JSON.parse(text) } catch(e) {}
        }}
    }
    Process {
        id: excProc
        running: false
        stdout: StdioCollector { waitForEnd:true }
        onExited: function(c){ root.refresh() }
    }

    Timer { id: noticeTimer; interval:2500; onTriggered: root.copiedNotice = "" }
    Timer { id: bgTimer; interval: root.refreshIntervalSec*1000; running: true; repeat:true; onTriggered: root.refresh() }
    Timer { id: fastTimer; interval:8000; running: root.opened; repeat:true; onTriggered: root.refresh() }

    Component.onCompleted: root.refresh()
    onOpenedChanged: if(opened) { Qt.callLater(function(){ if(keyCatcher) keyCatcher.forceActiveFocus() }); root.refresh() }

    function open(){ root.controller.show() }
    function close(){ root.controller.hide() }
    function toggle(){ if(root.opened) root.close(); else root.open() }
    function closeForPopoutSwitch(){ root.controller.hide() }
    function switchPanel(dir){
        if(root.bar && typeof root.bar.switchPanelFrom === "function")
            return root.bar.switchPanelFrom(root.hostWidget||root, dir)
        return false
    }
    function setting(k, defVal){ try { if(root.hostWidget && root.hostWidget.settings && k in root.hostWidget.settings) return root.hostWidget.settings[k]; if(root.settings && k in root.settings) return root.settings[k]; } catch(e){} return defVal }

    // UFW live controller for toggle switch
    UfwController {
        id: ufwCtrl
        settings: root.settings
        onTerminalRequested: function(cmd){
            if(!root.bar) return
            root.bar.run("omarchy-launch-floating-terminal-with-presentation " + Util.shellQuote(cmd))
            root.close()
        }
    }

    // ── Inline gauge component (circular) ──
    component SecGauge: Item {
        property int score: 0
        property string grade: "--"
        property int size: 88
        property color fg: Color.foreground
        property color accent: Color.accent
        property color urgent: Color.urgent
        width: size; height: size
        readonly property color ringColor: score >= 80 ? accent : score >= 50 ? accent : urgent
        Canvas {
            id: gaugeCanvas
            anchors.fill: parent
            onPaint: {
                var ctx = getContext("2d"); ctx.reset()
                var cx = width/2, cy = height/2, r = Math.min(width,height)/2 - 4
                ctx.beginPath(); ctx.arc(cx,cy,r,0,2*Math.PI); ctx.strokeStyle = Qt.rgba(fg.r,fg.g,fg.b,0.12); ctx.lineWidth=6; ctx.stroke()
                var pct = Math.max(0,Math.min(100, score))/100
                if(pct>0){
                    ctx.beginPath(); ctx.arc(cx,cy,r, -Math.PI/2, -Math.PI/2 + 2*Math.PI*pct, false); ctx.strokeStyle = ringColor; ctx.lineWidth=6; ctx.lineCap="round"; ctx.stroke()
                }
            }
            onWidthChanged: requestPaint()
            Component.onCompleted: requestPaint()
        }
        onScoreChanged: gaugeCanvas.requestPaint()
        onGradeChanged: gaugeCanvas.requestPaint()
        Column {
            anchors.centerIn: parent
            spacing: 1
            Text { textFormat: Text.PlainText; anchors.horizontalCenter: parent.horizontalCenter; text: "indice"; color: Qt.darker(parent.parent.fg,1.3); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.letterSpacing: 1.1 }
            Text { textFormat: Text.PlainText; anchors.horizontalCenter: parent.horizontalCenter; text: parent.parent.score + "%"; color: parent.parent.fg; font.family: root.barFontFamily; font.pixelSize: Style.font.title + 2; font.bold:true }
        }
    }

    component SmallGauge: Item {
        property int score: 0
        property int maxScore: 25
        property int size: 44
        width: size; height: size
        readonly property int pct: maxScore>0 ? Math.round(score/maxScore*100) : 0
        readonly property color ringColor: pct >= 80 ? Color.accent : pct >= 50 ? Color.accent : root.barUrgent
        Canvas {
            id: smallCanvas
            anchors.fill: parent
            onPaint: {
                var ctx=getContext("2d"); ctx.reset()
                var cx=width/2, cy=height/2, r=Math.min(width,height)/2 - 3
                ctx.beginPath(); ctx.arc(cx,cy,r,0,2*Math.PI); ctx.strokeStyle = Qt.rgba(root.barForeground.r,root.barForeground.g,root.barForeground.b,0.12); ctx.lineWidth=4; ctx.stroke()
                var p = Math.max(0,Math.min(100, parent.pct))/100
                if(p>0){ ctx.beginPath(); ctx.arc(cx,cy,r,-Math.PI/2,-Math.PI/2+2*Math.PI*p,false); ctx.strokeStyle=parent.ringColor; ctx.lineWidth=4; ctx.lineCap="round"; ctx.stroke() }
            }
            Component.onCompleted: requestPaint()
        }
        onScoreChanged: smallCanvas.requestPaint()
        onPctChanged: smallCanvas.requestPaint()
        Text { textFormat: Text.PlainText; anchors.centerIn: parent; text: parent.pct + "%"; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold:true }
    }

    implicitWidth: 0; implicitHeight: 0

    KeyboardPanel {
        id: panel
        anchorItem: root.anchorItem
        owner: root.hostWidget || root
        bar: root.bar
        open: root.opened
        focusTarget: keyCatcher
        contentWidth: panel.fittedContentWidth(Style.space(560))
        contentHeight: panel.fittedContentHeight(mainCol.implicitHeight, Style.space(780))

        PanelKeyCatcher {
            id: keyCatcher
            anchors.fill: parent
            onCloseRequested: { if (root.detailText !== "" || root.lynisDetailText !== "") root.closeLynisDetail(); else root.close() }
            onTabRequested: function(d){ root.switchPanel(d) }
            onTextKey: function(t){ if(t==="r"||t==="R") root.refresh(); if((root.detailText !== "" || root.lynisDetailText !== "") && (t==="Escape"||t==="\u001b")) root.closeLynisDetail() }

            Flickable {
                anchors.fill: parent
                contentWidth: width
                contentHeight: mainCol.implicitHeight
                clip: true
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                Column {
                    id: mainCol
                    width: parent.width
                    spacing: Style.space(10)

                    // ═══ HERO — global grade + subtitle ═══
                    RowLayout {
                        width: parent.width
                        spacing: Style.space(12)

                        Column {
                            Layout.preferredWidth: 200
                            spacing: Style.space(2)
                            Row {
                                spacing: Style.space(8)
                                Text { textFormat: Text.PlainText; text: "󰚊"; color: root.gradeColor(root.globalColor); font.family: "JetBrainsMono Nerd Font"; font.pixelSize: 56; anchors.verticalCenter: parent.verticalCenter }
                                Column {
                                    anchors.verticalCenter: parent.verticalCenter
                                    spacing: Style.space(1)
                                    Text { textFormat: Text.PlainText; text: "Security Center"; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.title; font.bold:true }
                                    Text { textFormat: Text.PlainText; text: root.globalLabel; color: Qt.darker(root.barForeground,1.45); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight; width: Math.min(implicitWidth, 200) }
                                }
                            }
                            BorderSurface {
                                visible: root.copiedNotice !== ""
                                width: parent.width
                                implicitHeight: noticeTxt.implicitHeight + Style.space(8)
                                color: "transparent"
                                borderSpec: Border.controlSpec("focus", Color.accent, Color.accent)
                                radius: Style.cornerRadius
                                Text { id: noticeTxt; textFormat: Text.PlainText; anchors.centerIn: parent; width: parent.width - Style.space(16); horizontalAlignment: Text.AlignHCenter; text: "Copied: " + root.copiedNotice; color: Color.accent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideMiddle }
                            }
                            Text {
                                visible: root.lastError !== ""
                                width: parent.width
                                text: root.lastError
                                color: root.barUrgent
                                font.family: root.barFontFamily
                                font.pixelSize: Style.font.caption
                                wrapMode: Text.WordWrap
                            }
                        }

                        Column {
                            Layout.alignment: Qt.AlignVCenter
                            Layout.preferredWidth: 140
                            spacing: Style.space(1)
                            Text { textFormat: Text.PlainText; text: "Last scan"; color: Qt.darker(root.barForeground,1.6); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold: true; font.letterSpacing: 0.8 }
                            Text { textFormat: Text.PlainText; text: "Lynis: " + (root.toolData("lynis") && root.toolData("lynis").lastScanEpoch ? root.ago(root.toolData("lynis").lastScanEpoch) : (root.toolData("lynis") && !root.toolData("lynis").readable ? "no permission" : "never")); color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight }
                            Text { textFormat: Text.PlainText; text: "RKHunter: " + (root.toolData("rkhunter") && root.toolData("rkhunter").lastCheckEpoch ? root.ago(root.toolData("rkhunter").lastCheckEpoch) : "never"); color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight }
                            Text { textFormat: Text.PlainText; text: "ClamAV: " + (root.toolData("clamav") && (root.toolData("clamav").lastScanEpoch || root.toolData("clamav").lastUpdateEpoch) ? root.ago(root.toolData("clamav").lastScanEpoch || root.toolData("clamav").lastUpdateEpoch) : "never"); color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight }
                        }

                        SecGauge {
                            Layout.alignment: Qt.AlignTop
                            score: root.globalScore
                            grade: root.globalGrade
                            fg: root.barForeground
                        }

                        Column {
                            Layout.alignment: Qt.AlignTop
                            spacing: Style.space(6)
                            PanelActionButton {
                                iconText: ""
                                tooltipText: root.isScanning ? "Scanning…" : "Rescan"
                                foreground: root.isScanning ? Color.accent : root.barForeground
                                onClicked: root.refresh()
                            }
                            PanelActionButton {
                                iconText: ""
                                tooltipText: "Settings"
                                foreground: root.showSettings ? Color.accent : root.barForeground
                                onClicked: root.showSettings = !root.showSettings
                            }
                        }
                    }

                    // ═══ Settings row (collapsible) ═══
                    BorderSurface {
                        visible: root.showSettings
                        width: parent.width
                        implicitHeight: settingsCol.implicitHeight + Style.space(12)
                        color: Style.hoverFillFor(root.barForeground, root.barForeground)
                        borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.6), Color.accent)
                        radius: Style.cornerRadius
                        Column {
                            id: settingsCol
                            anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                            anchors.margins: Style.space(8)
                            spacing: Style.space(6)
                            Text { textFormat: Text.PlainText; text: "Settings & Quick Actions"; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.bodySmall; font.bold:true }
                            RowLayout {
                                width: parent.width; spacing: Style.space(6)
                                Text { textFormat: Text.PlainText; text: "Scan paths:"; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                Text { Layout.fillWidth:true; textFormat: Text.PlainText; text: root.clamavScanPaths; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideMiddle }
                            }
                            Flow {
                                width: parent.width; spacing: Style.space(6)
                                Repeater {
                                    model: root.clamavScanPaths.split(",")
                                    delegate: Item {
                                        required property var modelData
                                        width: scanBtn.implicitWidth
                                        height: scanBtn.implicitHeight
                                        Button {
                                            id: scanBtn
                                            text: "Scan " + String(parent.modelData).trim().replace(/^.*\//,"")
                                            fontSize: Style.font.caption
                                            onClicked: root.runClamScan(String(parent.modelData).trim())
                                        }
                                    }
                                }
                                Button { text: "⚙ Open config"; fontSize: Style.font.caption; onClicked: if(root.bar) root.bar.run("xdg-open " + Util.shellQuote(root.homePath + "/.config/omarchy/security-center")) }
                            }
                            Text { width: parent.width; textFormat: Text.PlainText; text: "Tip: exceptions are stored in ~/.config/omarchy/security-center/exceptions.json — edit to un-ignore."; color: Qt.darker(root.barForeground,1.45); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap }
                        }
                    }

                    PanelSeparator { width: parent.width; foreground: root.barForeground }

                    // ═══ TWO COLUMNS: A=Lynis (left)  B=ClamAV/UFW/RKHunter stacked (right) ═══
                    RowLayout {
                        id: twoCols
                        width: parent.width
                        spacing: Style.space(10)

                        // ── Column A: Lynis + Systemd (left, bottom aligned with Column B) ──
                        Column {
                            id: leftCol
                            Layout.preferredWidth: Math.round(parent.width * 0.52)
                            Layout.preferredHeight: rightCol.implicitHeight
                            Layout.alignment: Qt.AlignTop
                            spacing: Style.space(10)
BorderSurface {
                            id: lynisCard
                            width: parent.width
                            height: Math.max(180, rightCol.implicitHeight - rkhCol.implicitHeight - Style.space(10))
                            radius: Style.cornerRadius
                            color: "transparent"
                            borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.6), Color.accent)
                            Column {
                                id: lynisCol
                                anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                                anchors.margins: Style.space(8)
                                spacing: Style.space(8)
                                RowLayout {
                                    width: parent.width
                                    Text { textFormat: Text.PlainText; text: "󰕥"; color: (root.toolData("lynis") && root.toolData("lynis").warnings.length>0) ? root.barUrgent : Color.accent; font.family: root.barFontFamily; font.pixelSize: Style.font.title }
                                    Column {
                                        Layout.fillWidth: true
                                        Text { textFormat: Text.PlainText; text: "Lynis"; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.body; font.bold:true }
                                        Text { textFormat: Text.PlainText; text: "Hardening " + (root.toolData("lynis") ? root.toolData("lynis").hardeningIndex : "--") + "/100"; color: Qt.darker(root.barForeground,1.3); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold:true }
                                        Text { textFormat: Text.PlainText; text: root.toolData("lynis") ? (root.toolData("lynis").warnings.length + " warnings \u00b7 " + root.toolData("lynis").suggestions.length + " suggestions" + (root.toolData("lynis").warningsFiltered>0 ? " \u00b7 " + root.toolData("lynis").warningsFiltered + " ignored" : "")) : "--"; color: Qt.darker(root.barForeground,1.45); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight }
                                    }
                                    SmallGauge { score: root.toolData("lynis") ? root.toolData("lynis").score : 0; maxScore:25; size: 48 }
                                    PanelActionButton { iconText: root.showLynis ? "\uf106" : "\uf107"; onClicked: root.showLynis = !root.showLynis }
                                }
                                Column {
                                    visible: root.showLynis
                                    width: parent.width
                                    spacing: Style.space(6)
                                    Text { visible: root.toolData("lynis") && !root.toolData("lynis").installed; width: parent.width; textFormat: Text.PlainText; text: "Lynis not installed — sudo pacman -S lynis && sudo lynis audit system"; color: root.barUrgent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap }
                                    BorderSurface {
                                        visible: root.toolData("lynis") && root.toolData("lynis").readable===false
                                        width: parent.width
                                        implicitHeight: fixPermCol.implicitHeight + Style.space(10)
                                        color: Style.hoverFillFor(root.barUrgent, root.barUrgent)
                                        borderSpec: Border.controlSpec("normal", root.barUrgent, root.barUrgent)
                                        radius: Style.cornerRadius
                                        Column {
                                            id: fixPermCol
                                            anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top; anchors.margins: Style.space(6)
                                            spacing: Style.space(4)
                                            Text { width: parent.width; textFormat: Text.PlainText; text: "Report exists but is not readable (640). Click to fix permissions."; color: root.barUrgent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap; font.bold: true }
                                            RowLayout { width: parent.width; Button { text: "Fix permissions"; fontSize: Style.font.caption; onClicked: if(root.bar) root.bar.run("omarchy-launch-floating-terminal-with-presentation " + Util.shellQuote("pkexec chmod 644 /var/log/lynis.log /var/log/lynis-report.dat && echo Fixed; ls -l /var/log/lynis*; read")) } Item { Layout.fillWidth:true } Text { textFormat: Text.PlainText; text: "needs pkexec"; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption } }
                                        }
                                    }
                                    // Always show a helpful scan button — even when hardeningIndex is 0 or logs missing
                                    RowLayout {
                                        width: parent.width
                                        visible: root.showLynis
                                        Button { text: "Run Lynis audit"; fontSize: Style.font.caption; onClicked: if(root.bar) root.bar.run("omarchy-launch-floating-terminal-with-presentation " + Util.shellQuote("sudo lynis audit system --quick; echo '--- Done, press Enter'; read")) }
                                        Item { Layout.fillWidth: true }
                                        PanelActionButton { iconText: "\uf021"; tooltipText: "Rescan"; onClicked: root.refresh() }
                                    }
                                    Text { visible: root.toolData("lynis") && root.toolData("lynis").installed && root.toolData("lynis").warnings.length===0 && root.toolData("lynis").suggestions.length===0; width: parent.width; textFormat: Text.PlainText; text: root.toolData("lynis") && root.toolData("lynis").hardeningIndex>=80 ? "No warnings — system hardened. Hardening index " + root.toolData("lynis").hardeningIndex + "/100." : "No warnings parsed. Hardening " + (root.toolData("lynis") ? root.toolData("lynis").hardeningIndex : 0) + "/100 — run an audit to refresh."; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap }
                                    Flickable {
                                        width: parent.width
                                        height: Math.max(140, lynisCard.height - 110)
                                        clip: true
                                        contentWidth: width
                                        contentHeight: lynisBody.implicitHeight
                                        boundsBehavior: Flickable.StopAtBounds
                                        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                                        Column {
                                            id: lynisBody
                                            width: parent.width
                                            spacing: Style.space(6)
                                    Repeater {
                                        model: (root.toolData("lynis") && root.showLynis) ? root.toolData("lynis").warnings : []
                                        delegate: BorderSurface {
                                            required property var modelData
                                            required property int index
                                            width: lynisCol.width
                                            implicitHeight: wCol.implicitHeight + Style.space(10)
                                            color: Style.hoverFillFor(root.barUrgent, root.barUrgent)
                                            borderSpec: Border.controlSpec("normal", root.barUrgent, root.barUrgent)
                                            radius: Style.cornerRadius
                                            Column {
                                                id: wCol
                                                anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top; anchors.margins: Style.space(6)
                                                spacing: Style.space(3)
                                                RowLayout {
                                                    width: parent.width
                                                    Text { textFormat: Text.PlainText; text: "\uf071"; color: root.barUrgent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold:true }
                                                    Text { Layout.fillWidth:true; textFormat: Text.PlainText; text: modelData.id || ("W" + index); color: root.barUrgent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold:true; elide: Text.ElideRight }
                                                    PanelActionButton { iconText: "\uF06E"; tooltipText: "Open details"; onClicked: root.openLynisDetail(modelData.id || ("W"+index), modelData.text) }
                                                    PanelActionButton { iconText: "\uF0A8"; tooltipText: "Ignore (exception)"; onClicked: root.addException("lynis", modelData.id || modelData.text.substring(0,32)) }
                                                }
                                                Text { width: parent.width; textFormat: Text.PlainText; text: modelData.text; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap }
                                            }
                                        }
                                    }
                                    Repeater {
                                        model: (root.toolData("lynis") && root.showLynis && (root.lynisShowAll || (root.toolData("lynis").warnings.length===0))) ? root.toolData("lynis").suggestions : []
                                        delegate: BorderSurface {
                                            required property var modelData
                                            width: lynisCol.width
                                            implicitHeight: sCol.implicitHeight + Style.space(10)
                                            color: "transparent"
                                            borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.6), Color.accent)
                                            radius: Style.cornerRadius
                                            Column {
                                                id: sCol
                                                anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top; anchors.margins: Style.space(6)
                                                spacing: Style.space(2)
                                                RowLayout {
                                                    width: parent.width
                                                    Text { textFormat: Text.PlainText; text: "\uF0FC"; color: Color.accent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                                    Text { Layout.fillWidth:true; textFormat: Text.PlainText; text: modelData.id || "Suggestion"; color: Color.accent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold:true; elide: Text.ElideRight }
                                                    PanelActionButton { iconText: "\uF06E"; tooltipText: "Open details"; onClicked: root.openLynisDetail(modelData.id || "Suggestion", modelData.text) }
                                                    PanelActionButton { iconText: "\uF0A8"; tooltipText: "Ignore"; onClicked: root.addException("lynis", modelData.id || modelData.text.substring(0,32)) }
                                                }
                                                Text { width: parent.width; textFormat: Text.PlainText; text: modelData.text; color: Qt.darker(root.barForeground,1.3); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap }
                                            }
                                        }
                                    }
                                    Button {
                                        visible: (root.toolData("lynis") ? root.toolData("lynis").suggestions.length>0 : false) && !root.lynisShowAll && (root.toolData("lynis").warnings.length>0)
                                        width: parent.width
                                        text: "Show " + (root.toolData("lynis") ? root.toolData("lynis").suggestions.length : 0) + " suggestions"
                                        fontSize: Style.font.caption
                                        onClicked: root.showSettings = true
                                    }
                                        } // lynisBody
                                    } // Flickable
                                }
                            }
                        }


                            // ── Systemd Services (exposure) — height = RKHunter ──
                            BorderSurface {
                                id: systemdCard
                                width: parent.width
                                implicitHeight: systemdCol.implicitHeight + Style.space(14)
                                height: rkhCol.implicitHeight
                                radius: Style.cornerRadius
                                color: "transparent"
                                borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.6), Color.accent)
                                Column {
                                    id: systemdCol
                                    anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                                    anchors.margins: Style.space(8)
                                    spacing: Style.space(6)
                                    RowLayout {
                                        width: parent.width
                                        Text { textFormat: Text.PlainText; text: "󰖟"; color: (root.toolData("systemd") && root.toolData("systemd").avgExposure >= 6 ? root.barUrgent : Color.accent); font.family: root.barFontFamily; font.pixelSize: Style.font.title }
                                        Column {
                                            Layout.fillWidth: true
                                            Text { textFormat: Text.PlainText; text: "Systemd"; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.body; font.bold:true }
                                            Text { textFormat: Text.PlainText; text: root.toolData("systemd") ? ("avg " + root.toolData("systemd").avgExposure + " \u00b7 " + root.toolData("systemd").label) : "--"; color: Qt.darker(root.barForeground,1.45); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight }
                                        }
                                        SmallGauge { score: root.toolData("systemd") ? root.toolData("systemd").score : 0; maxScore: 25; size: 48 }
                                        PanelActionButton { iconText: root.showSystemd ? "\uf106" : "\uf107"; onClicked: root.showSystemd = !root.showSystemd }
                                    }
                                    Column {
                                        visible: root.showSystemd
                                        width: parent.width
                                        spacing: Style.space(4)
                                        RowLayout {
                                            width: parent.width
                                            Button { text: "Analyze"; fontSize: Style.font.caption; onClicked: if(root.bar) root.bar.run("omarchy-launch-floating-terminal-with-presentation " + Util.shellQuote("systemd-analyze security --no-pager | head -n 80; echo '--- Full: systemd-analyze security --json=short | jq'; read")) }
                                            Item { Layout.fillWidth: true }
                                            Text { visible: root.toolData("systemd") && !root.toolData("systemd").installed; textFormat: Text.PlainText; text: "no systemd"; color: root.barUrgent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                        }
                                        Flickable {
                                            width: parent.width
                                            height: Math.min(180, Math.max(80, systemdBody.implicitHeight))
                                            clip: true
                                            contentWidth: width
                                            contentHeight: systemdBody.implicitHeight
                                            boundsBehavior: Flickable.StopAtBounds
                                            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                                            Column {
                                                id: systemdBody
                                                width: parent.width
                                                spacing: Style.space(3)
                                                Repeater {
                                                    model: (root.toolData("systemd") && root.showSystemd) ? root.toolData("systemd").services : []
                                                    delegate: RowLayout {
                                                        required property var modelData
                                                        width: systemdBody.width
                                                        spacing: Style.space(6)
                                                        Text { textFormat: Text.PlainText; text: modelData.exposure.toFixed(1); color: modelData.exposure >= 7 ? root.barUrgent : modelData.exposure >= 4 ? Color.accent : root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold: true; Layout.preferredWidth: 28; horizontalAlignment: Text.AlignRight }
                                                        Text { Layout.fillWidth: true; textFormat: Text.PlainText; text: modelData.unit; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight }
                                                        Text { textFormat: Text.PlainText; text: modelData.predicate; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; Layout.preferredWidth: 60; elide: Text.ElideRight }
                                                        Text { textFormat: Text.PlainText; text: modelData.predicate === "UNSAFE" ? "󱕼" : modelData.predicate === "EXPOSED" ? "󱕼" : modelData.predicate === "MEDIUM" ? "󰔷" : "󰱨"; color: modelData.exposure >= 7 ? root.barUrgent : modelData.exposure >= 4 ? Color.accent : Color.accent; font.family: "JetBrainsMono Nerd Font"; font.pixelSize: Style.font.caption }
                                                    }
                                                }
                                                Text { visible: (root.toolData("systemd") ? root.toolData("systemd").services.length : 0) === 0; width: parent.width; textFormat: Text.PlainText; text: "No data — run systemd-analyze security"; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // ── Column B: 3 mini panels stacked ──
                        // ── Column B: 3 mini panels stacked ──
                        Column {
                            id: rightCol
                            Layout.preferredWidth: Math.round(parent.width * 0.48) - Style.space(10)
                            Layout.fillWidth: true
                            Layout.alignment: Qt.AlignTop
                            spacing: Style.space(10)

                            // Mini ClamAV
                            BorderSurface {
                                width: parent.width
                                implicitHeight: clamCol.implicitHeight + Style.space(14)
                                radius: Style.cornerRadius
                                color: "transparent"
                                borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.6), Color.accent)
                                Column {
                                    id: clamCol
                                    anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                                    anchors.margins: Style.space(8)
                                    spacing: Style.space(6)
                                    RowLayout {
                                        width: parent.width
                                        Text { textFormat: Text.PlainText; text: (root.toolData("clamav") && root.toolData("clamav").activeCount>0) ? "\uf071" : "\uf132"; color: (root.toolData("clamav") && root.toolData("clamav").activeCount>0) ? root.barUrgent : Color.accent; font.family: root.barFontFamily; font.pixelSize: Style.font.title }
                                        Column { Layout.fillWidth: true; Text { textFormat: Text.PlainText; text: "ClamAV"; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.body; font.bold:true } Text { textFormat: Text.PlainText; text: root.toolData("clamav") ? root.toolData("clamav").label + " \u00b7 DB " + root.ago(root.toolData("clamav").lastUpdateEpoch) : "--"; color: Qt.darker(root.barForeground,1.45); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight } }
                                        SmallGauge { score: root.toolData("clamav") ? root.toolData("clamav").score : 0; maxScore:25; size: 48 }
                                        PanelActionButton { iconText: root.showClamav ? "\uf106" : "\uf107"; onClicked: root.showClamav = !root.showClamav }
                                    }
                                    Column {
                                        visible: root.showClamav
                                        width: parent.width
                                        spacing: Style.space(4)
                                        Column {
                                            width: parent.width
                                            spacing: Style.space(2)
                                            RowLayout {
                                                width: parent.width
                                                spacing: Style.space(4)
                                                Item {
                                                    Layout.fillWidth: false
                                                    width: clamdTxt.implicitWidth + 8
                                                    height: clamdTxt.implicitHeight + 6
                                                    Text { id: clamdTxt; anchors.centerIn: parent; textFormat: Text.PlainText; text: "clamd: " + (root.toolData("clamav") && root.toolData("clamav").clamdActive ? "\u25cf" : "\u25cb"); color: (root.toolData("clamav") && root.toolData("clamav").clamdActive) ? Color.accent : Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                                    MouseArea { anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onEntered: clamdTip.visible = true; onExited: clamdTip.visible = false }
                                                    PanelToolTip { id: clamdTip; visible: false; text: "clamd — on-demand scanner daemon (clamd.conf)"; fontFamily: root.barFontFamily }
                                                }
                                                Item {
                                                    width: onaccTxt.implicitWidth + 8
                                                    height: onaccTxt.implicitHeight + 6
                                                    Text { id: onaccTxt; anchors.centerIn: parent; textFormat: Text.PlainText; text: "on-access: " + (root.toolData("clamav") && root.toolData("clamav").onAccessActive ? "\u25cf" : "\u25cb"); color: (root.toolData("clamav") && root.toolData("clamav").onAccessActive) ? Color.accent : Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                                    MouseArea { anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onEntered: onaccTip.visible = true; onExited: onaccTip.visible = false }
                                                    PanelToolTip { id: onaccTip; visible: false; text: "clamonacc — real-time OnAccessIncludePath /home (clamd.conf)"; fontFamily: root.barFontFamily }
                                                }
                                                Item {
                                                    width: freshTxt.implicitWidth + 8
                                                    height: freshTxt.implicitHeight + 6
                                                    Text { id: freshTxt; anchors.centerIn: parent; textFormat: Text.PlainText; text: "freshclam: " + (root.toolData("clamav") && root.toolData("clamav").freshclamActive ? "\u25cf" : "\u25cb"); color: (root.toolData("clamav") && root.toolData("clamav").freshclamActive) ? Color.accent : Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                                    MouseArea { anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onEntered: freshTip.visible = true; onExited: freshTip.visible = false }
                                                    PanelToolTip { id: freshTip; visible: false; text: "freshclam — virus DB updater (freshclam.conf)"; fontFamily: root.barFontFamily }
                                                }
                                                Item { Layout.fillWidth: true }
                                                PanelActionButton {
                                                    iconText: ""
                                                    tooltipText: "Config: /etc/clamav/clamd.conf  •  OnAccessIncludePath /home  •  Exclude ~/.cache  •  Max 300M"
                                                    foreground: root.barForeground
                                                }
                                            }
                                            Text { width: parent.width; textFormat: Text.PlainText; text: "OnAccess: /home (clamd.conf) — see 󰋽 for details"; color: Qt.darker(root.barForeground,1.5); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.italic: true; wrapMode: Text.Wrap }
                                        }
                                        Text { visible: (root.toolData("clamav") && root.toolData("clamav").recent.length===0); width: parent.width; textFormat: Text.PlainText; text: (root.toolData("clamav") && root.toolData("clamav").total===0) ? "No detections." : "No recent detections."; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                        Repeater {
                                            model: (root.toolData("clamav") && root.showClamav) ? root.toolData("clamav").recent.slice(0,3) : []
                                            delegate: BorderSurface {
                                                required property var modelData
                                                width: clamCol.width
                                                implicitHeight: cRow.implicitHeight + Style.space(8)
                                                color: modelData.present ? Style.hoverFillFor(root.barUrgent, root.barUrgent) : "transparent"
                                                borderSpec: Border.controlSpec("normal", modelData.present ? root.barUrgent : Qt.darker(root.barForeground,1.6), root.barUrgent)
                                                radius: Style.cornerRadius
                                                Column {
                                                    id: cRow
                                                    anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top; anchors.margins: Style.space(6)
                                                    spacing: Style.space(2)
                                                    Text { textFormat: Text.PlainText; width: parent.width; text: modelData.signature; color: modelData.present ? root.barUrgent : root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold:true; elide: Text.ElideRight }
                                                    Text { textFormat: Text.PlainText; width: parent.width; text: modelData.path + " \u00b7 " + root.formatEpoch(modelData.whenEpoch); color: Qt.darker(root.barForeground,1.3); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideMiddle }
                                                }
                                            }
                                        }
                                        RowLayout {
                                            width: parent.width
                                            Button { text: "Scan ~/Downloads"; fontSize: Style.font.caption; onClicked: root.runClamScan("~/Downloads") }
                                            Item { Layout.fillWidth:true }
                                            Text { visible: root.toolData("clamav") && !root.toolData("clamav").installed; textFormat: Text.PlainText; text: "pacman -S clamav"; color: root.barUrgent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                        }
                                    }
                                }
                            }

                            // Mini Firewall
                            BorderSurface {
                                width: parent.width
                                implicitHeight: ufwCol.implicitHeight + Style.space(14)
                                radius: Style.cornerRadius
                                color: "transparent"
                                borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.6), Color.accent)
                                Column {
                                    id: ufwCol
                                    anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                                    anchors.margins: Style.space(8)
                                    spacing: Style.space(6)
                                    RowLayout {
                                        width: parent.width
                                        Text { textFormat: Text.PlainText; text: ufwCtrl.glyph; color: (ufwCtrl.isOn ? Color.accent : root.barUrgent); font.family: root.barFontFamily; font.pixelSize: Style.font.title }
                                        Column { Layout.fillWidth: true; Text { textFormat: Text.PlainText; text: "Firewall"; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.body; font.bold:true } Text { textFormat: Text.PlainText; text: ufwCtrl.statusWord + (root.toolData("ufw") ? " \u00b7 " + root.toolData("ufw").ruleCount + " rules" : ""); color: Qt.darker(root.barForeground,1.45); font.family: root.barFontFamily; font.pixelSize: Style.font.caption } }
                                        SmallGauge { score: root.toolData("ufw") ? root.toolData("ufw").score : 0; maxScore: 25; size: 48 }
                                        PanelActionButton { iconText: root.showUfw ? "\uf106" : "\uf107"; onClicked: root.showUfw = !root.showUfw }
                                    }
                                    Column {
                                        visible: root.showUfw
                                        width: parent.width
                                        spacing: Style.space(4)
                                        RowLayout {
                                            width: parent.width
                                            Text { textFormat: Text.PlainText; text: ufwCtrl.isOn ? "Active" : "Inactive"; color: ufwCtrl.isOn ? Color.accent : root.barUrgent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold:true }
                                            Item { Layout.fillWidth:true }
                                            ToggleSwitch { visible: (root.toolData("ufw") ? root.toolData("ufw").installed : false); checked: ufwCtrl.isOn; busy: ufwCtrl.busy; foreground: root.barForeground }
                                        }
                                        // MouseArea removed to save space — toggle via switch click
                                        RowLayout {
                                            width: parent.width
                                            Text { Layout.fillWidth:true; textFormat: Text.PlainText; text: (root.toolData("ufw") ? root.toolData("ufw").ruleCount : 0) + " rules" + (root.toolData("ufw") && root.toolData("ufw").defaults ? " \u00b7 in " + root.toolData("ufw").defaults.input : ""); color: Qt.darker(root.barForeground,1.3); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight }
                                            Button { text: root.showUfwRules ? "Hide rules" : "View rules"; fontSize: Style.font.caption; onClicked: root.showUfwRules = !root.showUfwRules }
                                        }
                                        // Scrollable full rules list (saves space when collapsed)
                                        BorderSurface {
                                            visible: root.showUfwRules && root.showUfw
                                            width: parent.width
                                            implicitHeight: 180
                                            radius: Style.cornerRadius
                                            color: Style.hoverFillFor(root.barForeground, root.barForeground)
                                            borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.7), Color.accent)
                                            Flickable {
                                                anchors.fill: parent
                                                anchors.margins: Style.space(6)
                                                contentWidth: width
                                                contentHeight: ruleListCol.implicitHeight
                                                clip: true
                                                boundsBehavior: Flickable.StopAtBounds
                                                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                                                Column {
                                                    id: ruleListCol
                                                    width: parent.width
                                                    spacing: Style.space(3)
                                                    Repeater {
                                                        model: ufwCtrl.ruleRows
                                                        delegate: RowLayout {
                                                            required property var modelData
                                                            width: ruleListCol.width
                                                            spacing: Style.space(6)
                                                            Text { textFormat: Text.PlainText; text: modelData.glyph; color: modelData.action==="deny"||modelData.action==="reject" ? root.barUrgent : root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                                            Column {
                                                                Layout.fillWidth: true
                                                                spacing: 1
                                                                Text { width: parent.width; textFormat: Text.PlainText; text: modelData.label; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold: true; elide: Text.ElideRight }
                                                                Text { width: parent.width; textFormat: Text.PlainText; text: modelData.verb + " \u00b7 " + modelData.detail; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight }
                                                            }
                                                            Text { textFormat: Text.PlainText; text: modelData.directionGlyph; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                                        }
                                                    }
                                                    Text { visible: ufwCtrl.ruleRows.length===0; width: parent.width; textFormat: Text.PlainText; text: (root.toolData("ufw") && root.toolData("ufw").rulesReadable===false) ? "Rules not readable (permission)" : "No rules — default policies apply."; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Mini RKHunter
                            BorderSurface {
                                width: parent.width
                                implicitHeight: rkhCol.implicitHeight + Style.space(14)
                                radius: Style.cornerRadius
                                color: "transparent"
                                borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.6), Color.accent)
                                Column {
                                    id: rkhCol
                                    anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                                    anchors.margins: Style.space(8)
                                    spacing: Style.space(6)
                                    RowLayout {
                                        width: parent.width
                                        Text { textFormat: Text.PlainText; text: "󱢼"; color: (root.toolData("rkhunter") && root.toolData("rkhunter").warnings.length>0) ? root.barUrgent : Color.accent; font.family: root.barFontFamily; font.pixelSize: Style.font.title }
                                        Column { Layout.fillWidth: true; Text { textFormat: Text.PlainText; text: "RKHunter"; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.body; font.bold:true } Text { textFormat: Text.PlainText; text: root.toolData("rkhunter") ? (root.toolData("rkhunter").label + (root.toolData("rkhunter").lastCheckEpoch ? " \u00b7 " + root.ago(root.toolData("rkhunter").lastCheckEpoch) : "")) : "--"; color: Qt.darker(root.barForeground,1.45); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight } }
                                        SmallGauge { score: root.toolData("rkhunter") ? root.toolData("rkhunter").score : 0; maxScore:25; size: 48 }
                                        PanelActionButton { iconText: root.showRkhunter ? "\uf106" : "\uf107"; onClicked: root.showRkhunter = !root.showRkhunter }
                                    }
                                    Column {
                                        visible: root.showRkhunter
                                        width: parent.width
                                        spacing: Style.space(4)
                                        Text { visible: root.toolData("rkhunter") && root.toolData("rkhunter").warnings.length===0; width: parent.width; textFormat: Text.PlainText; text: root.toolData("rkhunter") && root.toolData("rkhunter").status==="clean" ? "No warnings — clean." : "No warnings. Run check to refresh."; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap }
                                        Flickable {
                                            width: parent.width
                                            height: Math.min(220, Math.max(80, rkhBody.implicitHeight))
                                            clip: true
                                            contentWidth: width
                                            contentHeight: rkhBody.implicitHeight
                                            boundsBehavior: Flickable.StopAtBounds
                                            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                                            Column {
                                                id: rkhBody
                                                width: parent.width
                                                spacing: Style.space(4)
                                        Repeater {
                                            model: (root.toolData("rkhunter") && root.showRkhunter) ? root.toolData("rkhunter").warnings : []
                                            delegate: BorderSurface {
                                                required property var modelData
                                                width: rkhCol.width - Style.space(6)
                                                implicitHeight: rwCol.implicitHeight + Style.space(8)
                                                color: Style.hoverFillFor(root.barUrgent, root.barUrgent)
                                                borderSpec: Border.controlSpec("normal", root.barUrgent, root.barUrgent)
                                                radius: Style.cornerRadius
                                                Column {
                                                    id: rwCol
                                                    anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top; anchors.margins: Style.space(6)
                                                    spacing: Style.space(2)
                                                    RowLayout { width: parent.width; Text { textFormat: Text.PlainText; text: "\uf071"; color: root.barUrgent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption } Text { Layout.fillWidth:true; textFormat: Text.PlainText; text: modelData.id; color: root.barUrgent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold:true; elide: Text.ElideRight } PanelActionButton { iconText: "\uF06E"; tooltipText: "Open details"; onClicked: root.openRkhDetail(modelData.id, modelData.text) } PanelActionButton { iconText: "\uF0A8"; tooltipText: "Ignore"; onClicked: root.addException("rkhunter", modelData.id) } }
                                                    Text { width: parent.width; textFormat: Text.PlainText; text: modelData.text; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap; maximumLineCount: 2; elide: Text.ElideRight }
                                                }
                                            }
                                        }
                                            }
                                        }
                                        RowLayout { width: parent.width; visible: root.toolData("rkhunter") ? root.toolData("rkhunter").installed : false; Button { text: "Run check"; fontSize: Style.font.caption; onClicked: if(root.bar) root.bar.run("omarchy-launch-floating-terminal-with-presentation " + Util.shellQuote("sudo rkhunter --check --sk --report-warnings-only --no-verbose-logging; echo '--- Done (warnings only), press Enter'; read")) } Item { Layout.fillWidth:true } Text { visible: (root.toolData("rkhunter") ? root.toolData("rkhunter").warningsFiltered : 0) > 0; textFormat: Text.PlainText; text: (root.toolData("rkhunter") ? root.toolData("rkhunter").warningsFiltered : 0) + " ignored"; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption } }
                                    }
                                }
                            }
                        }
                    }

                    // ═══ CVE TICKER (news-style marquee) ═══
                    BorderSurface {
                        visible: root.cveEnabled
                        width: parent.width
                        implicitHeight: 38
                        radius: Style.cornerRadius
                        color: Style.hoverFillFor(root.barForeground, root.barForeground)
                        borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.7), Color.accent)
                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Style.space(6)
                            anchors.rightMargin: Style.space(6)
                            spacing: Style.space(8)
                            Text { textFormat: Text.PlainText; text: "\uF0A3  CVE"; color: Color.accent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold:true }
                            // Ticker viewport
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                color: "transparent"
                                clip: true
                                // Hover to pause
                                MouseArea {
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    onEntered: root.cvePaused = true
                                    onExited: root.cvePaused = false
                                    onClicked: {
                                        // open first filtered CVE in browser
                                        var f = root.cveFiltered
                                        if(f && f.length>0 && f[0].link && root.bar) root.bar.run("xdg-open " + Util.shellQuote(f[0].link))
                                    }
                                    cursorShape: Qt.PointingHandCursor
                                }
                                Text {
                                    id: tickerText
                                    y: (parent.height - implicitHeight)/2
                                    textFormat: Text.PlainText
                                    text: root.cveTickerText + root.cveTickerText // double for seamless loop
                                    color: root.barForeground
                                    font.family: root.barFontFamily
                                    font.pixelSize: Style.font.caption
                                    // animate x
                                    property int dur: Math.max(18000, text.length * 85)
                                    x: 0
                                    SequentialAnimation on x {
                                        loops: Animation.Infinite
                                        running: !root.cvePaused && root.cveFiltered.length>0
                                        NumberAnimation { from: 0; to: -tickerText.implicitWidth/2; duration: tickerText.dur; easing.type: Easing.Linear }
                                        NumberAnimation { from: -tickerText.implicitWidth/2; to: 0; duration: 0 }
                                    }
                                }
                            }
                            PanelActionButton { iconText: root.cveLinuxOnly ? "\uF023" : "\uF09C"; tooltipText: root.cveLinuxOnly ? "Linux filter: ON (click to show all)" : "Linux filter: OFF (click to filter)"; foreground: root.cveLinuxOnly ? Color.accent : root.barForeground; onClicked: root.cveLinuxOnly = !root.cveLinuxOnly }
                            PanelActionButton { iconText: "\uF021"; tooltipText: "Refresh CVEs"; onClicked: cveProc.running = true }
                            PanelActionButton { iconText: root.showCve ? "\uf106" : "\uf107"; tooltipText: root.showCve ? "Hide details" : "Show details"; onClicked: root.showCve = !root.showCve }
                        }
                    }
                    // Expanded CVE details (still available below ticker)
                    BorderSurface {
                        visible: root.cveEnabled && root.showCve
                        width: parent.width
                        implicitHeight: cveCol.implicitHeight + Style.space(14)
                        radius: Style.cornerRadius
                        color: "transparent"
                        borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.7), Color.accent)
                        Column {
                            id: cveCol
                            anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top
                            anchors.margins: Style.space(8)
                            spacing: Style.space(6)
                            RowLayout {
                                width: parent.width
                                Text { textFormat: Text.PlainText; text: (root.cveLinuxOnly ? "Filtered" : "Latest") + " (" + root.cveFiltered.length + ")"; color: Qt.darker(root.barForeground,1.45); font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                                Item { Layout.fillWidth: true }
                                Text { visible: root.cveFiltered.length!==root.cveData.items.length; textFormat: Text.PlainText; text: root.cveData.items.length + " total"; color: Qt.darker(root.barForeground,1.6); font.family: root.barFontFamily; font.pixelSize: Style.font.caption }
                            }
                            Repeater {
                                model: root.showCve ? root.cveFiltered.slice(0, root.cveMaxItems) : []
                                delegate: BorderSurface {
                                    required property var modelData
                                    width: cveCol.width
                                    implicitHeight: cvRow.implicitHeight + Style.space(8)
                                    color: "transparent"
                                    borderSpec: Border.controlSpec("normal", Qt.darker(root.barForeground,1.7), Color.accent)
                                    radius: Style.cornerRadius
                                    Column {
                                        id: cvRow
                                        anchors.left: parent.left; anchors.right: parent.right; anchors.top: parent.top; anchors.margins: Style.space(6)
                                        spacing: Style.space(2)
                                        RowLayout {
                                            width: parent.width
                                            Text { textFormat: Text.PlainText; text: modelData.cve; color: Color.accent; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.bold:true }
                                            Text { Layout.fillWidth:true; textFormat: Text.PlainText; text: modelData.date; color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight; horizontalAlignment: Text.AlignRight }
                                            PanelActionButton { iconText: "\uF08E"; tooltipText: "Open in browser"; onClicked: if(root.bar) root.bar.run("xdg-open " + Util.shellQuote(modelData.link)) }
                                        }
                                        Text { width: parent.width; textFormat: Text.PlainText; text: modelData.title; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap; maximumLineCount: 2; elide: Text.ElideRight }
                                    }
                                    MouseArea { anchors.fill: parent; acceptedButtons: Qt.LeftButton; propagateComposedEvents: true; onClicked: function(e){ if(e.button===Qt.LeftButton && modelData.link && root.bar) root.bar.run("xdg-open " + Util.shellQuote(modelData.link)) } }
                                }
                            }
                            Text { width: parent.width; textFormat: Text.PlainText; text: "Source: https://cvefeed.io/rssfeed/latest.xml — hover ticker to pause, click to open."; color: Qt.darker(root.barForeground,1.6); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; wrapMode: Text.Wrap }
                        }
                    }

                    // ═══ FOOTER ═══
                    Text {
                        width: parent.width
                        textFormat: Text.PlainText
                        text: "R to rescan · Click CVE to open · Shield hides ignored findings · v0.1.0"
                        color: Qt.darker(root.barForeground,1.6)
                        font.family: root.barFontFamily
                        font.pixelSize: Style.font.caption
                        horizontalAlignment: Text.AlignHCenter
                        wrapMode: Text.Wrap
                    }
                }
            }
            // ── Lynis detail overlay (covers whole panel, outside Flickable) ──
            Item {
                anchors.fill: parent
                visible: root.detailText !== "" || root.lynisDetailText !== ""
                z: 10
                Rectangle { anchors.fill: parent; color: Util.alpha(Color.background, 0.85); MouseArea { anchors.fill: parent; onClicked: root.closeLynisDetail() } }
                Rectangle {
                    anchors.centerIn: parent
                    width: parent.width - Style.space(24)
                    implicitHeight: detailCol2.implicitHeight + Style.space(24)
                    radius: Style.space(8)
                    color: Color.background
                    border.color: Color.accent
                    border.width: 1
                    Column {
                        id: detailCol2
                        anchors.fill: parent
                        anchors.margins: Style.space(12)
                        spacing: Style.space(8)
                        Text { textFormat: Text.PlainText; text: root.detailId !== "" ? root.detailId : root.lynisDetailId; color: Color.accent; font.family: root.barFontFamily; font.pixelSize: Style.font.body; font.bold: true; width: parent.width; wrapMode: Text.Wrap }
                        Flickable {
                            width: parent.width
                            height: Math.min(320, detailText2.implicitHeight)
                            contentHeight: detailText2.implicitHeight
                            clip: true
                            Text { id: detailText2; width: parent.width; textFormat: Text.PlainText; text: root.detailText !== "" ? root.detailText : root.lynisDetailText; color: root.barForeground; font.family: root.barFontFamily; font.pixelSize: Style.font.bodySmall; wrapMode: Text.Wrap }
                        }
                        Text { visible: (root.detailId !== "" ? root.detailId : root.lynisDetailId) !== ""; width: parent.width; textFormat: Text.PlainText; text: (root.detailKind==="rkhunter" ? "See: rkhunter docs" : "Doc: cisofy.com/lynis/controls/" + (root.detailId !== "" ? root.detailId : root.lynisDetailId) + "/"); color: Qt.darker(root.barForeground,1.4); font.family: root.barFontFamily; font.pixelSize: Style.font.caption; font.italic: true; elide: Text.ElideMiddle }
                        RowLayout {
                            width: parent.width
                            Button { text: "Copy"; fontSize: Style.font.caption; onClicked: root.copyToClipboard(root.detailText !== "" ? root.detailText : root.lynisDetailText) }
                            Button { visible: root.detailKind==="lynis"; text: "Google"; fontSize: Style.font.caption; onClicked: if(root.bar) root.bar.run("xdg-open " + Util.shellQuote("https://www.google.com/search?q=lynis+" + (root.detailId !== "" ? root.detailId : root.lynisDetailId))) }
                            Button { visible: root.detailKind==="lynis"; text: "CIS Docs"; fontSize: Style.font.caption; onClicked: if(root.bar) root.bar.run("xdg-open " + Util.shellQuote("https://cisofy.com/lynis/controls/" + (root.detailId !== "" ? root.detailId : root.lynisDetailId) + "/")) }
                            Button { visible: root.detailKind==="rkhunter"; text: "Google"; fontSize: Style.font.caption; onClicked: if(root.bar) root.bar.run("xdg-open " + Util.shellQuote("https://www.google.com/search?q=" + (root.detailId !== "" ? root.detailId : root.lynisDetailId))) }
                            Item { Layout.fillWidth: true }
                            Button { text: "Ignore"; fontSize: Style.font.caption; onClicked: { if(root.detailKind==="rkhunter") root.addException("rkhunter", root.detailId); else root.addException("lynis", root.detailId !== "" ? root.detailId : root.lynisDetailId); root.closeLynisDetail() } }
                            Button { text: "Close"; fontSize: Style.font.caption; onClicked: root.closeLynisDetail() }
                        }
                    }
                }
            }
        }
    }
}
