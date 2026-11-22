import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import "Model.js" as Model

// Minimal UFW controller — reads state files, offers enable/disable/reload via pkexec.
// Based on srozen.ufw UfwController.qml (MIT).
Item {
    id: root
    property var settings: ({})

    property bool installed: false
    property bool probed: false
    property var fileEnabled: null
    property string logLevel: ""
    property var defaults: ({ input: "deny", output: "allow", forward: "deny", ipv6: true })
    property var ruleRows: []
    property bool rulesReadable: true

    property bool acting: false
    property string actionStatus: ""
    property string lastError: ""
    property int _desired: -1

    readonly property var firewallOn: _desired >= 0 ? _desired === 1 : fileEnabled
    readonly property bool stateKnown: firewallOn !== null && firewallOn !== undefined
    readonly property bool isOn: firewallOn === true
    readonly property bool busy: acting || _desired >= 0
    readonly property string glyph: isOn ? Model.GLYPH_WALL_FIRE : Model.GLYPH_WALL
    readonly property string statusWord: Model.statusWord(installed, firewallOn)

    readonly property string elevation: {
        var v = String(settings && settings.elevation ? settings.elevation : "pkexec").toLowerCase()
        return v === "terminal" ? "terminal" : "pkexec"
    }
    readonly property var _ufwCandidates: ["/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw", "/bin/ufw"]
    property string _ufwPath: ""
    readonly property string _pkexecPath: "/usr/bin/pkexec"
    readonly property string _sudoPath: "/usr/bin/sudo"
    signal terminalRequested(string command)

    function refresh() { confFile.reload(); defaultsFile.reload(); rulesFile.reload(); rules6File.reload() }
    function toggle() { if (!installed) return; setEnabled(!isOn) }
    function setEnabled(v) {
        if (!installed || acting) return
        if (stateKnown && v === isOn) return
        root._desired = v ? 1 : 0
        root.actionStatus = v ? "Enabling…" : "Disabling…"
        run(v ? ["--force","enable"] : ["disable"])
    }
    function reloadFirewall() {
        if (!installed || acting || !isOn) return
        root.actionStatus = "Reloading…"
        run(["reload"])
    }
    function run(args) {
        if (root._ufwPath === "") return
        var bin = root._ufwPath
        root.lastError = ""
        if (root.elevation === "terminal") {
            root.terminalRequested(root._sudoPath + " " + bin + " " + args.join(" "))
            root.actionStatus = ""
            settleTimer.ticks = 0; settleTimer.restart(); return
        }
        root.acting = true
        actionProcess.command = [root._pkexecPath, bin].concat(args)
        actionProcess.running = true
    }
    function _finish(exitCode, msg) {
        root.acting = false; root.actionStatus = ""
        if (exitCode === 0) root.lastError = ""
        else { root._desired = -1; root.lastError = (exitCode === 126 || exitCode === 127) ? "" : (String(msg||"").replace(/^\s+|\s+$/g,"") || "Command failed.") }
        settleTimer.ticks = 0; settleTimer.restart(); refresh()
    }
    function _applyConf(t) {
        root.fileEnabled = Model.parseEnabled(t)
        root.logLevel = Model.parseLogLevel(t)
        if (root._desired >= 0 && root.fileEnabled === (root._desired === 1)) root._desired = -1
    }
    function _applyRules() { root.ruleRows = Model.buildRuleRows(rulesFile.text(), rules6File.text()) }

    Component.onCompleted: probeProcess.running = true

    Process {
        id: probeProcess
        running: false
        command: ["/bin/sh","-c","for p in " + root._ufwCandidates.join(" ") + "; do if [ -x \"$p\" ]; then echo \"$p\"; break; fi; done"]
        stdout: StdioCollector { id: probeStdout; waitForEnd: true }
        onExited: function(code) {
            var f = String(probeStdout.text||"").replace(/^\s+|\s+$/g,"")
            root._ufwPath = root._ufwCandidates.indexOf(f) >= 0 ? f : ""
            root.installed = root._ufwPath !== ""
            root.probed = true
            if (root.installed) root.refresh()
        }
    }
    Process {
        id: actionProcess
        running: false; command: []
        stdout: StdioCollector { id: actionStdout; waitForEnd: true }
        stderr: StdioCollector { id: actionStderr; waitForEnd: true }
        onExited: function(c) { root._finish(c, String(actionStderr.text||actionStdout.text||"")) }
    }
    FileView { id: confFile; path: "/etc/ufw/ufw.conf"; watchChanges: true; printErrors:false; onLoaded: root._applyConf(text()); onFileChanged: reload(); onLoadFailed: root.fileEnabled = null }
    FileView { id: defaultsFile; path: "/etc/default/ufw"; watchChanges: true; printErrors:false; onLoaded: root.defaults = Model.parseDefaults(text()); onFileChanged: reload() }
    FileView { id: rulesFile; path: "/etc/ufw/user.rules"; watchChanges: true; printErrors:false; onLoaded: { root.rulesReadable = true; root._applyRules() } onFileChanged: reload(); onLoadFailed: { root.rulesReadable = false; root.ruleRows = [] } }
    FileView { id: rules6File; path: "/etc/ufw/user6.rules"; watchChanges: true; printErrors:false; onLoaded: root._applyRules(); onFileChanged: reload() }
    Timer { id: settleTimer; property int ticks:0; interval:700; repeat:true; running: root._desired >=0; onTriggered: { ticks+=1; root.refresh(); if(ticks>=12){ ticks=0; root._desired=-1; stop() } } }
}
