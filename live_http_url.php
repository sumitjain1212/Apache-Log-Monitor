<?php

// Basic browser-side security headers. Protect the endpoint itself with
// your web server's authentication/authorization as described in README.md.
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
// ─── Configuration ────────────────────────────────────────────────────────────
// Copy config.example.php to config.php and set values for your environment.
// config.php is intentionally excluded from Git.
$configFile = __DIR__ . '/config.php';
if (!is_readable($configFile)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    exit("Apache Log Monitor is not configured. Create config.php from config.example.php.\n");
}
require_once $configFile;

$requiredConfig = array('MASTER_CONF', 'SSH_USER', 'SSH_KEY', 'CONN_TIMEOUT', 'LOG_BASE');
foreach ($requiredConfig as $configName) {
    if (!isset($$configName)) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=UTF-8');
        exit("Missing configuration value: ".$configName."\n");
    }
}

function jsonResponse($data, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function validHost($host) {
    return $host !== '' && preg_match('/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/', $host);
}

function validLogName($name) {
    return $name !== '' && preg_match('/^[a-zA-Z0-9][a-zA-Z0-9._-]*_(access|error)_log$/', $name);
}

function logPathForHost($host, $name, $LOG_BASE) {
    return rtrim($LOG_BASE, '/') . '/' . $host . '/common/' . $name;
}

// ──────────────────────────────────────────────────────────────────────────────

function sshRun($host, $cmd, $SSH_USER, $SSH_KEY, $CONN_TIMEOUT) {
    global $SSH_KNOWN_HOSTS, $SSH_STRICT_HOST_KEY_CHECKING;

    $target = ($SSH_USER !== '') ? $SSH_USER . '@' . $host : $host;
    $identFlag = ($SSH_KEY !== '') ? ' -i ' . escapeshellarg($SSH_KEY) : '';
    $knownFlag = (!empty($SSH_KNOWN_HOSTS))
               ? ' -o UserKnownHostsFile=' . escapeshellarg($SSH_KNOWN_HOSTS)
               : '';
    $strictFlag = (isset($SSH_STRICT_HOST_KEY_CHECKING) && $SSH_STRICT_HOST_KEY_CHECKING === false)
                ? ' -o StrictHostKeyChecking=no'
                : ' -o StrictHostKeyChecking=yes';

    $b64 = base64_encode($cmd);
    $full = 'ssh -q -o BatchMode=yes -o ConnectTimeout='.(int)$CONN_TIMEOUT
          . $strictFlag . $knownFlag . $identFlag . ' '
          . escapeshellarg($target)
          . " 'printf \"%s\" ".escapeshellarg($b64)." | base64 -d | sh' 2>&1";

    $out = shell_exec($full);
    return trim($out !== null ? $out : '');
}

function hostIsConfigured($host, $MASTER_CONF) {
    if (!validHost($host) || !is_readable($MASTER_CONF)) return false;
    $cmd = 'awk -v h='.escapeshellarg($host)." \'$1 == h {found=1} END {exit !found}\' "
         . escapeshellarg($MASTER_CONF) . ' 2>/dev/null';
    exec($cmd, $unused, $status);
    return $status === 0;
}

// ── action=hosts ─────────────────────────────────────────────────────────────
if (isset($_GET['action']) && $_GET['action'] === 'hosts') {
    if (!is_readable($MASTER_CONF)) {
        jsonResponse(array('hosts' => array(), 'error' => 'Master configuration is not readable'), 500);
    }

    $cmd = "awk '{print \$1}' ".escapeshellarg($MASTER_CONF)
         . " | grep -v '^#' | grep -v '^$' | grep -v '^__default__' | sort -u";
    $raw = shell_exec($cmd.' 2>/dev/null');
    $hosts = array_values(array_filter(array_map('trim', explode("\n", trim($raw ?: '')))));
    jsonResponse(array('hosts' => $hosts));
}

// ── action=logs — list access and error logs on a configured host ─────────────
if (isset($_GET['action']) && $_GET['action'] === 'logs') {
    $host = trim(isset($_GET['host']) ? $_GET['host'] : '');

    if (!hostIsConfigured($host, $MASTER_CONF)) {
        jsonResponse(array('logs' => array(), 'error' => 'Host is not configured'), 400);
    }

    $base = rtrim($LOG_BASE, '/') . '/' . $host . '/common';
    $script = 'for f in '.escapeshellarg($base).'/*_access_log '
            . escapeshellarg($base).'/*_error_log; do
    [ -f "$f" ] || continue
    SIZE=$(du -h "$f" 2>/dev/null | awk "{print \$1}")
    case "$f" in
        *_access_log) TYPE=access ;;
        *_error_log) TYPE=error ;;
        *) continue ;;
    esac
    printf "%s|%s|%s\\n" "$f" "$SIZE" "$TYPE"
done';

    $raw = sshRun($host, $script, $SSH_USER, $SSH_KEY, $CONN_TIMEOUT);
    $logs = array();

    foreach (explode("\n", $raw) as $line) {
        $line = trim($line);
        if ($line === '') continue;

        $parts = explode('|', $line);
        if (count($parts) !== 3) continue;

        $name = basename($parts[0]);
        if (!validLogName($name)) continue;

        $logs[] = array(
            'path' => logPathForHost($host, $name, $LOG_BASE),
            'name' => $name,
            'size' => $parts[1],
            'type' => $parts[2]
        );
    }

    jsonResponse(array(
        'logs' => $logs,
        'error' => empty($logs) ? 'No access/error logs found' : ''
    ));
}

// ── action=tail — stream last N lines of a selected log ───────────────────────
if (isset($_GET['action']) && $_GET['action'] === 'tail') {
    $host  = trim(isset($_GET['host']) ? $_GET['host'] : '');
    $name  = trim(isset($_GET['name']) ? $_GET['name'] : '');
    $lines = max(20, min(500, (int)(isset($_GET['lines']) ? $_GET['lines'] : 50)));

    if (!hostIsConfigured($host, $MASTER_CONF)) {
        jsonResponse(array('error' => 'Host is not configured'), 400);
    }
    if (!validLogName($name)) {
        jsonResponse(array('error' => 'Invalid log name'), 400);
    }

    $log = logPathForHost($host, $name, $LOG_BASE);
    $script = 'if [ -f '.escapeshellarg($log).' ]; then tail -'.intval($lines).' '
             .escapeshellarg($log).' 2>/dev/null; else echo "__LOG_NOT_FOUND__"; fi';

    $raw = sshRun($host, $script, $SSH_USER, $SSH_KEY, $CONN_TIMEOUT);

    if (strpos($raw, '__LOG_NOT_FOUND__') !== false) {
        jsonResponse(array('error' => 'Log file not found or no longer available'), 404);
    }

    $loglines = array_values(array_filter(explode("\n", $raw), function($l){
        return trim($l) !== '';
    }));
    jsonResponse(array('lines' => $loglines, 'count' => count($loglines)));
}

// ── action=stats — run access-log statistics ─────────────────────────────────
if (isset($_GET['action']) && $_GET['action'] === 'stats') {
    $host = trim(isset($_GET['host']) ? $_GET['host'] : '');
    $name = trim(isset($_GET['name']) ? $_GET['name'] : '');

    if (!hostIsConfigured($host, $MASTER_CONF)) {
        jsonResponse(array('error' => 'Host is not configured'), 400);
    }
    if (!validLogName($name)) {
        jsonResponse(array('error' => 'Invalid log name'), 400);
    }

    if (strpos($name, '_error_log') !== false) {
        jsonResponse(array('error' => 'Statistics are available only for access logs'), 400);
    }

    $log = logPathForHost($host, $name, $LOG_BASE);

    // Inline moni.sh logic — key sections only, no file writes, output directly
    $script = <<<'BASH'
LOG="__LOG__"
if [ ! -f "$LOG" ]; then echo "ERROR: log not found: $LOG"; exit 1; fi

echo "SECTION:Summary"
TOTAL=$(wc -l < "$LOG")
FIRST=$(head -1 "$LOG" | cut -d'"' -f1 | cut -d'[' -f2 | cut -d']' -f1)
echo "Total entries: $TOTAL"
echo "First entry:   $FIRST"
echo "ENDSECTION"

echo "SECTION:Top 10 User Agents (last 600k hits)"
tail -600000 "$LOG" | cut -d'"' -f6 | sort | uniq -ic | sort -rh | head -10
echo "ENDSECTION"

echo "SECTION:Top 10 IPs (last 600k hits)"
tail -600000 "$LOG" | awk '{print $1,$3}' | sort | uniq -c | sort -rn | head -10
echo "ENDSECTION"

echo "SECTION:Response Code Distribution (last 600k hits)"
tail -600000 "$LOG" | awk '{print $9}' | sort | uniq -c | sort -rn
echo "ENDSECTION"

echo "SECTION:Top 10 URLs with 500 errors"
awk '($9 ~ /^500$/)' "$LOG" | awk '{print $7}' | grep -v xcf | grep -v xce | sort | uniq -c | sort -rn | head -10
echo "ENDSECTION"

echo "SECTION:Top 10 URLs with 400 errors"
awk '($9 ~ /^400$/)' "$LOG" | awk '{print $7}' | grep -v xcf | grep -v xce | sort | uniq -c | sort -rn | head -10
echo "ENDSECTION"

echo "SECTION:Top 10 URLs with 401 Unauthorized"
awk '($9 ~ /^401$/)' "$LOG" | awk '{print $7}' | grep -v xcf | grep -v xce | sort | uniq -c | sort -rn | head -10
echo "ENDSECTION"

echo "SECTION:Top 10 URLs with 403 Forbidden"
awk '($9 ~ /^403$/)' "$LOG" | awk '{print $7}' | grep -v xcf | grep -v xce | sort | uniq -c | sort -rn | head -10
echo "ENDSECTION"

echo "SECTION:Last 10 404 Not Found"
tail -600000 "$LOG" | awk '($9 ~ /^404$/)' | awk -F'"' '{print $1, $2}' | tail -10
echo "ENDSECTION"

echo "SECTION:Top 10 Popular URLs (last 600k hits)"
tail -600000 "$LOG" | awk -F'"' '{print $2}' | sort | uniq -c | sort -rn | head -10
echo "ENDSECTION"
BASH;

    $script = str_replace('__LOG__', addslashes($log), $script);
    $raw = sshRun($host, $script, $SSH_USER, $SSH_KEY, $CONN_TIMEOUT);

    $sections = array();
    $lines = explode("\n", $raw);
    $cur = null;
    $buf = array();

    foreach ($lines as $line) {
        $line = rtrim($line);
        if (strpos($line, 'SECTION:') === 0) {
            $cur = substr($line, 8);
            $buf = array();
        } elseif ($line === 'ENDSECTION' && $cur !== null) {
            $sections[] = array('title' => $cur, 'lines' => $buf);
            $cur = null;
            $buf = array();
        } elseif ($cur !== null) {
            $buf[] = $line;
        }
    }

    $errCheck = '';
    if (count($sections) === 0) $errCheck = $raw ?: 'No output from stats script';
    jsonResponse(array('sections' => $sections, 'error' => $errCheck));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Apache Log Monitor</title>
<style>
600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--border:#30363d;
  --amber:#e3a21a;--green:#3fb950;--red:#f85149;--yellow:#d29922;--blue:#58a6ff;
  --purple:#bc8cff;--cyan:#39d353;
  --muted:#8b949e;--text:#c9d1d9;--bright:#f0f6fc;
  --mono:'IBM Plex Mono','DejaVu Sans Mono',monospace;--sans:'IBM Plex Sans','Segoe UI',Arial,sans-serif;
}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;padding-bottom:60px}

header{background:var(--surface);border-bottom:1px solid var(--border);padding:18px 36px;
  display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:50}
.hicon{width:34px;height:34px;background:var(--amber);border-radius:8px;
  display:grid;place-items:center;font-size:17px;flex-shrink:0}
header h1{font-family:var(--mono);font-size:15px;font-weight:600;color:var(--bright);letter-spacing:.05em}
header p{font-size:11px;color:var(--muted);margin-top:2px}
.hactions{margin-left:auto;display:flex;gap:8px;align-items:center}

.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 15px;border-radius:6px;
  font-family:var(--sans);font-size:13px;font-weight:500;cursor:pointer;
  border:1px solid transparent;transition:opacity .15s,background .15s}
.btn:disabled{opacity:.35;cursor:not-allowed}
.btn-primary{background:var(--amber);color:#000;border-color:var(--amber)}
.btn-primary:hover:not(:disabled){opacity:.82}
.btn-ghost{background:transparent;color:var(--text);border-color:var(--border)}
.btn-ghost:hover:not(:disabled){background:var(--surface2)}
.btn-sm{padding:4px 10px;font-size:11px;font-family:var(--mono)}
.btn-danger{background:transparent;color:var(--red);border-color:var(--red)}
.btn-danger:hover:not(:disabled){background:rgba(248,81,73,.08)}

/* 3-column layout */
main{max-width:1700px;margin:0 auto;padding:24px 32px;
  display:grid;grid-template-columns:220px 260px 1fr;gap:16px;align-items:start}
@media(max-width:1100px){main{grid-template-columns:220px 1fr}}

/* Sidebar panels */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.panel-head{padding:11px 14px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between}
.panel-head h2{font-family:var(--mono);font-size:11px;font-weight:600;
  color:var(--bright);text-transform:uppercase;letter-spacing:.08em}
.panel-count{font-family:var(--mono);font-size:10px;color:var(--muted)}
.panel-search{padding:8px 12px;border-bottom:1px solid var(--border)}
.panel-search input{width:100%;background:var(--bg);border:1px solid var(--border);
  border-radius:5px;padding:4px 8px;font-family:var(--mono);font-size:11px;
  color:var(--text);outline:none}
.panel-search input:focus{border-color:var(--amber)}
.panel-search input::placeholder{color:var(--muted)}
.item-list{max-height:calc(100vh - 260px);overflow-y:auto}
.list-item{padding:8px 14px;cursor:pointer;font-family:var(--mono);font-size:11px;
  color:var(--text);border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
  transition:background .1s;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.list-item:last-child{border-bottom:none}
.list-item:hover{background:var(--surface2)}
.list-item.active{background:rgba(227,162,26,.1);color:var(--amber);border-left:3px solid var(--amber)}
.list-item .li-name{flex:1;overflow:hidden;text-overflow:ellipsis}
.list-item .li-arrow{color:var(--muted);font-size:10px;flex-shrink:0;margin-left:4px}
.panel-empty{padding:20px;text-align:center;color:var(--muted);font-size:12px}

/* Content panel */
.content{}
.welcome{background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:50px;text-align:center;color:var(--muted)}
.welcome .ico{font-size:48px;margin-bottom:16px}
.welcome h2{font-family:var(--mono);font-size:14px;color:var(--bright);margin-bottom:8px}
.welcome p{font-size:13px;line-height:1.7}

/* Tabs */
.tab-bar{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:16px}
.tab{padding:9px 18px;font-family:var(--mono);font-size:12px;cursor:pointer;
  color:var(--muted);border-bottom:2px solid transparent;transition:all .15s;user-select:none}
.tab:hover{color:var(--text)}
.tab.on{color:var(--amber);border-bottom-color:var(--amber)}

/* Live tail panel */
.tail-controls{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.tail-controls label{font-size:11px;color:var(--muted);font-family:var(--mono)}
.tail-controls select,.tail-controls input[type=number]{
  background:var(--surface2);border:1px solid var(--border);border-radius:5px;
  color:var(--text);font-family:var(--mono);font-size:11px;padding:4px 8px;outline:none}
.tail-controls select:focus,.tail-controls input[type=number]:focus{border-color:var(--amber)}

.log-terminal{background:#010409;border:1px solid var(--border);border-radius:8px;
  font-family:var(--mono);font-size:11px;height:460px;overflow-y:auto;
  padding:12px 14px;line-height:1.65;position:relative}
.log-line{white-space:pre-wrap;word-break:break-all;border-bottom:1px solid rgba(48,54,61,.3);
  padding:2px 0}
.log-line:last-child{border-bottom:none}
.log-line.s2xx{color:#c9d1d9}
.log-line.s3xx{color:var(--blue)}
.log-line.s4xx{color:var(--yellow)}
.log-line.s5xx{color:var(--red)}
.log-line.new{animation:flash .6s ease-out}
@keyframes flash{0%{background:rgba(227,162,26,.18)}100%{background:transparent}}

.live-badge{display:inline-flex;align-items:center;gap:5px;background:rgba(63,185,80,.12);
  color:var(--green);border:1px solid rgba(63,185,80,.3);border-radius:20px;
  font-family:var(--mono);font-size:10px;font-weight:600;padding:2px 9px}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--green);
  animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.stopped-badge{display:none;align-items:center;gap:5px;background:rgba(139,148,158,.1);
  color:var(--muted);border:1px solid var(--border);border-radius:20px;
  font-family:var(--mono);font-size:10px;font-weight:600;padding:2px 9px}

.tail-footer{display:flex;align-items:center;justify-content:space-between;
  margin-top:8px;font-family:var(--mono);font-size:10px;color:var(--muted)}

/* Stats panel */
.stats-running{background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:20px;text-align:center;color:var(--muted);margin-bottom:14px}
.section-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;
  overflow:hidden;margin-bottom:12px}
.section-card-head{padding:10px 16px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;cursor:pointer;
  user-select:none}
.section-card-head h3{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--amber)}
.section-card-head .toggle{color:var(--muted);font-size:11px;font-family:var(--mono)}
.section-card-body{padding:0}
.section-line{padding:6px 16px;border-bottom:1px solid var(--border);
  font-family:var(--mono);font-size:11px;color:var(--text);
  display:flex;align-items:center;gap:10px;white-space:nowrap}
.section-line:last-child{border-bottom:none}
.section-line:hover{background:var(--surface2)}
.section-line .scount{color:var(--amber);font-weight:600;min-width:60px;text-align:right;flex-shrink:0}
.section-line .sval{flex:1;overflow:hidden;text-overflow:ellipsis;color:var(--text)}
.section-line .scode{padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600;flex-shrink:0}
.scode.s2{background:rgba(63,185,80,.12);color:var(--green)}
.scode.s3{background:rgba(88,166,255,.12);color:var(--blue)}
.scode.s4{background:rgba(210,153,34,.12);color:var(--yellow)}
.scode.s5{background:rgba(248,81,73,.12);color:var(--red)}
.section-empty{padding:14px 16px;font-family:var(--mono);font-size:11px;color:var(--muted);text-align:center}

/* Alerts */
.alert-err{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.3);
  border-radius:8px;padding:12px 16px;font-size:13px;color:var(--red);margin-bottom:14px}
.alert-ok{background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.3);
  border-radius:8px;padding:10px 14px;font-size:12px;color:var(--green);margin-bottom:14px;font-family:var(--mono)}
.log-access{
  color:#3fb950;
}

.log-error{
  color:#f85149;
}
.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--border);
  border-top-color:var(--amber);border-radius:50%;animation:sp .7s linear infinite;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
</style>
</head>
<body>
<header>
  <div class="hicon">📋</div>
  <div>
    <h1>APACHE LOG MONITOR</h1>
    <p>Live access/error log tail · Access-log statistics · SSH-based monitoring</p>
  </div>
  <div class="hactions">
    <span class="live-badge"    id="liveBadge"    style="display:none"><span class="live-dot"></span>LIVE</span>
    <span class="stopped-badge" id="stoppedBadge">⏹ STOPPED</span>
    <button class="btn btn-ghost btn-sm" id="btnAutoRefresh" disabled>⏸ Pause</button>
    <button class="btn btn-primary" id="btnLoad">▶ Load Hosts</button>
  </div>
</header>

<main>
  <!-- Col 1: Hosts -->
  <aside class="panel" id="hostPanel">
    <div class="panel-head">
      <h2>Hosts</h2>
      <span class="panel-count" id="hostCount">—</span>
    </div>
    <div class="panel-search"><input type="text" id="hostSearch" placeholder="Filter…"></div>
    <div class="item-list" id="hostList">
      <div class="panel-empty">Click <strong>Load Hosts</strong></div>
    </div>
  </aside>

  <!-- Col 2: Log files -->
  <aside class="panel" id="logPanel">
    <div class="panel-head">
      <h2>Logs</h2>
      <span class="panel-count" id="logCount">—</span>
    </div>
    <div class="panel-search"><input type="text" id="logSearch" placeholder="Filter…"></div>
    <div class="item-list" id="logList">
      <div class="panel-empty">Select a host</div>
    </div>
  </aside>

  <!-- Col 3: Content -->
  <div class="content">
    <div class="welcome" id="welcomePanel">
      <div class="ico">📊</div>
      <h2>Select Host → Log</h2>
      <p>Choose a host from the left panel,<br>then select an access log to begin.<br><br>
        <span style="color:var(--amber)">Live Tail</span> — streams new log entries every 5s<br>
        <span style="color:var(--amber)">Statistics</span> — runs moni.sh analysis on demand</p>
    </div>

    <div id="mainContent" style="display:none">
      <div id="alertBox"></div>

      <!-- Tab bar -->
      <div class="tab-bar">
        <div class="tab on"  data-tab="tail">📡 Live Tail</div>
        <div class="tab"     data-tab="stats">📈 Statistics</div>
      </div>

      <!-- ── Live Tail ── -->
      <div id="tabTail">
        <div class="tail-controls">
          <label>Lines:</label>
          <input type="number" id="tailLines" value="50" min="10" max="500" style="width:65px">
          <label>Refresh:</label>
          <select id="tailInterval">
            <option value="3000">3s</option>
            <option value="5000" selected>5s</option>
            <option value="10000">10s</option>
            <option value="30000">30s</option>
          </select>
          <label style="margin-left:6px">Filter:</label>
          <input type="text" id="tailFilter" placeholder="grep text…"
            style="background:var(--surface2);border:1px solid var(--border);border-radius:5px;
            color:var(--text);font-family:var(--mono);font-size:11px;padding:4px 8px;outline:none;width:160px">
          <button class="btn btn-ghost btn-sm" id="btnScrollBottom">↓ Bottom</button>
          <button class="btn btn-ghost btn-sm" id="btnClearTail">✕ Clear</button>
        </div>
        <div class="log-terminal" id="logTerminal">
          <div style="color:var(--muted);text-align:center;margin-top:80px">Select a log file to begin tailing</div>
        </div>
        <div class="tail-footer">
          <span id="tailStatus">—</span>
          <span id="tailLineCount">0 lines</span>
        </div>
      </div>

      <!-- ── Statistics ── -->
      <div id="tabStats" style="display:none">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap">
          <button class="btn btn-primary" id="btnRunStats">▶ Run Statistics</button>
          <span style="font-size:12px;color:var(--muted);font-family:var(--mono)" id="statsStatus">
            Click to analyse the selected log file</span>
        </div>
        <div id="statsContent">
          <div class="welcome" style="padding:30px">
            <div class="ico" style="font-size:36px">📊</div>
            <p>Click <strong>Run Statistics</strong> to analyse the access log.<br>
              This runs moni.sh sections: response codes, top IPs, top URLs, errors and more.</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</main>

<script>
// ── State ─────────────────────────────────────────────────────────────────── //
var allHosts    = [];
var allLogs     = [];
var hostSearch  = '';
var logSearch   = '';
var currentHost = '';
var currentLog  = '';
var currentLogSize = '';
var currentLogType = '';
var currentTab  = 'tail';
var tailTimer   = null;
var tailPaused  = false;
var tailSeenLines = [];
var autoScroll  = true;
var lastTailLines = [];

// ── DOM ───────────────────────────────────────────────────────────────────── //
var hostList     = document.getElementById('hostList');
var logList      = document.getElementById('logList');
var hostCount    = document.getElementById('hostCount');
var logCount     = document.getElementById('logCount');
var welcomePanel = document.getElementById('welcomePanel');
var mainContent  = document.getElementById('mainContent');
var alertBox     = document.getElementById('alertBox');
var logTerminal  = document.getElementById('logTerminal');
var tailStatus   = document.getElementById('tailStatus');
var tailLineCount= document.getElementById('tailLineCount');
var statsContent = document.getElementById('statsContent');
var statsStatus  = document.getElementById('statsStatus');
var liveBadge    = document.getElementById('liveBadge');
var stoppedBadge = document.getElementById('stoppedBadge');
var btnLoad      = document.getElementById('btnLoad');
var btnAutoRefresh=document.getElementById('btnAutoRefresh');

document.getElementById('tailFilter').addEventListener('input', function(){
    renderTail(lastTailLines);
});
// ── Load hosts ────────────────────────────────────────────────────────────── //
btnLoad.addEventListener('click', function() {
  btnLoad.disabled = true; btnLoad.textContent = '⏳ Loading…';
  hostList.innerHTML = '<div class="panel-empty"><span class="spin"></span> Fetching…</div>';
  fetch('?action=hosts').then(function(r){return r.json();}).then(function(data){
    btnLoad.disabled = false; btnLoad.textContent = '↺ Reload';
    allHosts = data.hosts || [];
    hostCount.textContent = allHosts.length + ' hosts';
    renderHosts();
  }).catch(function(e){
    btnLoad.disabled = false; btnLoad.textContent = '▶ Load Hosts';
    hostList.innerHTML = '<div class="panel-empty" style="color:var(--red)">⚠ '+esc(e.message)+'</div>';
  });
});

function renderHosts() {
  var term = hostSearch.toLowerCase();
  var filtered = allHosts.filter(function(h){ return !term || h.toLowerCase().includes(term); });
  if (!filtered.length) { hostList.innerHTML='<div class="panel-empty">No hosts match</div>'; return; }
  hostList.innerHTML = filtered.map(function(h){
    return '<div class="list-item'+(h===currentHost?' active':'')+'" data-host="'+esc(h)+'">'
          +'<span class="li-name">'+esc(h)+'</span><span class="li-arrow">›</span></div>';
  }).join('');
  hostList.querySelectorAll('.list-item').forEach(function(el){
    el.addEventListener('click', function(){ selectHost(el.getAttribute('data-host')); });
  });
}

// ── Select host → load logs ───────────────────────────────────────────────── //
function selectHost(host) {
  currentHost = host;
  currentLog  = '';
  stopTail();
  document.querySelectorAll('.list-item[data-host]').forEach(function(el){
    el.classList.toggle('active', el.getAttribute('data-host')===host);
  });
  logList.innerHTML = '<div class="panel-empty"><span class="spin"></span> Loading logs…</div>';
  logCount.textContent = '—';
  welcomePanel.style.display = 'block';
  mainContent.style.display  = 'none';

  fetch('?action=logs&host='+encodeURIComponent(host))
    .then(function(r){return r.json();})
    .then(function(data){
      allLogs = data.logs || [];
      logCount.textContent = allLogs.length + ' logs';
      if (data.error || !allLogs.length) {
        logList.innerHTML = '<div class="panel-empty" style="color:var(--muted)">⚠ '
          +esc(data.error || 'No logs found')+'</div>';
        return;
      }
      renderLogs();
    })
    .catch(function(e){
      logList.innerHTML = '<div class="panel-empty" style="color:var(--red)">⚠ '+esc(e.message)+'</div>';
    });
}

/*function renderLogs() {
  var term = logSearch.toLowerCase();
  var filtered = allLogs.filter(function(l){ return !term || l.name.toLowerCase().includes(term); });
  if (!filtered.length) { logList.innerHTML='<div class="panel-empty">No logs match</div>'; return; }
  logList.innerHTML = filtered.map(function(l){
    return '<div class="list-item'+(l.path===currentLog?' active':'')+'" data-path="'+esc(l.path)+'" data-name="'+esc(l.name)+'">'
          +'<span class="li-name" title="'+esc(l.path)+'">'+esc(l.name)+'</span><span class="li-arrow">›</span></div>';
  }).join('');
  logList.querySelectorAll('.list-item').forEach(function(el){
    el.addEventListener('click', function(){
      selectLog(el.getAttribute('data-path'), el.getAttribute('data-name'));
    });
  });
}
*/
function renderLogs() {

  var term = logSearch.toLowerCase();

  var filtered = allLogs.filter(function(l){
    return !term ||
           l.name.toLowerCase().includes(term);
  });

  if (!filtered.length) {
    logList.innerHTML =
      '<div class="panel-empty">No logs match</div>';
    return;
  }

  logList.innerHTML = filtered.map(function(l){

    var badgeColor =
      l.type === 'error'
       ? '#f85149'
       : '#3fb950';

    return '<div class="list-item'
         +(l.path===currentLog?' active':'')
         +'"'
         +' data-path="'+esc(l.path)+'"'
         +' data-name="'+esc(l.name)+'"'
         +' data-size="'+esc(l.size)+'"'
         +' data-type="'+esc(l.type)+'">'
         +'<div style="overflow:hidden">'
         +'<div class="li-name">'
         +esc(l.name)
         +'</div>'
         +'<div style="font-size:10px;color:var(--muted)">'
         +'<span style="color:'+badgeColor+'">'
         +esc(l.type.toUpperCase())
         +'</span>'
         +' • '
         +esc(l.size)
         +'</div>'
         +'</div>'
         +'<span class="li-arrow">›</span>'
         +'</div>';

  }).join('');

  logList.querySelectorAll('.list-item').forEach(function(el){

      el.addEventListener('click', function(){

          selectLog(
              el.getAttribute('data-path'),
              el.getAttribute('data-name'),
              el.getAttribute('data-size'),
              el.getAttribute('data-type')
          );

      });

  });

}
// ── Select log ────────────────────────────────────────────────────────────── //
//function selectLog(path, name) {
function selectLog(path, name, size, type) {
  currentLog      = path;
  currentLogSize  = size;
  currentLogType  = type;
  stopTail();
  tailSeenLines = [];
  document.querySelectorAll('.list-item[data-path]').forEach(function(el){
    el.classList.toggle('active', el.getAttribute('data-path')===path);
  });
  welcomePanel.style.display = 'none';
  mainContent.style.display  = 'block';
  alertBox.innerHTML = '';
  //logTerminal.innerHTML = '<div style="color:var(--muted);padding:10px">Loading '+esc(name)+'…</div>';
logTerminal.innerHTML =
  '<div style="color:var(--muted);padding:10px">'
  +'Loading '
  +esc(name)
  +' ('
  +esc(size)
  +')...'
  +'</div>';
  statsContent.innerHTML = '<div class="welcome" style="padding:30px"><div class="ico" style="font-size:36px">📊</div>'
    +'<p>Click <strong>Run Statistics</strong> to analyse this log.</p></div>';
  //statsStatus.textContent = 'Click to analyse: '+name;
  btnAutoRefresh.disabled = false;
  tailPaused = false;
  updateBadge();
  startTail();
var statsButton =
 document.getElementById('btnRunStats');

if(type === 'error') {

    statsButton.disabled = true;

    statsStatus.textContent =
       'Statistics available only for access logs';

} else {

    statsButton.disabled = false;

    statsStatus.textContent =
       'Click to analyse: ' + name;
}
}

// ── Tail ──────────────────────────────────────────────────────────────────── //
function startTail() {
  if (!currentHost || !currentLog) return;
  doTail();
  var ms = parseInt(document.getElementById('tailInterval').value) || 5000;
  tailTimer = setInterval(doTail, ms);
}

function stopTail() {
  if (tailTimer) { clearInterval(tailTimer); tailTimer = null; }
  liveBadge.style.display    = 'none';
  stoppedBadge.style.display = 'none';
  btnAutoRefresh.disabled    = true;
}
function renderTail(lines){

    var filter =
      document.getElementById('tailFilter')
              .value
              .trim()
              .toLowerCase();

    logTerminal.innerHTML = '';

    lines.forEach(function(line){

        if(filter &&
           line.toLowerCase().indexOf(filter) === -1)
            return;

        var div = document.createElement('div');
        div.className='log-line '+lineClass(line);
        div.textContent=line;

        logTerminal.appendChild(div);
    });

    tailLineCount.textContent =
      logTerminal.querySelectorAll('.log-line').length +
      ' lines';

    logTerminal.scrollTop =
      logTerminal.scrollHeight;
}

function doTail() {
  if (tailPaused || !currentLog) return;
  var n       = parseInt(document.getElementById('tailLines').value) || 50;
  var filter  = document.getElementById('tailFilter').value.trim();
  var url     = '?action=tail&host='+encodeURIComponent(currentHost)
              + '&name='+encodeURIComponent(currentLog.split('/').pop())
              + '&lines='+n;
  fetch(url).then(function(r){return r.json();}).then(function(data){
    if (data.error) { tailStatus.textContent = '⚠ '+data.error; return; }
    //var lines = data.lines || [];
    lastTailLines = data.lines || [];

    var lines = lastTailLines.slice();

    // Apply client-side filter
/*    if (filter) lines = lines.filter(function(l){ return l.toLowerCase().includes(filter.toLowerCase()); });

    // Find new lines (lines not seen in last poll)
    var newLines = lines.filter(function(l){ return tailSeenLines.indexOf(l) === -1; });
    tailSeenLines = lines.slice(); // update seen

    // Append new lines to terminal
    newLines.forEach(function(l){
      var div = document.createElement('div');
      div.className = 'log-line new ' + lineClass(l);
      div.textContent = l;
      logTerminal.appendChild(div);
    });

    // Remove old lines if terminal is getting too long (keep last 500)
    var allDivs = logTerminal.querySelectorAll('.log-line');
    if (allDivs.length > 600) {
      for (var i = 0; i < allDivs.length - 500; i++) allDivs[i].remove();
    }

    tailStatus.textContent = 'Last refresh: ' + new Date().toTimeString().slice(0,8);
    tailLineCount.textContent = logTerminal.querySelectorAll('.log-line').length + ' lines'; */
    renderTail(lines);
    liveBadge.style.display    = 'inline-flex';
    stoppedBadge.style.display = 'none';

    if (autoScroll) logTerminal.scrollTop = logTerminal.scrollHeight;
  }).catch(function(e){ tailStatus.textContent = '⚠ '+e.message; });
}

function lineClass(line) {
  var m = line.match(/" (\d{3}) /);
  if (!m) return '';
  var c = m[1][0];
  return c==='2'?'s2xx':c==='3'?'s3xx':c==='4'?'s4xx':c==='5'?'s5xx':'';
}

function updateBadge() {
  if (tailPaused) {
    liveBadge.style.display    = 'none';
    stoppedBadge.style.display = 'inline-flex';
    btnAutoRefresh.textContent = '▶ Resume';
  } else {
    liveBadge.style.display    = 'inline-flex';
    stoppedBadge.style.display = 'none';
    btnAutoRefresh.textContent = '⏸ Pause';
  }
}

btnAutoRefresh.addEventListener('click', function(){
  tailPaused = !tailPaused;
  updateBadge();
  if (!tailPaused) doTail();
});

document.getElementById('tailInterval').addEventListener('change', function(){
  if (tailTimer) { clearInterval(tailTimer); tailTimer = null; }
  if (!tailPaused && currentLog) {
    var ms = parseInt(this.value) || 5000;
    tailTimer = setInterval(doTail, ms);
  }
});

document.getElementById('btnScrollBottom').addEventListener('click', function(){
  logTerminal.scrollTop = logTerminal.scrollHeight;
});
document.getElementById('btnClearTail').addEventListener('click', function(){
  logTerminal.innerHTML = '';
  tailSeenLines = [];
  tailLineCount.textContent = '0 lines';
});

// Auto-scroll detection
logTerminal.addEventListener('scroll', function(){
  var atBottom = logTerminal.scrollTop + logTerminal.clientHeight >= logTerminal.scrollHeight - 40;
  autoScroll = atBottom;
});

// ── Statistics ────────────────────────────────────────────────────────────── //
document.getElementById('btnRunStats').addEventListener('click', function(){
  if (!currentHost || !currentLog) return;
  statsContent.innerHTML = '<div class="stats-running"><span class="spin"></span> Running moni.sh analysis on '
    +esc(currentLog.split('/').pop())+'…<br><span style="font-size:11px;color:var(--muted)">This may take 30–60 seconds for large logs</span></div>';
  statsStatus.textContent = 'Analysing…';
  fetch('?action=stats&host='+encodeURIComponent(currentHost)+'&name='+encodeURIComponent(currentLog.split('/').pop()))
    .then(function(r){return r.json();})
    .then(function(data){
      if (data.error) {
        statsContent.innerHTML = '<div class="alert-err">⚠ '+esc(data.error)+'</div>';
        statsStatus.textContent = 'Error';
        return;
      }
      var secs = data.sections || [];
      statsStatus.textContent = 'Done — '+secs.length+' sections · '+new Date().toTimeString().slice(0,8);
      if (!secs.length) {
        statsContent.innerHTML = '<div class="section-empty">No output — log may be empty or unreachable</div>';
        return;
      }
      statsContent.innerHTML = secs.map(function(sec, idx){
        var rows = renderSection(sec);
        return '<div class="section-card" id="sec'+idx+'">'
          +'<div class="section-card-head" onclick="toggleSec('+idx+')">'
          +'<h3>'+esc(sec.title)+'</h3>'
          +'<span class="toggle" id="tog'+idx+'">▲ collapse</span>'
          +'</div>'
          +'<div class="section-card-body" id="secbody'+idx+'">'+rows+'</div>'
          +'</div>';
      }).join('');
    })
    .catch(function(e){
      statsContent.innerHTML = '<div class="alert-err">⚠ Fetch error: '+esc(e.message)+'</div>';
      statsStatus.textContent = 'Error';
    });
});

function renderSection(sec) {
  if (!sec.lines || sec.lines.filter(function(l){return l.trim();}).length === 0) {
    return '<div class="section-empty">No data</div>';
  }
  return sec.lines.filter(function(l){return l.trim();}).map(function(line){
    // Try to parse count + value  (e.g. "  12345 GET /foo HTTP/1.1")
    var m = line.match(/^\s*(\d+)\s+(.+)$/);
    if (m) {
      var count = m[1];
      var val   = m[2].trim();
      // Detect HTTP status code
      var codeMatch = val.match(/^(\d{3})$/);
      var codeClass = '';
      if (codeMatch) {
        var c = codeMatch[1][0];
        codeClass = c==='2'?'s2':c==='3'?'s3':c==='4'?'s4':c==='5'?'s5':'';
        val = '<span class="scode '+codeClass+'">'+esc(codeMatch[1])+'</span>';
      } else {
        val = '<span title="'+esc(val)+'">'+esc(val)+'</span>';
      }
      return '<div class="section-line"><span class="scount">'+esc(count)+'</span>'
           + '<span class="sval">'+val+'</span></div>';
    }
    // Plain line (summary, first entry, etc.)
    return '<div class="section-line"><span class="sval" style="color:var(--muted)">'+esc(line)+'</span></div>';
  }).join('');
}

function toggleSec(idx) {
  var body = document.getElementById('secbody'+idx);
  var tog  = document.getElementById('tog'+idx);
  if (body.style.display === 'none') {
    body.style.display = ''; tog.textContent = '▲ collapse';
  } else {
    body.style.display = 'none'; tog.textContent = '▼ expand';
  }
}

// ── Tabs ──────────────────────────────────────────────────────────────────── //
document.querySelectorAll('.tab').forEach(function(t){
  t.addEventListener('click', function(){
    currentTab = t.getAttribute('data-tab');
    document.querySelectorAll('.tab').forEach(function(x){ x.classList.remove('on'); });
    t.classList.add('on');
    document.getElementById('tabTail').style.display  = currentTab==='tail'  ? '' : 'none';
    document.getElementById('tabStats').style.display = currentTab==='stats' ? '' : 'none';
  });
});

// ── Search filters ────────────────────────────────────────────────────────── //
document.getElementById('hostSearch').addEventListener('input', function(e){
  hostSearch = e.target.value.trim(); renderHosts();
});
document.getElementById('logSearch').addEventListener('input', function(e){
  logSearch = e.target.value.trim(); renderLogs();
});

// ── Helpers ───────────────────────────────────────────────────────────────── //
function esc(s){
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>
