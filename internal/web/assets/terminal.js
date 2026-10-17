// The service terminal: xterm.js on a WebSocket to a shell in the
// container. Keystrokes go as binary frames; a text frame {"cols","rows"}
// resizes the shell. The shell (bash or sh) is picked in the toolbar; a
// saved or suggested command is typed into the open shell and run, so its
// output stays in the same session.
(function () {
  var box = document.getElementById('terminal');
  if (!box || !window.Terminal || !window.FitAddon) return;
  var css = getComputedStyle(document.documentElement);
  var color = function (name, fallback) { return (css.getPropertyValue(name) || '').trim() || fallback; };
  var term = new window.Terminal({
    cursorBlink: true, fontSize: 13, scrollback: 5000,
    fontFamily: color('--p-mono', 'ui-monospace, Menlo, monospace'),
    theme: {
      background: color('--p-log-bg', '#08090b'), foreground: color('--p-log-fg', '#c9cdd3'),
      cursor: color('--p-accent', '#5b57f0'), selectionBackground: 'rgba(91, 87, 240, .35)'
    }
  });
  var fit = new window.FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(box);

  var status = document.getElementById('terminal-status');
  var again = document.getElementById('terminal-again');
  var clear = document.getElementById('terminal-clear');
  var enc = new TextEncoder();
  var ws = null;
  var pending = ''; // a command to type once the shell is up
  function say(text) { if (status) status.textContent = text; }
  function shell() {
    var r = document.querySelector('input[name="shell"]:checked');
    return r ? r.value : 'bash';
  }

  function connect() {
    if (ws) {
      var old = ws;
      ws = null;
      old.onclose = null;
      old.close();
    }
    term.reset();
    var sh = shell();
    say(box.dataset.connecting);
    var url = new URL(box.dataset.ws, location.href);
    url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    url.searchParams.set('cols', term.cols);
    url.searchParams.set('rows', term.rows);
    url.searchParams.set('shell', sh);
    var sock = new WebSocket(url);
    ws = sock;
    sock.binaryType = 'arraybuffer';
    sock.onopen = function () {
      say(box.dataset.connected);
      term.focus();
      if (pending) { sock.send(enc.encode(pending + '\r')); pending = ''; }
    };
    sock.onmessage = function (e) {
      term.write(typeof e.data === 'string' ? e.data : new Uint8Array(e.data));
    };
    sock.onclose = function (e) {
      if (ws !== sock) return;
      say(e.reason || box.dataset.closed);
      term.write('\r\n\x1b[2m' + (e.reason || box.dataset.closed) + '\x1b[0m\r\n');
    };
  }
  term.onData(function (d) {
    if (ws && ws.readyState === 1) ws.send(enc.encode(d));
  });
  term.onResize(function (s) {
    if (ws && ws.readyState === 1) ws.send(JSON.stringify({ cols: s.cols, rows: s.rows }));
  });
  // Measure again whenever the box changes size (the shell is told through
  // onResize), and connect once it has its real width.
  var started = false;
  new ResizeObserver(function () {
    if (box.clientWidth < 50) return;
    fit.fit();
    if (!started) { started = true; connect(); }
  }).observe(box);

  if (again) again.addEventListener('click', connect);
  if (clear) clear.addEventListener('click', function () { term.clear(); term.focus(); });
  // bash and sh switch at once.
  document.addEventListener('change', function (e) {
    if (e.target.matches && e.target.matches('input[name="shell"]')) connect();
  });
  // A saved or suggested command is typed into the open shell and run.
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-run-command]');
    if (!b) return;
    var cmd = b.dataset.runCommand;
    if (ws && ws.readyState === 1) {
      ws.send(enc.encode(cmd + '\r'));
      term.focus();
    } else {
      pending = cmd;
      connect();
    }
  });
  // "Save" fills the dialog with the suggestion it came from (or clears it).
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-save-command]');
    if (!b) return;
    var name = document.getElementById('cmd-name'), cmd = document.getElementById('cmd-command');
    if (name) name.value = b.dataset.saveName || '';
    if (cmd) cmd.value = b.dataset.saveCommand || '';
  });
})();
