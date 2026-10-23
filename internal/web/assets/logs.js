// Live logs (SSE). Text always goes in through textContent: logs are untrusted
// input and never become HTML (docs/17, hole 5).
// HangarLogs.start() hooks the log box on the page (also after the service
// drawer swaps its content); stop() closes the stream.
(function () {
  "use strict";
  var current = null;
  function stop() {
    if (current) { current.close(); current = null; }
  }
  function start() {
  stop();
  var box = document.getElementById("logs");
  if (!box || !window.EventSource) return;
  var status = document.getElementById("log-status");
  var dot = document.getElementById("log-dot");
  var pauseBtn = document.getElementById("log-pause");
  var MAX = 2000;
  var text = {
    live: box.getAttribute("data-live"),
    reconnecting: box.getAttribute("data-reconnecting"),
    ended: box.getAttribute("data-ended"),
    pause: box.getAttribute("data-pause"),
    resume: box.getAttribute("data-resume")
  };
  var paused = false;
  var queue = [];

  // Only the colour changes: the dot keeps its size and shape classes from
  // the template (replacing className used to leave it with no size at all).
  var dotColors = ["bg-success", "bg-warning", "bg-border"];
  function setStatus(text, cls) {
    status.textContent = text;
    dot.classList.remove.apply(dot.classList, dotColors);
    dot.classList.add(cls);
  }

  // The colour follows the level written in the line, not the stream: many
  // programs (nginx, Python's logging) write every line to stderr, so
  // painting all of stderr red hid the real errors among notices.
  var errRE = /\b(error|err|fatal|panic|crit(ical)?|emerg(ency)?|alert|exception|traceback)\b|\blevel=(error|fatal)/i;
  var warnRE = /\b(warn(ing)?)\b|\blevel=warn/i;

  function levelClass(m) {
    if (errRE.test(m)) return " log-err";
    if (warnRE.test(m)) return " log-warn";
    return "";
  }

  function append(d) {
    var line = document.createElement("div");
    line.className = "log-line" + levelClass(d.m || "");
    if (d.t) {
      var t = document.createElement("span");
      t.className = "log-time";
      t.textContent = d.t;
      line.appendChild(t);
    }
    line.appendChild(document.createTextNode(d.m));
    place(line, d.n);
  }

  // place keeps lines and marks in time order (n = unix nanoseconds): an
  // element goes after the last one that is not newer than it.
  function place(el, n) {
    var stick = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    if (n) el.dataset.n = n;
    var ref = null;
    if (n) {
      var cur = box.lastChild;
      while (cur && cur.dataset && +cur.dataset.n > n) { ref = cur; cur = cur.previousSibling; }
    }
    box.insertBefore(el, ref);
    while (box.childNodes.length > MAX) box.removeChild(box.firstChild);
    if (stick) box.scrollTop = box.scrollHeight;
  }

  // A mark is a separator with its time and author. The side rules are real
  // dash characters (not a CSS border), so selecting the line copies them
  // too: "──── marcação · time · author ────".
  // A long run so the rules fill any width (flex:1 + overflow:hidden clips
  // the excess); still real text, so copying a mark brings the dashes too.
  var markRule = "─".repeat(120);
  function mark(d) {
    var el = document.createElement("div");
    el.className = "log-mark";
    var left = document.createElement("span");
    left.className = "log-mark-rule";
    left.textContent = markRule;
    var label = document.createElement("span");
    label.className = "log-mark-label";
    label.textContent = (box.getAttribute("data-mark-label") || "") + " · " + d.t + " · " + d.by;
    var right = document.createElement("span");
    right.className = "log-mark-rule";
    right.textContent = markRule;
    el.appendChild(left);
    el.appendChild(label);
    el.appendChild(right);
    place(el, d.n);
  }

  var src = new EventSource(box.getAttribute("data-src"));
  current = src;
  src.onopen = function () { setStatus(text.live, "bg-success"); };
  src.onerror = function () { setStatus(text.reconnecting, "bg-warning"); };
  src.onmessage = function (e) {
    var d;
    try { d = JSON.parse(e.data); } catch (_) { return; }
    if (paused) { queue.push(d); if (queue.length > MAX) queue.shift(); return; }
    append(d);
  };
  src.addEventListener("mark", function (e) {
    try { mark(JSON.parse(e.data)); } catch (_) {}
  });
  var markBtn = document.getElementById("log-mark");
  if (markBtn) {
    markBtn.addEventListener("click", function () {
      markBtn.disabled = true;
      fetch(markBtn.dataset.url, { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": markBtn.dataset.csrf } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { if (d) mark(d); })
        .finally(function () { markBtn.disabled = false; });
    });
  }
  src.addEventListener("end", function (e) {
    setStatus(text.ended, "bg-border");
    src.close();
  });
  pauseBtn.addEventListener("click", function () {
    paused = !paused;
    pauseBtn.querySelector("[data-label]").textContent = paused ? text.resume : text.pause;
    pauseBtn.querySelector("[data-icon-pause]").classList.toggle("hidden", paused);
    pauseBtn.querySelector("[data-icon-play]").classList.toggle("hidden", !paused);
    if (!paused) { queue.forEach(append); queue = []; }
  });
  }
  window.HangarLogs = { start: start, stop: stop };
  start();
})();
