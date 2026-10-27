// The ".env" modal of a service: the variables shown as a .env file the
// operator can edit, paste over or copy out, and where the connector writes
// its references. An admin's editor holds every value and saving replaces
// the variables (a line taken out is deleted). For other roles a secret's
// value never reaches the page: it is a commented line (# KEY=••••),
// skipped on save, and saving only adds and updates.
(function () {
  "use strict";

  function initialText(form) {
    var src = form.querySelector("[data-envfile]");
    if (!src) return "";
    var lines = [];
    var spans = src.querySelectorAll("span[data-k]");
    for (var i = 0; i < spans.length; i++) {
      var s = spans[i];
      var k = s.getAttribute("data-k");
      if (s.getAttribute("data-secret") === "1") {
        lines.push("# " + k + "=••••");
      } else {
        lines.push(k + "=" + (s.textContent || ""));
      }
    }
    return lines.length ? lines.join("\n") + "\n" : "";
  }

  // The Variables tab can be swapped in without a page load (switching tabs
  // in the drawer), and this script runs only once, so everything is wired
  // by delegation and the editor is filled when its modal opens.
  function fill(form) {
    var ta = form.querySelector("[data-envimport-src]");
    // Fill once, without clobbering anything the operator already typed.
    if (ta && !ta.value.trim()) ta.value = initialText(form);
  }

  // appendSuggested adds the repository's suggested variables (the
  // "Suggested variables" card) to the end of the editor, under a comment
  // naming the file. A key already in the editor, even commented out, is
  // left alone, so clicking "Add" twice does not repeat lines.
  function appendSuggested(form) {
    var ta = form.querySelector("[data-envimport-src]");
    var src = form.querySelector("[data-envsuggest]");
    if (!ta || !src) return;
    var present = {};
    var have = ta.value.split("\n");
    for (var i = 0; i < have.length; i++) {
      var m = /^\s*#?\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(have[i]);
      if (m) present[m[1]] = true;
    }
    var lines = [];
    var spans = src.querySelectorAll("span[data-k]");
    for (var j = 0; j < spans.length; j++) {
      var k = spans[j].getAttribute("data-k");
      if (present[k]) continue;
      lines.push(k + "=" + (spans[j].textContent || ""));
    }
    if (!lines.length) return;
    var text = ta.value;
    if (text && !/\n$/.test(text)) text += "\n";
    if (text) text += "\n";
    ta.value = text + "# " + (src.getAttribute("data-comment") || "") + "\n" + lines.join("\n") + "\n";
  }

  // appendBlock adds the connector's lines for one service (a comment, then
  // KEY=${{service.VALUE}} references) to the end of the editor. A name
  // already in the editor is left alone: the operator renames or removes
  // lines there before saving.
  function appendBlock(form, block) {
    var ta = form.querySelector("[data-envimport-src]");
    if (!ta) return;
    var present = {};
    var have = ta.value.split("\n");
    for (var i = 0; i < have.length; i++) {
      var m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(have[i]);
      if (m) present[m[1]] = true;
    }
    var lines = block.split("\n").filter(function (l) {
      var m = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(l);
      return l && (!m || !present[m[1]]);
    });
    if (lines.length < 2) return;
    var text = ta.value;
    if (text && !/\n$/.test(text)) text += "\n";
    if (text) text += "\n";
    ta.value = text + lines.join("\n") + "\n";
    ta.focus();
    ta.setSelectionRange(ta.value.length, ta.value.length);
    ta.scrollTop = ta.scrollHeight;
  }

  function openModal(dlg) {
    if (dlg._tucano && dlg._tucano.open) dlg._tucano.open(); else if (!dlg.open) dlg.showModal();
  }
  function closeModal(dlg) {
    if (dlg._tucano && dlg._tucano.close) dlg._tucano.close(); else if (dlg.open) dlg.close();
  }

  // A service picked in the connector: its lines go into the .env editor,
  // which opens in its place.
  document.addEventListener("click", function (e) {
    var b = e.target.closest && e.target.closest("[data-env-block]");
    if (!b) return;
    var editor = document.getElementById("env-bulk");
    var form = editor && editor.querySelector("form[data-envimport]");
    if (!form) return;
    fill(form);
    appendBlock(form, b.getAttribute("data-env-block"));
    var picker = b.closest("dialog");
    if (picker) closeModal(picker);
    openModal(editor);
  });

  function copy(btn) {
    var form = btn.closest("form[data-envimport]");
    var ta = form && form.querySelector("[data-envimport-src]");
    if (!ta) return;
    var label = btn.querySelector("[data-env-copy-label]");
    function done() {
      if (!label) return;
      var msg = btn.getAttribute("data-copied");
      if (!msg) return;
      var old = label.textContent;
      label.textContent = msg;
      setTimeout(function () { label.textContent = old; }, 1500);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(ta.value).then(done, function () {});
    } else {
      ta.select();
      try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
    }
  }

  // Capture phase: the editor is filled before the modal script shows it.
  document.addEventListener("click", function (e) {
    var t = e.target.closest && e.target.closest("[data-env-copy], [data-tuc-modal]");
    if (!t) return;
    if (t.hasAttribute("data-env-copy")) { copy(t); return; }
    var dlg = null;
    try { dlg = document.querySelector(t.getAttribute("data-tuc-modal")); } catch (err) { return; }
    var form = dlg && dlg.querySelector("form[data-envimport]");
    if (!form) return;
    fill(form);
    if (t.hasAttribute("data-env-suggest")) appendSuggested(form);
  }, true);

  function boot() {
    var forms = document.querySelectorAll("form[data-envimport]");
    for (var i = 0; i < forms.length; i++) fill(forms[i]);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
