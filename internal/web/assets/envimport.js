// The ".env" modal of a service: the file as its operator wrote it
// (comments, sections, order), to edit, paste over or copy out, and where
// the connector writes its references. Saving replaces the variables: a
// line taken out is deleted. Below admin a secret shows as KEY=••••, which
// saving keeps as it is.
(function () {
  "use strict";

  // The Variables tab can be swapped in without a page load (switching tabs
  // in the drawer), and this script runs only once, so everything is wired
  // by delegation.

  // --- the editor -----------------------------------------------------------
  //
  // The textarea stays the real editor (caret, selection, undo/redo, paste,
  // IME, mobile keyboards); it draws its text transparent over a <pre> with
  // the same text in colors, and a gutter numbers the lines. Lines never
  // wrap, so a number always sits beside its line; the <pre> and the
  // gutter follow the textarea's scroll. The text can hold secrets: it is
  // only ever written into this page, never logged or sent anywhere else.

  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // A Hangar reference (${{service.VAR}}, ${{project.service.VAR}}), then a
  // plain interpolation (${VAR}, ${VAR:-default}, $VAR).
  var interpRE = /\$\{\{[^{}\n]*\}\}|\$\{[A-Za-z_][A-Za-z0-9_]*(?:[:?+-][^}\n]*)?\}|\$[A-Za-z_][A-Za-z0-9_]*/g;
  var keyRE = /^[A-Za-z_][A-Za-z0-9_.-]*$/;

  function valueHTML(v) {
    var out = "";
    var last = 0;
    interpRE.lastIndex = 0;
    var m;
    while ((m = interpRE.exec(v))) {
      out += esc(v.slice(last, m.index));
      out += '<span class="' + (m[0].charAt(1) === "{" && m[0].charAt(2) === "{" ? "env-ref" : "env-var") + '">' + esc(m[0]) + "</span>";
      last = m.index + m[0].length;
    }
    return out + esc(v.slice(last));
  }

  // lineHTML colors one line; bad reports a line that is neither blank, a
  // comment nor KEY=value (marked, never blocking the save).
  function lineHTML(l, st) {
    if (!/\S/.test(l)) return esc(l);
    var c = /^(\s*)(#.*)$/.exec(l);
    if (c) return esc(c[1]) + '<span class="env-c">' + esc(c[2]) + "</span>";
    var i = l.indexOf("=");
    if (i < 0) {
      st.bad++;
      return '<span class="env-bad">' + esc(l) + "</span>";
    }
    var key = l.slice(0, i);
    var k = /^(\s*)(export\s+)?(.*?)(\s*)$/.exec(key);
    var cls = keyRE.test(k[3]) ? "env-k" : "env-k env-bad";
    return esc(k[1] + (k[2] || "")) + '<span class="' + cls + '">' + esc(k[3] || " ") + "</span>" +
      esc(k[4]) + "=" + valueHTML(l.slice(i + 1));
  }

  function parts(ed) {
    if (!ed._env) {
      ed._env = {
        ta: ed.querySelector("[data-envimport-src]"),
        hl: ed.querySelector("[data-env-hl]"),
        pre: ed.querySelector(".env-editor__hl"),
        nums: ed.querySelector("[data-env-gutter]"),
        status: ed.parentNode.querySelector("[data-env-status]"),
        lines: -1
      };
    }
    return ed._env;
  }

  function sync(ed) {
    var p = parts(ed);
    if (!p.ta) return;
    var x = p.ta.scrollLeft, y = p.ta.scrollTop;
    p.pre.style.transform = "translate(" + -x + "px," + -y + "px)";
    p.nums.style.transform = "translateY(" + -y + "px)";
  }

  function position(ed) {
    var p = parts(ed);
    if (!p.status || !p.ta) return;
    var pos = p.status.querySelector("[data-env-pos]");
    if (!pos) return;
    var at = p.ta.selectionStart || 0;
    var before = p.ta.value.slice(0, at);
    var line = before.split("\n").length;
    var col = at - before.lastIndexOf("\n");
    pos.textContent = (p.status.getAttribute("data-pos") || "")
      .replace("{line}", line).replace("{col}", col);
  }

  function render(ed) {
    var p = parts(ed);
    if (!p.ta || !p.hl || !p.nums) return;
    var lines = p.ta.value.split("\n");
    var st = { bad: 0 };
    var out = new Array(lines.length);
    for (var i = 0; i < lines.length; i++) out[i] = lineHTML(lines[i], st);
    // The trailing newline keeps a last empty line as tall as the
    // textarea's.
    p.hl.innerHTML = out.join("\n") + "\n";
    if (p.lines !== lines.length) {
      var n = new Array(lines.length);
      for (var j = 0; j < lines.length; j++) n[j] = j + 1;
      p.nums.textContent = n.join("\n");
      p.lines = lines.length;
    }
    if (p.status) {
      var bad = p.status.querySelector("[data-env-invalid]");
      if (bad) {
        bad.hidden = st.bad === 0;
        bad.textContent = st.bad === 1 ? p.status.getAttribute("data-invalid-one") || ""
          : (p.status.getAttribute("data-invalid-other") || "").replace("{n}", st.bad);
      }
    }
    ed.classList.add("is-live");
    sync(ed);
    position(ed);
  }

  function renderIn(root) {
    if (!root || !root.querySelectorAll) return;
    var eds = root.querySelectorAll("[data-env-editor]");
    for (var i = 0; i < eds.length; i++) render(eds[i]);
  }

  function editorOf(t) {
    return t && t.matches && t.matches("[data-envimport-src]") ? t.closest("[data-env-editor]") : null;
  }

  // Delegated: the Variables tab can be swapped in after this script ran.
  document.addEventListener("input", function (e) {
    var ed = editorOf(e.target);
    if (ed) render(ed);
  });
  // scroll does not bubble: listen in the capture phase.
  document.addEventListener("scroll", function (e) {
    var ed = editorOf(e.target);
    if (ed) sync(ed);
  }, true);
  ["keyup", "mouseup", "focusin"].forEach(function (type) {
    document.addEventListener(type, function (e) {
      var ed = editorOf(e.target);
      if (ed) position(ed);
    });
  });
  // Draw the editor when its modal opens, however it opens (a button, a
  // link straight to it, the connector).
  new MutationObserver(function (list) {
    for (var i = 0; i < list.length; i++) {
      var t = list[i].target;
      if (t.open && t.querySelector) renderIn(t);
    }
  }).observe(document.documentElement, { attributes: true, attributeFilter: ["open"], subtree: true });
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { renderIn(document); });
  } else {
    renderIn(document);
  }

  function refresh(form) {
    var ed = form.querySelector("[data-env-editor]");
    if (ed) render(ed);
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
    refresh(form);
  }

  // appendBlock puts the connector's lines (a "# service" comment, then
  // KEY=${{service.VALUE}} references) into the editor. A variable already
  // in the file is changed where it is: same line, same place, comments
  // around it untouched. Only the new ones go to the end, under the
  // comment. Returns how many lines changed.
  function appendBlock(form, block) {
    var ta = form.querySelector("[data-envimport-src]");
    if (!ta) return 0;
    var lines = ta.value.split("\n");
    var at = {};
    for (var i = 0; i < lines.length; i++) {
      var m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(lines[i]);
      if (m && !(m[1] in at)) at[m[1]] = i;
    }
    var head = "";
    var added = [];
    var changed = 0;
    block.split("\n").forEach(function (l) {
      if (!l) return;
      var m = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(l);
      if (!m) { head = l; return; }
      if (m[1] in at) {
        if (lines[at[m[1]]] !== l) { lines[at[m[1]]] = l; changed++; }
      } else {
        added.push(l);
      }
    });
    var text = lines.join("\n");
    if (added.length) {
      text = text.replace(/\n*$/, "");
      if (text) text += "\n\n";
      text += (head ? head + "\n" : "") + added.join("\n");
    }
    if (text && !/\n$/.test(text)) text += "\n";
    ta.value = text;
    refresh(form);
    ta.focus();
    return changed + added.length;
  }

  function openModal(dlg) {
    if (dlg._tucano && dlg._tucano.open) dlg._tucano.open(); else if (!dlg.open) dlg.showModal();
  }
  function closeModal(dlg) {
    if (dlg._tucano && dlg._tucano.close) dlg._tucano.close(); else if (dlg.open) dlg.close();
  }

  // The connector: the service's modal crosses its values with the app's
  // variables; "Add to .env" writes the filled rows into the editor as
  // references and opens it (closing the connector), to check and save.
  document.addEventListener("click", function (e) {
    var t = e.target.closest && e.target.closest("[data-connector-suggest], [data-connector-add]");
    if (!t) return;
    var panel = t.closest("[data-connector-panel]");
    if (!panel) return;
    var inputs = panel.querySelectorAll("input[data-key]");
    if (t.hasAttribute("data-connector-suggest")) {
      inputs.forEach(function (i) { if (!i.value.trim()) i.value = i.placeholder; });
      return;
    }
    var service = panel.getAttribute("data-service");
    var lines = ["# " + service];
    for (var i = 0; i < inputs.length; i++) {
      var name = inputs[i].value.trim();
      if (!name) continue;
      if (!inputs[i].checkValidity()) { inputs[i].reportValidity(); return; }
      lines.push(name + "=${{" + service + "." + inputs[i].getAttribute("data-key") + "}}");
    }
    if (lines.length < 2) { inputs[0].focus(); return; }
    var editor = document.getElementById("env-bulk");
    var form = editor && editor.querySelector("form[data-envimport]");
    if (!form) return;
    appendBlock(form, lines.join("\n"));
    closeModal(panel);
    var picker = document.getElementById("connector");
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
    // Untouched editor: the file with references resolved, so it works
    // pasted outside Hangar. Edited: exactly what is in the editor.
    var resolved = form.querySelector("template[data-env-resolved]");
    var text = resolved && ta.value === ta.defaultValue ? resolved.content.textContent : ta.value;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {});
    } else {
      ta.select();
      try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
    }
  }

  // Capture phase: the suggested lines are in before the modal shows.
  document.addEventListener("click", function (e) {
    var t = e.target.closest && e.target.closest("[data-env-copy], [data-tuc-modal]");
    if (!t) return;
    if (t.hasAttribute("data-env-copy")) { copy(t); return; }
    var dlg = null;
    try { dlg = document.querySelector(t.getAttribute("data-tuc-modal")); } catch (err) { return; }
    var form = dlg && dlg.querySelector("form[data-envimport]");
    if (!form) return;
    if (t.hasAttribute("data-env-suggest")) appendSuggested(form);
  }, true);
})();
