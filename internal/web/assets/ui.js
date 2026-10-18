// Small behaviours the CSP keeps out of the HTML: copy buttons
// (data-copy, with the "copied" text in data-copied, shown as a Tucano toast)
// and controls that submit their form when changed (data-autosubmit).
(function () {
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-copy]');
    if (!b) return;
    navigator.clipboard.writeText(b.dataset.copy).then(function () {
      if (window.Tucano && b.dataset.copied) {
        window.Tucano.toast({ type: 'success', text: b.dataset.copied, position: 'bottom-center' });
      }
    });
  });
  // A dialog marked data-open (a form came back with an error) opens by
  // itself: through Tucano's own instance, which is what its triggers call
  // (a trigger may sit in a closed dropdown), else through the trigger.
  window.addEventListener('load', function () {
    document.querySelectorAll('dialog.tuc-modal[data-open="true"], dialog.tuc-drawer[data-open="true"]').forEach(function (d) {
      if (d._tucano && typeof d._tucano.open === 'function') {
        d._tucano.open();
        return;
      }
      var tr = document.querySelector('[data-tuc-modal="#' + d.id + '"], [data-tuc-drawer="#' + d.id + '"]');
      if (tr) tr.click();
    });
    // What the form came back to show (a preview below the button that
    // asked for it) is scrolled into view, else the dialog seems unchanged.
    requestAnimationFrame(function () {
      var shown = document.querySelector('dialog[open] [data-reveal]');
      if (shown) shown.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
  // Forms that destroy or change something important ask first, in a
  // Tucano dialog whose color says what kind of action it is (data-tone:
  // danger red, warning yellow, success green; default purple).
  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (!f.matches || !f.matches('form[data-confirm]') || f.dataset.confirmed === '1' || !window.Tucano) return;
    e.preventDefault();
    var submitter = e.submitter;
    window.Tucano.confirm({
      title: f.dataset.confirm, text: f.dataset.confirmText || '',
      tone: f.dataset.tone || 'default', confirm: f.dataset.confirmOk || undefined
    }).then(function (ok) {
      if (!ok) {
        // A switch that submits on change goes back to where it was.
        f.querySelectorAll('input[type=checkbox][data-autosubmit]').forEach(function (c) { c.checked = c.defaultChecked; });
        return;
      }
      f.dataset.confirmed = '1';
      // A form inside a dropdown is out of the document once the dropdown
      // closed (Tucano keeps closed panels detached): put it back, hidden,
      // or the browser silently refuses to submit it.
      if (!f.isConnected) {
        f.hidden = true;
        document.body.appendChild(f);
      }
      f.requestSubmit(submitter && submitter.form === f ? submitter : undefined);
    });
  }, true);
  // Tucano paints the color picker's swatches with a style attribute, which
  // the panel's CSP blocks: paint them through the CSSOM (allowed) as they
  // appear.
  function paintSwatches(root) {
    (root.querySelectorAll ? root : document).querySelectorAll('.tuc-colorpicker__swatchbtn[title]').forEach(function (b) {
      b.style.setProperty('--color', b.title);
    });
  }
  new MutationObserver(function (list) {
    list.forEach(function (m) {
      m.addedNodes.forEach(function (n) { if (n.nodeType === 1) paintSwatches(n); });
    });
  }).observe(document.documentElement, { childList: true, subtree: true });
  paintSwatches(document);
  // Expand a block (logs, terminal) to the whole screen and back. The
  // block moves into a modal dialog of its own (the top layer: nothing
  // underneath can clip it) and back to its place on close; moving keeps
  // its live connection.
  function setExpanded(block, on) {
    if (on === block.classList.contains('is-expanded')) return;
    block.classList.toggle('is-expanded', on);
    block.querySelectorAll('[data-expand]').forEach(function (b) { b.setAttribute('aria-pressed', on ? 'true' : 'false'); });
    if (on) {
      var mark = document.createComment('expanded');
      block.before(mark);
      var dlg = document.createElement('dialog');
      dlg.className = 'expand-dialog';
      dlg.addEventListener('cancel', function (e) { e.preventDefault(); setExpanded(block, false); });
      dlg.append(block);
      document.body.append(dlg);
      dlg.showModal();
      block._expand = { mark: mark, dlg: dlg };
    } else if (block._expand) {
      block._expand.mark.replaceWith(block);
      block._expand.dlg.close();
      block._expand.dlg.remove();
      block._expand = null;
    }
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-expand]');
    if (!b) return;
    var block = b.closest('[data-expandable]');
    if (block) setExpanded(block, !block.classList.contains('is-expanded'));
  });
  // Masks: data-allow="port" keeps digits only, up to 65535; data-allow="ips"
  // keeps what an IPv4/IPv6 address or network list can hold. The server
  // checks everything again.
  var allowed = { port: /[^0-9]/g, ips: /[^0-9a-fA-F.:/,\s]/g };
  document.addEventListener('input', function (e) {
    var el = e.target, kind = el.dataset && el.dataset.allow;
    if (!kind || !allowed[kind]) return;
    var v = el.value.replace(allowed[kind], '');
    if (kind === 'port') {
      v = v.replace(/^0+/, '').slice(0, 5);
      if (v && +v > 65535) v = '65535';
    }
    if (kind === 'ips') {
      // Any run of separators (comma, space, newline from a paste) becomes a
      // single ", ", so the list is always comma-separated; no leading one.
      v = v.replace(/[,\s]+/g, ', ').replace(/^,\s*/, '');
    }
    if (v !== el.value) el.value = v;
  });
  // A block marked data-shown-when="<key>=<value>" shows only while the
  // control named by key has that value (or one of "a|b"): a select (its id), a checkbox
  // (its id; "1" checked, "0" not) or a radio group (its name, looked up in
  // the block's own form first). Its fields are disabled while hidden, so
  // the browser neither requires nor sends them.
  function valueOf(key, scope) {
    var el = document.getElementById(key);
    if (el && el.tagName === 'SELECT') return el.value;
    if (el && el.type === 'checkbox') return el.checked ? '1' : '0';
    var sel = 'input[type="radio"][name="' + key + '"]:checked';
    var r = (scope && scope.querySelector(sel)) || document.querySelector(sel);
    return r ? r.value : null;
  }
  function syncShown() {
    document.querySelectorAll('[data-shown-when]').forEach(function (el) {
      var cond = el.dataset.shownWhen.split('=');
      var on = cond[1].split('|').indexOf(valueOf(cond[0], el.closest('form'))) >= 0;
      el.hidden = !on;
      if (el.matches('input, select, textarea')) el.disabled = !on;
      el.querySelectorAll('input, select, textarea').forEach(function (f) { f.disabled = !on; });
    });
  }
  document.addEventListener('change', function (e) {
    if (e.target.matches && e.target.matches('select, input[type="radio"], input[type="checkbox"]')) syncShown();
  });
  // Tucano selects fire tucano:change instead of a native change, so a
  // data-shown-when driven by a Tucano select (e.g. the credential picker)
  // still toggles.
  document.addEventListener('tucano:change', syncShown);
  syncShown();
  // The add-domain form previews what will be stored: "*." in front in the
  // wildcard and scale modes. Typing "*." picks the wildcard mode instead,
  // so the field always holds a plain hostname.
  function domainPreview() {
    document.querySelectorAll('[data-domain-preview]').forEach(function (out) {
      var f = out.closest('form');
      var host = f && f.querySelector('[name="hostname"]');
      if (!host) return;
      var mode = f.querySelector('[name="mode"]:checked');
      if (/^\s*\*\./.test(host.value)) {
        host.value = host.value.replace(/^\s*\*\./, '');
        var wild = f.querySelector('[name="mode"][value="wildcard"]');
        if (wild && (!mode || mode.value === 'normal')) {
          wild.checked = true;
          mode = wild;
          syncShown();
        }
      }
      var h = host.value.trim().toLowerCase().replace(/\.$/, '');
      var star = mode && mode.value !== 'normal';
      out.textContent = h ? (star ? '*.' : '') + h : out.dataset.empty;
    });
  }
  document.addEventListener('input', domainPreview);
  document.addEventListener('change', domainPreview);
  // A frame marked data-src inside a dialog loads only while the dialog is
  // open and is emptied when it closes: the terminal modal opens its shell
  // only when asked, and closing it ends the session.
  // One observer on the whole document: dialogs that arrive later (the
  // service drawer swapped in from the canvas) work too.
  function syncFrames(dlg) {
    dlg.querySelectorAll('iframe[data-src]').forEach(function (fr) {
      var src = fr.getAttribute('src');
      if (dlg.open && src !== fr.dataset.src) fr.setAttribute('src', fr.dataset.src);
      if (!dlg.open && src && src !== 'about:blank') fr.setAttribute('src', 'about:blank');
    });
  }
  new MutationObserver(function (list) {
    list.forEach(function (m) {
      if (m.target.tagName === 'DIALOG') syncFrames(m.target);
    });
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['open'], subtree: true });
  document.querySelectorAll('dialog').forEach(syncFrames);
  // Demo buttons of the /_pista catalog: they open a confirm dialog of the
  // given tone (data-demo-confirm) or a toast (data-demo-toast) and do
  // nothing else.
  document.addEventListener('click', function (e) {
    if (!window.Tucano) return;
    var c = e.target.closest('[data-demo-confirm]');
    if (c) {
      window.Tucano.confirm({
        title: c.dataset.demoConfirm, text: c.dataset.confirmText || '',
        tone: c.dataset.tone || 'default', confirm: c.dataset.confirmOk || undefined
      });
      return;
    }
    var t = e.target.closest('[data-demo-toast]');
    if (t) window.Tucano.toast({ type: t.dataset.type || 'info', text: t.dataset.demoToast, position: 'bottom-center' });
  });
  // Cmd/Ctrl+Shift+L is the panic button: it submits the lock form, which
  // still asks for confirmation first (only the owner has the form).
  document.addEventListener('keydown', function (e) {
    if (!(e.metaKey || e.ctrlKey) || !e.shiftKey || (e.key !== 'L' && e.key !== 'l')) return;
    var f = document.getElementById('lock-form');
    if (!f) return;
    e.preventDefault();
    f.requestSubmit();
  });
  // Forms that send a moment (the restore) also send the browser's time
  // zone, so "14:32" means 14:32 where the person is.
  document.querySelectorAll('[data-tz-offset]').forEach(function (i) {
    i.value = String(new Date().getTimezoneOffset());
  });
  function autosubmit(e) {
    var el = e.target;
    if (!el.matches || !el.matches('[data-autosubmit]') || !el.form) return;
    var form = el.form;
    var sel = form.getAttribute('data-ajax-swap');
    if (!sel || !document.querySelector(sel)) { form.requestSubmit(); return; }
    // Update just the target region instead of reloading the whole page: fetch
    // the same GET URL, pull the region out of the response and swap it in. On
    // any failure, fall back to a full navigation so the change still happens.
    var action = form.getAttribute('action') || location.pathname;
    var url = action + (action.indexOf('?') < 0 ? '?' : '&') + new URLSearchParams(new FormData(form)).toString();
    fetch(url, { headers: { Accept: 'text/html' } })
      .then(function (r) { if (!r.ok) throw 0; return r.text(); })
      .then(function (html) {
        var next = new DOMParser().parseFromString(html, 'text/html').querySelector(sel);
        var cur = document.querySelector(sel);
        if (!next || !cur) throw 0;
        cur.replaceWith(next);
        // The swapped region can hold Tucano parts (a sortable table).
        if (window.Tucano && Tucano.init) Tucano.init(next);
        markSorted(next);
        try { history.replaceState(null, '', url); } catch (e2) {}
      })
      .catch(function () { form.requestSubmit(); });
  }
  document.addEventListener('change', autosubmit);
  document.addEventListener('tucano:change', autosubmit);

  // A table that comes from the server already sorted says so: Tucano
  // starts every column as unsorted, so the header of the order the rows
  // are in (data-sort-initial) gets its arrow once Tucano has built it.
  function markSorted(root) {
    var ths = (root || document).querySelectorAll('th[data-sort-initial]');
    for (var i = 0; i < ths.length; i++) {
      if (ths[i].getAttribute('aria-sort') === 'none') {
        ths[i].setAttribute('aria-sort', ths[i].getAttribute('data-sort-initial'));
      }
    }
  }
  function markSortedSoon() { setTimeout(function () { markSorted(document); }, 0); }

  // Live numbers: a [data-refresh="N"] page fetches itself again every N
  // seconds while the tab is visible and swaps each [data-live] part (by
  // id), without replaying the charts' entry animation. A table the
  // visitor sorted by another column is left alone, so the order they chose
  // does not jump back.
  function userSorted(part) {
    var init = part.querySelector('th[data-sort-initial]');
    var on = part.querySelector('th[aria-sort]:not([aria-sort="none"])');
    return !!(init && on && (on !== init || on.getAttribute('aria-sort') !== init.getAttribute('data-sort-initial')));
  }
  function refreshLive() {
    var region = document.querySelector('[data-refresh]');
    if (!region || document.hidden) return;
    fetch(location.href, { headers: { Accept: 'text/html' } })
      .then(function (r) { if (!r.ok) throw 0; return r.text(); })
      .then(function (html) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        var parts = document.querySelectorAll('[data-live]');
        for (var i = 0; i < parts.length; i++) {
          var cur = parts[i];
          var next = cur.id && doc.getElementById(cur.id);
          if (!next || userSorted(cur)) continue;
          next.classList.add('no-anim');
          cur.replaceWith(next);
          if (window.Tucano && Tucano.init) Tucano.init(next);
          markSorted(next);
        }
      })
      .catch(function () {});
  }
  (function () {
    var region = document.querySelector('[data-refresh]');
    var secs = region ? parseInt(region.getAttribute('data-refresh'), 10) : 0;
    if (secs >= 5) setInterval(refreshLive, secs * 1000);
  })();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', markSortedSoon);
  } else {
    markSortedSoon();
  }
})();

// While an update is applied the panel restarts: the page asks for itself
// every 2 s, ignoring the errors of the restart, and reloads once the answer
// no longer says "waiting" (the new version is up, or the old one came
// back). After 5 minutes it says so instead of waiting forever.
(function () {
  var box = document.querySelector('[data-update-wait]');
  if (!box) return;
  var started = Date.now();
  function tick() {
    if (Date.now() - started > 5 * 60 * 1000) {
      var msg = box.querySelector('[data-update-msg]');
      if (msg) msg.textContent = box.getAttribute('data-update-slow');
      return;
    }
    fetch('/update', { headers: { Accept: 'text/html' }, cache: 'no-store', credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw 0;
        return r.text();
      })
      .then(function (html) {
        if (html.indexOf('data-update-wait') < 0) { location.reload(); return; }
        setTimeout(tick, 2000);
      })
      .catch(function () { setTimeout(tick, 2000); });
  }
  setTimeout(tick, 2000);
})();
