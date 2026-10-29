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
  // Copy buttons whose text is too long for an attribute fetch it from
  // data-copy-url (the updates page's Markdown). The ClipboardItem path hands
  // the clipboard a promise so Safari keeps the click's permission while the
  // text loads; the others copy once it has arrived, the last one through a
  // hidden textarea for browsers without the Clipboard API.
  function copyToast(b, ok) {
    var text = ok ? b.dataset.copied : b.dataset.copyFailed;
    if (window.Tucano && text) {
      window.Tucano.toast({ type: ok ? 'success' : 'danger', text: text, position: 'bottom-center' });
    }
  }
  function copyByTextarea(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (_) {}
    ta.remove();
    return ok ? Promise.resolve() : Promise.reject(new Error('copy'));
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-copy-url]');
    if (!b || b.disabled) return;
    b.disabled = true;
    var text = fetch(b.dataset.copyUrl, { credentials: 'same-origin', headers: { Accept: 'text/markdown' } })
      .then(function (r) {
        if (!r.ok) throw new Error('status ' + r.status);
        return r.text();
      });
    var done;
    if (navigator.clipboard && navigator.clipboard.write && window.ClipboardItem) {
      done = navigator.clipboard.write([new ClipboardItem({
        'text/plain': text.then(function (t) { return new Blob([t], { type: 'text/plain' }); })
      })]).catch(function () {
        return text.then(function (t) {
          return navigator.clipboard.writeText(t).catch(function () { return copyByTextarea(t); });
        });
      });
    } else if (navigator.clipboard && navigator.clipboard.writeText) {
      done = text.then(function (t) {
        return navigator.clipboard.writeText(t).catch(function () { return copyByTextarea(t); });
      });
    } else {
      done = text.then(copyByTextarea);
    }
    done.then(function () { copyToast(b, true); }, function () { copyToast(b, false); })
      .then(function () { b.disabled = false; });
  });
  // Names become identifiers the way the server derives them
  // (projects.Slugify — keep both in step): lowercase, no accents, anything
  // else a hyphen, at most 32 characters, "s-" before a leading digit.
  var accents = { 'á': 'a', 'à': 'a', 'â': 'a', 'ã': 'a', 'ä': 'a', 'å': 'a', 'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
    'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'ö': 'o',
    'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ç': 'c', 'ñ': 'n', 'ý': 'y', 'ÿ': 'y' };
  window.hangarSlugify = function (name) {
    var s = (name || '').trim().toLowerCase().replace(/[^\x00-\x7f]/g, function (c) { return accents[c] || c; });
    var out = '', dash = false;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) { out += c; dash = false; }
      else if (out.length && !dash) { out += '-'; dash = true; }
    }
    out = out.replace(/^-+|-+$/g, '');
    if (/^[0-9]/.test(out)) out = 's-' + out;
    if (out.length > 32) out = out.slice(0, 32).replace(/-+$/, '');
    return /^[a-z][a-z0-9-]{0,30}[a-z0-9]$/.test(out) ? out : '';
  };
  // An input with data-slug-preview="#out" shows its identifier there as
  // it is typed (the new-project dialog).
  function slugPreview(input) {
    var out = document.querySelector(input.dataset.slugPreview);
    if (out) out.textContent = window.hangarSlugify(input.value) || out.dataset.empty || '—';
  }
  document.addEventListener('input', function (e) {
    if (e.target.matches && e.target.matches('[data-slug-preview]')) slugPreview(e.target);
  });
  document.querySelectorAll('[data-slug-preview]').forEach(function (i) { if (i.value) slugPreview(i); });

  // Toasts stay in front of an open modal or drawer: those live in the
  // browser's top layer, above anything else on the page, so Tucano's toast
  // region (a plain element in <body>) would land behind their backdrop.
  // The region becomes a manual popover, which is in the top layer too, and
  // is shown again on every new toast so it stacks above the last dialog.
  function raiseToasts(region) {
    if (!region.showPopover) return;
    if (!region.hasAttribute('popover')) region.setAttribute('popover', 'manual');
    try {
      if (region.matches(':popover-open')) region.hidePopover();
      region.showPopover();
    } catch (_) {}
  }
  function raiseAll() {
    document.querySelectorAll('.tuc-toasts').forEach(function (region) {
      if (region.querySelector('.tuc-toast:not(.is-closing)')) raiseToasts(region);
    });
  }
  new MutationObserver(function (records) {
    records.forEach(function (r) {
      // A dialog that opens after a toast (a drawer reopened by the page
      // the save landed on) would cover it: put the toasts back on top.
      if (r.type === 'attributes') {
        if (r.target.tagName === 'DIALOG' && r.target.open) raiseAll();
        return;
      }
      r.addedNodes.forEach(function (n) {
        if (n.nodeType !== 1) return;
        var region = n.classList.contains('tuc-toasts') ? n : n.classList.contains('tuc-toast') ? n.closest('.tuc-toasts') : null;
        if (region) raiseToasts(region);
      });
    });
  }).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['open'] });
  raiseAll();

  // A dialog marked data-open (a form came back with an error, a link that
  // asks for it) opens by itself: through Tucano's own instance, which is
  // what its triggers call (a trigger may sit in a closed dropdown), else
  // through the trigger. Right after Tucano is set up (it runs first), not
  // at "load", which waits for every image: in document order, so a
  // drawer opens before a dialog inside it.
  function openMarked() {
    document.querySelectorAll('dialog.tuc-modal[data-open="true"], dialog.tuc-drawer[data-open="true"]').forEach(function (d) {
      if (d.open) return;
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
  }
  // This script is deferred, so it runs before DOMContentLoaded (the page
  // is already "interactive" then): wait for it, after Tucano's own
  // listener, which adopts the dialogs. A page shown again from the
  // back/forward cache does not run this again.
  document.addEventListener('DOMContentLoaded', openMarked);

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
  // One request at a time per form: once a form is on its way, its buttons
  // are disabled (the clicked one shows a spinner) until the page answers,
  // so a second click cannot start the same job again or skip the confirm
  // dialog. Runs last (bubble phase on document), after anything that
  // handles the submit itself (confirm dialog, fetch-based forms).
  function unlock(f) {
    delete f.dataset.sending;
    f.removeAttribute('aria-busy');
    f.querySelectorAll('[data-sending-off]').forEach(function (b) {
      b.disabled = false;
      b.removeAttribute('data-sending-off');
      var sp = b.querySelector('.tuc-spinner[data-sending]');
      if (sp) sp.remove();
    });
  }
  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (e.defaultPrevented || !f.matches || f.target || f.hasAttribute('data-no-lock')) return;
    if (f.dataset.sending === '1') { e.preventDefault(); return; }
    f.dataset.sending = '1';
    f.setAttribute('aria-busy', 'true');
    var submitter = e.submitter;
    // Disabled after the event: a disabled button would drop out of the
    // data being sent (its name and value).
    setTimeout(function () {
      delete f.dataset.confirmed;
      f.querySelectorAll('button[type=submit], button:not([type]), input[type=submit]').forEach(function (b) {
        if (b.disabled) return;
        b.disabled = true;
        b.setAttribute('data-sending-off', '');
      });
      if (submitter && submitter.tagName === 'BUTTON' && !submitter.querySelector('.tuc-spinner')) {
        var sp = document.createElement('span');
        sp.className = 'tuc-spinner';
        sp.setAttribute('aria-hidden', 'true');
        sp.setAttribute('data-sending', '');
        submitter.prepend(sp);
      }
    }, 0);
    // A response that is not a page (a file download) leaves this page in
    // place: give the form back after a while.
    setTimeout(function () { unlock(f); }, 20000);
  });
  // Back/forward cache: a page restored as it was left keeps its locks.
  window.addEventListener('pageshow', function (e) {
    if (e.persisted) document.querySelectorAll('form[data-sending]').forEach(unlock);
  });

  // The "done" notice of a redirect (?ok=…) and a dialog a link opened
  // (?routine=1) are shown once: take them out of the address so a reload,
  // a refresh while something runs or the back button does not show them
  // again.
  (function () {
    var u = new URL(location.href);
    if (!u.searchParams.has('ok') && !u.searchParams.has('routine')) return;
    u.searchParams.delete('ok');
    u.searchParams.delete('routine');
    history.replaceState(history.state, '', u.pathname + u.search + u.hash);
  })();

  // A page showing a job in progress ([data-busy-poll], e.g. a dependency
  // scan or a backup) checks every few seconds and reloads once the job is
  // over, instead of reloading itself (and its notice) the whole time.
  // Checked on every tick, so content swapped in later (the drawer) counts.
  var polling = false;
  setInterval(function () {
    if (polling || document.hidden || !document.querySelector('[data-busy-poll]')) return;
    polling = true;
    fetch(location.pathname + location.search, { credentials: 'same-origin', headers: { Accept: 'text/html' } })
      .then(function (r) { return r.ok ? r.text() : ''; })
      .then(function (html) {
        if (html && html.indexOf('data-busy-poll') < 0) location.reload();
      })
      .catch(function () {})
      .finally(function () { polling = false; });
  }, 3000);

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
        document.dispatchEvent(new CustomEvent('hangar:swap'));
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
        // The chart hover card moves onto the new charts (below).
        document.dispatchEvent(new CustomEvent('hangar:swap'));
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

// Hover cards on the history charts (svg[data-spark], views.spark): the bar
// under the pointer, or the one picked with the arrow keys once the chart
// has focus, is highlighted and a Tucano tooltip shows its time (in the
// browser's own time zone) and its reading. One card for the whole page,
// in the top layer (a manual popover) so it also shows over the service
// drawer. A live refresh swaps the charts: the card moves onto the new ones
// in the same frame, so it does not blink.
(function () {
  var SEL = 'svg[data-spark]';
  var tip = null, body = null, arrow = null;
  var chart = null, bar = null;
  var pos = -1;      // the chart's place among the page's charts
  var byKey = false; // shown from the keyboard (not the pointer)
  var last = null;   // the mouse's last spot over a chart
  var lang = document.documentElement.lang || undefined;
  var HM = { hour: '2-digit', minute: '2-digit' };
  var DM = { day: '2-digit', month: '2-digit' };

  function card() {
    if (tip) return tip;
    tip = document.createElement('div');
    tip.className = 'tuc-tip spark-tip';
    tip.id = 'spark-tip';
    tip.setAttribute('role', 'tooltip');
    if (tip.showPopover) tip.setAttribute('popover', 'manual');
    body = document.createElement('span');
    body.className = 'tuc-tip__text spark-tip__text';
    arrow = document.createElement('span');
    arrow.className = 'tuc-tip__arrow';
    arrow.setAttribute('aria-hidden', 'true');
    tip.append(body, arrow);
    document.body.appendChild(tip);
    return tip;
  }
  function bars(svg) { return svg.querySelectorAll('rect[data-at]'); }
  // The bar with data nearest to slot i (a gap has no rect).
  function nearest(svg, i) {
    var best = null, dist = Infinity, rs = bars(svg);
    for (var k = 0; k < rs.length; k++) {
      var d = Math.abs(parseInt(rs[k].getAttribute('data-i'), 10) - i);
      if (d < dist) { dist = d; best = rs[k]; }
    }
    return best;
  }
  // "14:32", "14:30 – 14:45" for a bar longer than a minute, with the date
  // in front when the chart crosses midnight, and only the date for a
  // bar of a whole day.
  function when(svg, rect) {
    var step = parseInt(svg.getAttribute('data-step'), 10) || 0;
    var at = parseInt(rect.getAttribute('data-at'), 10) * 1000;
    var d = new Date(at);
    if (step >= 86400) return d.toLocaleDateString(lang, DM);
    var s = d.toLocaleTimeString(lang, HM);
    if (step > 60) s += ' – ' + new Date(at + step * 1000).toLocaleTimeString(lang, HM);
    var rs = bars(svg);
    var first = new Date(parseInt(rs[0].getAttribute('data-at'), 10) * 1000);
    var end = new Date(parseInt(rs[rs.length - 1].getAttribute('data-at'), 10) * 1000);
    if (first.toDateString() !== end.toDateString()) s = d.toLocaleDateString(lang, DM) + ' ' + s;
    return s;
  }
  function line(cls, text) {
    var s = document.createElement('span');
    s.className = cls;
    s.textContent = text;
    return s;
  }
  function show(svg, rect) {
    if (!rect) { hide(); return; }
    card();
    if (chart && chart !== svg) chart.classList.remove('is-pointing');
    if (bar && bar !== rect) bar.classList.remove('is-on');
    chart = svg; bar = rect;
    pos = Array.prototype.indexOf.call(document.querySelectorAll(SEL), svg);
    svg.classList.add('is-pointing');
    rect.classList.add('is-on');
    var parts = [line('spark-tip__time', when(svg, rect)), line('spark-tip__value', rect.getAttribute('data-tip'))];
    if (rect.hasAttribute('data-peak')) parts.push(line('spark-tip__peak', svg.getAttribute('data-peak-text')));
    body.replaceChildren.apply(body, parts);
    svg.setAttribute('aria-describedby', tip.id);
    if (!tip.classList.contains('is-open')) {
      try { if (tip.showPopover && !tip.matches(':popover-open')) tip.showPopover(); } catch (_) {}
      tip.classList.add('is-open');
    }
    place();
  }
  // Above the bar, or below the chart when there is no room above; slid
  // sideways to stay on screen, the arrow still pointing at the bar.
  function place() {
    var r = bar.getBoundingClientRect(), c = chart.getBoundingClientRect();
    var w = tip.offsetWidth, h = tip.offsetHeight, gap = 8, pad = 6;
    var vw = document.documentElement.clientWidth, vh = document.documentElement.clientHeight;
    var x = r.left + r.width / 2;
    var side = 'top', top = c.top - h - gap;
    if (top < pad && c.bottom + gap + h <= vh - pad) { side = 'bottom'; top = c.bottom + gap; }
    var left = Math.min(Math.max(x - w / 2, pad), Math.max(pad, vw - w - pad));
    tip.style.left = Math.round(left) + 'px';
    tip.style.top = Math.round(top) + 'px';
    tip.setAttribute('data-side', side);
    arrow.style.left = Math.min(Math.max(x - left, 8), w - 8) + 'px';
    arrow.style.top = side === 'top' ? '100%' : '0';
  }
  function hide() {
    if (chart) { chart.classList.remove('is-pointing'); chart.removeAttribute('aria-describedby'); }
    if (bar) bar.classList.remove('is-on');
    chart = bar = null;
    if (!tip) return;
    tip.classList.remove('is-open');
    try { if (tip.hidePopover && tip.matches(':popover-open')) tip.hidePopover(); } catch (_) {}
  }
  function pick(svg, clientX) {
    var c = svg.getBoundingClientRect();
    var n = parseInt(svg.getAttribute('data-bars'), 10) || 1;
    var i = Math.min(n - 1, Math.max(0, Math.floor((clientX - c.left) / c.width * n)));
    byKey = false;
    show(svg, nearest(svg, i));
  }

  document.addEventListener('pointermove', function (e) {
    var svg = e.target.closest && e.target.closest(SEL);
    if (svg) {
      if (e.pointerType === 'mouse') last = { x: e.clientX, y: e.clientY };
      pick(svg, e.clientX);
    } else if (chart && !byKey && e.pointerType !== 'touch') {
      last = null;
      hide();
    }
  });
  // A tap shows the bar under the finger; a tap elsewhere puts it away.
  document.addEventListener('pointerdown', function (e) {
    var svg = e.target.closest && e.target.closest(SEL);
    if (svg) pick(svg, e.clientX);
    else if (chart) hide();
  });
  document.addEventListener('pointerout', function (e) {
    if (!e.relatedTarget && e.pointerType === 'mouse' && chart && !byKey) { last = null; hide(); }
  });
  window.addEventListener('scroll', function () { if (chart && !byKey) hide(); else if (chart) place(); }, true);
  window.addEventListener('resize', function () { if (chart) place(); });

  document.addEventListener('keydown', function (e) {
    var svg = e.target.closest && e.target.closest(SEL);
    if (!svg) return;
    if (e.key === 'Escape') { if (chart) { hide(); e.preventDefault(); } return; }
    var rs = Array.prototype.slice.call(bars(svg));
    if (!rs.length) return;
    var at = chart === svg && bar ? rs.indexOf(bar) : rs.length;
    var to;
    switch (e.key) {
      case 'ArrowLeft': to = at - 1; break;
      case 'ArrowRight': to = at + 1; break;
      case 'Home': to = 0; break;
      case 'End': to = rs.length - 1; break;
      default: return;
    }
    e.preventDefault();
    byKey = true;
    show(svg, rs[Math.min(rs.length - 1, Math.max(0, to))]);
  });
  // Tabbing onto a chart starts on its newest bar.
  document.addEventListener('focusin', function (e) {
    var svg = e.target.closest && e.target.closest(SEL);
    if (!svg || chart === svg || !svg.matches(':focus-visible')) return;
    var rs = bars(svg);
    if (!rs.length) return;
    byKey = true;
    show(svg, rs[rs.length - 1]);
  });
  document.addEventListener('focusout', function (e) {
    if (!byKey || !e.target.closest || e.target.closest(SEL) !== chart) return;
    // Wait: a live refresh takes the focused chart out and focuses its
    // replacement right after.
    var was = chart;
    setTimeout(function () { if (chart === was && document.activeElement !== was) hide(); }, 0);
  });

  // After a live refresh (or a period change) the old chart is gone: find
  // the same chart again, at the same bar — the one under the mouse, or the
  // same moment for the keyboard and touch.
  document.addEventListener('hangar:swap', function () {
    if (!chart || chart.isConnected) return;
    var oldAt = bar && bar.getAttribute('data-at');
    if (last) {
      var el = document.elementFromPoint(last.x, last.y);
      var svg = el && el.closest && el.closest(SEL);
      chart = bar = null;
      if (svg) pick(svg, last.x); else hide();
      return;
    }
    // The chart in the same place on the page.
    var next = pos >= 0 ? document.querySelectorAll(SEL)[pos] : null;
    chart = bar = null;
    if (!next) { hide(); return; }
    var hit = oldAt && next.querySelector('rect[data-at="' + oldAt + '"]');
    var rs = bars(next);
    if (byKey) next.focus({ preventScroll: true });
    show(next, hit || rs[rs.length - 1]);
  });
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
