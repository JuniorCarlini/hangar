// Command palette (⌘K / Ctrl+K): a search over pages, projects, services and
// actions. The list comes from /palette.json the first time the palette opens
// on a page (already filtered by the user's role); everything from it is
// written with textContent, and icons are cloned from a server-rendered
// <template>, so nothing in the JSON is ever parsed as HTML.
(function () {
  var dlg = document.getElementById('palette');
  if (!dlg) return;
  var input = document.getElementById('palette-input');
  var list = document.getElementById('palette-list');
  var status = document.getElementById('palette-status');
  var icons = {};
  var tpl = document.getElementById('palette-icons');
  if (tpl) {
    Array.prototype.forEach.call(tpl.content.querySelectorAll('[data-icon]'), function (s) {
      icons[s.dataset.icon] = s.firstElementChild;
    });
  }

  var data = null;    // { groups, items } once loaded
  var loading = null; // the pending fetch
  var shown = [];     // items currently listed, in order
  var active = -1;
  var MAX_EMPTY = 8;  // per group, before the user types
  var MAX = 60;

  // Lowercase without accents: "dominios" finds "Domínios".
  function fold(s) {
    return (s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  }

  // Score one query word against a text: a word start beats a substring,
  // which beats the letters in order (fuzzy). 0 means no match.
  function scoreWord(w, text) {
    var i = text.indexOf(w);
    if (i === 0) return 100;
    if (i > 0) return /[\s/›:._-]/.test(text.charAt(i - 1)) ? 80 : 50;
    var pos = 0, gaps = 0, last = -1;
    for (var k = 0; k < w.length; k++) {
      var j = text.indexOf(w.charAt(k), pos);
      if (j < 0) return 0;
      if (last >= 0) gaps += j - last - 1;
      last = j;
      pos = j + 1;
    }
    return Math.max(1, 30 - gaps);
  }

  function score(it, words) {
    var total = 0;
    for (var i = 0; i < words.length; i++) {
      var s = Math.max(scoreWord(words[i], it._label), scoreWord(words[i], it._all) * 0.6);
      if (!s) return 0;
      total += s;
    }
    return total;
  }

  function prepare(d) {
    d.items.forEach(function (it, i) {
      it._i = i;
      it._label = fold(it.label);
      it._all = fold(it.label + ' ' + (it.hint || ''));
    });
    return d;
  }

  function load() {
    if (data) return Promise.resolve(data);
    if (loading) return loading;
    showStatus(dlg.dataset.loading);
    loading = fetch(dlg.dataset.src, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) {
        if (r.status === 401) { location.reload(); throw new Error('signed out'); }
        if (!r.ok) throw new Error('status ' + r.status);
        return r.json();
      })
      .then(function (d) { data = prepare(d); return data; })
      .catch(function (err) {
        loading = null;
        showStatus(dlg.dataset.error);
        throw err;
      });
    return loading;
  }

  function showStatus(text) {
    list.replaceChildren();
    status.textContent = text || '';
    input.removeAttribute('aria-activedescendant');
  }

  function render() {
    if (!data) return;
    var words = fold(input.value).split(/\s+/).filter(Boolean);
    var byGroup = {};
    data.items.forEach(function (it) {
      if (!words.length) {
        if (it.deep) return;
        (byGroup[it.group] = byGroup[it.group] || []).push({ it: it, s: 0 });
        return;
      }
      var s = score(it, words);
      if (s) (byGroup[it.group] = byGroup[it.group] || []).push({ it: it, s: s });
    });
    shown = [];
    var frag = document.createDocumentFragment();
    data.groups.forEach(function (g) {
      var rows = byGroup[g.id];
      if (!rows || !rows.length || shown.length >= MAX) return;
      rows.sort(function (a, b) { return b.s - a.s || a.it._i - b.it._i; });
      rows = rows.slice(0, words.length ? MAX - shown.length : MAX_EMPTY);
      var box = document.createElement('div');
      box.className = 'palette__group';
      box.setAttribute('role', 'group');
      var label = document.createElement('div');
      label.className = 'tuc-dropdown__label';
      label.id = 'palette-g-' + g.id;
      label.textContent = g.label;
      box.setAttribute('aria-labelledby', label.id);
      box.appendChild(label);
      rows.forEach(function (row) { box.appendChild(option(row.it, shown.length)); shown.push(row.it); });
      frag.appendChild(box);
    });
    list.replaceChildren(frag);
    status.textContent = shown.length ? '' : dlg.dataset.empty;
    select(shown.length ? 0 : -1);
  }

  function option(it, index) {
    var el = document.createElement('div');
    el.className = 'tuc-dropdown__item palette__item' + (it.tone === 'danger' ? ' is-danger' : '');
    el.id = 'palette-opt-' + index;
    el.setAttribute('role', 'option');
    el.setAttribute('aria-selected', 'false');
    el.dataset.index = index;
    var ic = document.createElement('span');
    ic.className = 'tuc-dropdown__icon';
    if (icons[it.icon]) ic.appendChild(icons[it.icon].cloneNode(true));
    var text = document.createElement('span');
    text.className = 'tuc-dropdown__text';
    text.textContent = it.label;
    if (it.hint) {
      var hint = document.createElement('span');
      hint.className = 'palette__hint';
      hint.textContent = it.hint;
      text.appendChild(hint);
    }
    var key = document.createElement('span');
    key.className = 'tuc-dropdown__shortcut';
    key.setAttribute('aria-hidden', 'true');
    key.textContent = '↵';
    el.append(ic, text, key);
    return el;
  }

  function select(i) {
    var prev = list.querySelector('[aria-selected="true"]');
    if (prev) prev.setAttribute('aria-selected', 'false');
    active = i;
    var el = i >= 0 ? document.getElementById('palette-opt-' + i) : null;
    if (!el) { input.removeAttribute('aria-activedescendant'); return; }
    el.setAttribute('aria-selected', 'true');
    input.setAttribute('aria-activedescendant', el.id);
    el.scrollIntoView({ block: 'nearest' });
  }

  // Only local paths: the JSON is ours, but a path is checked before use.
  function local(p) { return typeof p === 'string' && p.charAt(0) === '/' && p.charAt(1) !== '/' && p.indexOf('\\') < 0; }

  function post(p) {
    var f = document.createElement('form');
    f.method = 'post';
    f.action = p.url;
    f.hidden = true;
    var fields = Object.assign({ csrf: dlg.dataset.csrf }, p.fields || {});
    if (p.next) fields.next = location.pathname + location.search;
    Object.keys(fields).forEach(function (k) {
      var i = document.createElement('input');
      i.type = 'hidden';
      i.name = k;
      i.value = fields[k];
      f.appendChild(i);
    });
    document.body.appendChild(f);
    f.submit();
  }

  function run(it) {
    if (!it) return;
    if (it.href) {
      // "Novo serviço" of the project on screen opens its dialog in place.
      var ns = document.getElementById('new-service');
      if (ns && it.href === '/p/' + ns.dataset.project + '/new') {
        close(function () { if (ns._tucano) ns._tucano.open(); else ns.showModal(); });
        return;
      }
      if (local(it.href)) location.href = it.href;
      return;
    }
    // Actions that open another dialog or ask first wait for the palette
    // to close, so the two never fight over focus.
    close(function () {
      if (it.modal) {
        var m = document.getElementById(it.modal);
        if (m && m.classList.contains('tuc-modal') && m._tucano) m._tucano.open();
        return;
      }
      var p = it.post;
      if (!p || !local(p.url)) return;
      if (!p.confirm || !window.Tucano) { post(p); return; }
      window.Tucano.confirm({
        title: p.confirm.title, text: p.confirm.text || '',
        tone: p.confirm.tone || 'default', confirm: p.confirm.ok || undefined
      }).then(function (ok) { if (ok) post(p); });
    });
  }

  var afterClose = null;
  dlg.addEventListener('close', function () {
    var fn = afterClose;
    afterClose = null;
    if (fn) fn();
  });

  function open() {
    if (dlg.open) return;
    input.value = '';
    if (dlg._tucano) dlg._tucano.open(); else dlg.showModal();
    input.focus();
    load().then(render, function () {});
  }

  function close(then) {
    afterClose = then || null;
    if (!dlg.open) { afterClose = null; if (then) then(); return; }
    if (dlg._tucano) dlg._tucano.close(); else dlg.close();
  }

  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      if (dlg.open) close(); else open();
    }
  });
  document.addEventListener('click', function (e) {
    if (e.target.closest && e.target.closest('[data-palette-open]')) { e.preventDefault(); open(); }
  });

  input.addEventListener('input', render);
  input.addEventListener('keydown', function (e) {
    var n = shown.length;
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        if (n) select((active + 1) % n);
        break;
      case 'ArrowUp':
        e.preventDefault();
        if (n) select((active - 1 + n) % n);
        break;
      case 'PageUp':
        e.preventDefault();
        if (n) select(0);
        break;
      case 'PageDown':
        e.preventDefault();
        if (n) select(n - 1);
        break;
      case 'Enter':
        if (e.isComposing) return;
        e.preventDefault();
        run(shown[active]);
        break;
    }
  });
  list.addEventListener('mousemove', function (e) {
    var el = e.target.closest('.palette__item');
    if (el && Number(el.dataset.index) !== active) select(Number(el.dataset.index));
  });
  list.addEventListener('mousedown', function (e) { e.preventDefault(); }); // keep focus in the field
  list.addEventListener('click', function (e) {
    var el = e.target.closest('.palette__item');
    if (el) run(shown[Number(el.dataset.index)]);
  });
})();
