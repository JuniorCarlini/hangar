// The "Novo serviço" dialog (docs/27). One name per service: the internal
// address shown under it is derived the same way the server derives it
// (projects.Slugify — keep both in step), and a name is suggested from the
// image, the repository or the template until the user types their own.
// Dragging a line from a card to empty space opens the dialog with the
// place filled in (canvas.js calls window.hangarNewService).
(function () {
  var dlg = document.getElementById('new-service');
  if (!dlg) return;
  var taken = (dlg.dataset.taken || '').split(' ').filter(Boolean);
  var MAX = 32;
  // ui.js (loaded first) holds the one copy of the name → identifier rule.
  var slugify = window.hangarSlugify;

  function unique(base) {
    base = slugify(base) || 'web';
    if (taken.indexOf(base) < 0) return base;
    for (var i = 2; ; i++) {
      var suffix = '-' + i, b = base;
      if (b.length + suffix.length > MAX) b = b.slice(0, MAX - suffix.length).replace(/-+$/, '');
      if (taken.indexOf(b + suffix) < 0) return b + suffix;
    }
  }

  function fromImage(v) {
    var n = (v || '').trim().split('@')[0];
    n = n.slice(n.lastIndexOf('/') + 1).split(':')[0];
    return slugify(n);
  }

  function fromRepo(v) {
    var n = (v || '').trim().replace(/\/+$/, '').replace(/\.git$/, '');
    return slugify(n.slice(n.lastIndexOf('/') + 1));
  }

  function showSlug(input) {
    var out = input.closest('div').querySelector('[data-slug-out]');
    if (out) out.textContent = slugify(input.value) || '—';
  }

  function suggest(input, value) {
    if (input.dataset.edited === '1') return;
    input.value = value;
    showSlug(input);
  }

  // The template and repository dialogs sit beside the main one.
  document.querySelectorAll('input[data-service-name]').forEach(function (input) {
    showSlug(input);
    input.addEventListener('input', function () {
      input.dataset.edited = input.value.trim() ? '1' : '';
      showSlug(input);
    });
    var src = input.dataset.suggestFrom && document.getElementById(input.dataset.suggestFrom);
    if (!src) return;
    src.addEventListener('input', function () {
      var base = input.dataset.suggestKind === 'repo' ? fromRepo(src.value) : fromImage(src.value);
      suggest(input, unique(base || 'web'));
    });
  });

  function openDialog(d) {
    if (d.open) return;
    if (d._tucano && typeof d._tucano.open === 'function') d._tucano.open(); else d.showModal();
  }

  // The catalog: a search box and a category select filter the cards (each
  // card opens its template's own dialog).
  var catalog = dlg.querySelector('[data-catalog]');
  if (catalog) {
    var cat = '', query = '';
    var cards = Array.prototype.slice.call(catalog.querySelectorAll('[data-search]'));
    var countOut = catalog.querySelector('[data-catalog-count]');
    var countText = countOut ? countOut.textContent : '';
    var filter = function () {
      var words = query.toLowerCase().split(/\s+/).filter(Boolean), shown = 0;
      cards.forEach(function (c) {
        var ok = (!cat || c.dataset.cat === cat) && words.every(function (w) { return c.dataset.search.indexOf(w) >= 0; });
        c.hidden = !ok;
        if (ok) shown++;
      });
      catalog.querySelector('[data-catalog-empty]').hidden = shown > 0;
      if (countOut) countOut.textContent = countText.replace(/\d+/, String(shown));
    };
    catalog.querySelector('[data-catalog-search]').addEventListener('input', function (e) { query = e.target.value; filter(); });
    var catSel = catalog.querySelector('[data-catalog-cat]');
    var onCat = function () { cat = catSel.value === 'all' ? '' : catSel.value; filter(); };
    if (catSel) ['change', 'tucano:change'].forEach(function (ev) { catSel.addEventListener(ev, onCat); });
  }

  // "Meus repositórios": what the chosen GitHub credential can read,
  // fetched when the tab is first shown. Built with textContent only: the
  // names and descriptions come from GitHub.
  var mine = dlg.querySelector('[data-myrepos]');
  var repoDlg = document.getElementById('repo-detail');
  if (mine && repoDlg) {
    var list = mine.querySelector('[data-myrepos-list]');
    var status = mine.querySelector('[data-myrepos-status]');
    var credSel = mine.querySelector('[data-myrepos-cred]');
    var search = mine.querySelector('[data-myrepos-search]');
    var repos = [], loadedFor = null;
    var lang = document.documentElement.lang || 'pt-BR';
    var rtf = window.Intl && Intl.RelativeTimeFormat ? new Intl.RelativeTimeFormat(lang, { numeric: 'auto' }) : null;
    var ago = function (iso) {
      if (!iso || !rtf) return '';
      var s = (Date.parse(iso) - Date.now()) / 1000, a = Math.abs(s);
      var u = a < 3600 ? ['minute', 60] : a < 86400 ? ['hour', 3600] : a < 2592000 ? ['day', 86400] : a < 31536000 ? ['month', 2592000] : ['year', 31536000];
      return rtf.format(Math.round(s / u[1]), u[0]);
    };
    var el = function (tag, cls, text) {
      var n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text) n.textContent = text;
      return n;
    };
    var errBox = mine.querySelector('[data-myrepos-error]');
    var errText = mine.querySelector('[data-myrepos-error-text]');
    var setStatus = function (text) { status.textContent = text; };
    var setError = function (text) {
      errText.textContent = text || '';
      errBox.hidden = !text;
      status.hidden = !!text;
      search.disabled = !!text;
    };
    var render = function () {
      var words = (search.value || '').toLowerCase().split(/\s+/).filter(Boolean);
      list.textContent = '';
      var shown = repos.filter(function (r) {
        var hay = (r.full_name + ' ' + (r.description || '') + ' ' + (r.language || '')).toLowerCase();
        return words.every(function (w) { return hay.indexOf(w) >= 0; });
      });
      var mark = mine.querySelector('[data-repo-mark]');
      shown.forEach(function (r) {
        var b = el('button', 'catalog-card');
        b.type = 'button';
        var logo = el('span', 'catalog-logo');
        if (mark) logo.appendChild(mark.content.cloneNode(true));
        var txt = el('span', 'flex min-w-0 flex-col gap-0.5 text-left');
        txt.appendChild(el('strong', 'truncate text-[13px] font-semibold', r.full_name));
        if (r.description) txt.appendChild(el('span', 'line-clamp-3 text-xs leading-4 text-muted', r.description));
        txt.appendChild(el('span', 'text-[11px] text-muted',
          [r.private ? mine.dataset.private : mine.dataset.public, r.language, ago(r.pushed_at)].filter(Boolean).join(' · ')));
        b.append(logo, txt);
        b.addEventListener('click', function () { pick(r); });
        list.appendChild(b);
      });
      if (!repos.length) setStatus(mine.dataset.empty);
      else if (!shown.length) setStatus(mine.dataset.none);
      else setStatus(mine.dataset.count.replace('{n}', String(repos.length)));
    };
    var load = function () {
      var cred = credSel.value;
      if (loadedFor === cred) return;
      loadedFor = cred;
      repos = [];
      list.textContent = '';
      setError('');
      setStatus(mine.dataset.loading);
      fetch(mine.dataset.url + '?credential=' + encodeURIComponent(cred), { credentials: 'same-origin' })
        .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || mine.dataset.failed); return j; }); })
        .then(function (j) { if (loadedFor !== cred) return; repos = j.repos || []; render(); })
        .catch(function (err) { if (loadedFor !== cred) return; loadedFor = null; setError(err.message || mine.dataset.failed); });
    };
    var out = function (k, v) { repoDlg.querySelectorAll('[data-repo-out="' + k + '"]').forEach(function (n) { n.textContent = v || '—'; }); };
    var pick = function (r) {
      out('full_name', r.full_name);
      out('visibility', r.private ? mine.dataset.private : mine.dataset.public);
      out('language', r.language);
      out('description', r.description);
      out('default_branch', r.default_branch);
      out('pushed', ago(r.pushed_at));
      out('credential', credSel.options[credSel.selectedIndex].text);
      repoDlg.querySelector('[data-repo-out="language"]').hidden = !r.language;
      repoDlg.querySelector('[data-repo-link]').href = r.url.replace(/\.git$/, '');
      repoDlg.querySelector('[data-repo-in="url"]').value = r.url;
      repoDlg.querySelector('[data-repo-in="credential"]').value = credSel.value;
      var name = repoDlg.querySelector('input[data-service-name]');
      name.dataset.edited = '';
      suggest(name, unique(fromRepo(r.full_name)));
      var sel = repoDlg.querySelector('[data-repo-branches]');
      sel.textContent = '';
      sel.appendChild(new Option(r.default_branch, r.default_branch, true, true));
      // Tucano draws the select from the native options: redraw after
      // filling them.
      var redraw = function () { if (sel._tucano) sel._tucano.refresh(); };
      redraw();
      fetch(mine.dataset.branchesUrl + '?credential=' + encodeURIComponent(credSel.value) + '&repo=' + encodeURIComponent(r.full_name), { credentials: 'same-origin' })
        .then(function (x) { return x.ok ? x.json() : { branches: [] }; })
        .then(function (j) {
          (j.branches || []).forEach(function (b) { if (b !== r.default_branch) sel.appendChild(new Option(b, b)); });
          redraw();
        }).catch(function () {});
      openDialog(repoDlg);
    };
    ['change', 'tucano:change'].forEach(function (ev) { credSel.addEventListener(ev, load); });
    search.addEventListener('input', render);
    var tab = dlg.querySelector('[data-gh-tab]');
    if (tab) tab.addEventListener('click', load);
    if (!mine.closest('[hidden]') && dlg.dataset.open === 'true') load();
  }

  // The model compose file is fetched only when someone asks for it.
  var sampleText = null;
  function sample(url) {
    if (sampleText) return Promise.resolve(sampleText);
    return fetch(url, { credentials: 'same-origin' }).then(function (r) {
      if (!r.ok) throw new Error('status ' + r.status);
      return r.text();
    }).then(function (t) {
      sampleText = t;
      return t;
    });
  }

  dlg.addEventListener('click', function (e) {
    // "Usar o modelo" puts the model file in the text box.
    var b = e.target.closest('[data-compose-sample]');
    if (!b) return;
    var box = dlg.querySelector(b.dataset.composeSample);
    sample(b.dataset.src).then(function (t) {
      if (!box) return;
      box.value = t;
      box.focus();
    }).catch(function () {});
  });

  function open() { openDialog(dlg); }

  // From the canvas: a line dropped on empty space.
  window.hangarNewService = function (from, x, y) {
    document.querySelectorAll('input[data-place="from"]').forEach(function (i) { i.value = from || ''; });
    document.querySelectorAll('input[data-place="x"]').forEach(function (i) { i.value = String(x); });
    document.querySelectorAll('input[data-place="y"]').forEach(function (i) { i.value = String(y); });
    open();
  };

  // Opened through /p/<project>/new: closing goes back to the canvas
  // address, so a reload does not open it again.
  dlg.addEventListener('close', function () {
    if (/\/new$/.test(location.pathname)) history.replaceState(null, '', location.pathname.replace(/\/new$/, ''));
  });
})();
