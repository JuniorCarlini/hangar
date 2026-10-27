// Project canvas: drag from a card's port to another card to connect them.
// A card that offers nothing takes no connection (a toast says so); one that
// does opens the connect dialog, where each offered value gets the variable
// of the dragged service that receives it (a reference such as
// DB_HOST = ${{db.HOST}}), applied by the next deploy. The Variables tab
// connects one pair at a time from its Connector card. Texts come from
// data-*.
(function () {
  var modal = document.getElementById('connect-modal');
  if (!modal) return;
  var project = modal.dataset.project;
  var body = document.getElementById('connect-body');
  var title = document.getElementById('connect-modal-title');
  var from = '';

  function load(to) {
    body.textContent = '';
    var p = document.createElement('p');
    p.className = 'm-0 text-[13px] text-muted';
    p.textContent = modal.dataset.loading;
    body.appendChild(p);
    fetch('/p/' + project + '/s/' + encodeURIComponent(from) + '/connect' + (to ? '?to=' + encodeURIComponent(to) : ''), { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.text(); })
      .then(function (html) { body.innerHTML = html; })
      .catch(function () { p.textContent = modal.dataset.failed; });
  }
  function open() { if (modal._tucano) modal._tucano.open(); else modal.showModal(); }

  // window.hangarConnect opens the dialog: to is one service ("db", a drag
  // on the canvas) or empty for every service that offers something.
  window.hangarConnect = function (fromSlug, to) {
    from = fromSlug;
    title.textContent = modal.dataset.title.replace('{from}', from);
    load(to || '');
    open();
  };
})();

(function () {
  var svg = document.getElementById('canvas');
  if (!svg || svg.dataset.canConnect !== 'true') return;
  var line = document.getElementById('drag-line');
  var project = svg.dataset.project;
  var drag = null;

  function toSvg(x, y) {
    var pt = svg.createSVGPoint();
    pt.x = x; pt.y = y;
    return pt.matrixTransform(svg.getScreenCTM().inverse());
  }
  function curve(a, b) {
    var dx = Math.max(60, Math.abs(b.x - a.x) / 2);
    return 'M ' + a.x + ' ' + a.y + ' C ' + (a.x + dx) + ' ' + a.y + ', ' + (b.x - dx) + ' ' + b.y + ', ' + b.x + ' ' + b.y;
  }
  function nodeAt(x, y) {
    var el = document.elementFromPoint(x, y);
    return el ? el.closest('.node') : null;
  }
  function offers(node) { return (node.dataset.exports || '').trim() !== ''; }
  function clearDrop() {
    svg.querySelectorAll('.node.is-drop, .node.is-nodrop').forEach(function (n) { n.classList.remove('is-drop', 'is-nodrop'); });
  }

  svg.addEventListener('pointerdown', function (e) {
    var port = e.target.closest('.node-port');
    if (!port) return;
    e.preventDefault();
    var r = port.getBoundingClientRect();
    drag = { from: port.dataset.from, start: toSvg(r.left + r.width / 2, r.top + r.height / 2), port: port };
    port.classList.add('is-on');
    line.setAttribute('d', curve(drag.start, drag.start));
    line.classList.add('is-on');
    port.setPointerCapture(e.pointerId);
  });

  svg.addEventListener('pointermove', function (e) {
    if (!drag) return;
    line.setAttribute('d', curve(drag.start, toSvg(e.clientX, e.clientY)));
    clearDrop();
    var target = nodeAt(e.clientX, e.clientY);
    if (target && target.dataset.slug !== drag.from) target.classList.add(offers(target) ? 'is-drop' : 'is-nodrop');
  });

  svg.addEventListener('pointerup', function (e) {
    if (!drag) return;
    var from = drag.from;
    var drag0 = drag.start;
    drag.port.classList.remove('is-on');
    drag = null;
    line.classList.remove('is-on');
    var target = nodeAt(e.clientX, e.clientY);
    clearDrop();
    if (!target) {
      // Dropped on empty space: create a service there, connected to this
      // one (the new-service dialog knows where and from whom).
      var p = toSvg(e.clientX, e.clientY);
      var start = drag0;
      if (Math.abs(p.x - start.x) + Math.abs(p.y - start.y) > 40) {
        var x = Math.round((p.x - 20) / 16) * 16, y = Math.round((p.y - 46) / 16) * 16;
        if (window.hangarNewService) window.hangarNewService(from, x, y);
        else location.href = '/p/' + project + '/new?from=' + encodeURIComponent(from) + '&x=' + x + '&y=' + y;
      }
      return;
    }
    if (target.dataset.slug === from) return;
    if (!offers(target)) {
      if (window.Tucano) window.Tucano.toast({ type: 'warning', text: svg.dataset.nothing.replace('{service}', target.dataset.slug) });
      return;
    }
    if (window.hangarConnect) window.hangarConnect(from, target.dataset.ref);
  });
})();

// Moving cards, zoom and opening a service without reloading the page.
// Card positions are saved on drop (POST …/position); lines follow the card
// while it moves, using the same geometry as the server (canvas.go).
(function () {
  var svg = document.getElementById('canvas');
  if (!svg) return;
  var scroll = svg.closest('.canvas-scroll');
  var project = svg.dataset.project;
  var csrf = svg.dataset.csrf;
  var baseW = +svg.getAttribute('width'), baseH = +svg.getAttribute('height');
  var zoom = 1;
  // Room around each card inside its foreignObject (cardPad in canvas.templ).
  var PAD = 16;

  function toSvg(x, y) {
    var pt = svg.createSVGPoint();
    pt.x = x; pt.y = y;
    return pt.matrixTransform(svg.getScreenCTM().inverse());
  }
  function boxOf(key) {
    var fo = svg.querySelector('.node-fo[data-key="' + CSS.escape(key) + '"]');
    if (!fo) return null;
    return { x: +fo.getAttribute('x') + PAD, y: +fo.getAttribute('y') + PAD, w: +fo.getAttribute('width') - 2 * PAD, h: +(fo.dataset.h || fo.getAttribute('height') - 2 * PAD) };
  }
  function curve(x1, y1, x2, y2, back) {
    if (back) {
      var bx = Math.min(x1, x2) - 60;
      return 'M ' + x1 + ' ' + y1 + ' C ' + bx + ' ' + y1 + ', ' + bx + ' ' + y2 + ', ' + x2 + ' ' + y2;
    }
    var dx = Math.max(60, Math.abs(x2 - x1) / 2);
    return 'M ' + x1 + ' ' + y1 + ' C ' + (x1 + dx) + ' ' + y1 + ', ' + (x2 - dx) + ' ' + y2 + ', ' + x2 + ' ' + y2;
  }
  function redraw(key) {
    svg.querySelectorAll('.edge').forEach(function (g) {
      if (g.dataset.from !== key && g.dataset.to !== key) return;
      var b = boxOf(g.dataset.to), d;
      if (!b) return;
      if (g.dataset.internet === 'true') {
        var m = /^M (-?[\d.]+) (-?[\d.]+)/.exec(g.querySelector('path').getAttribute('d'));
        var x1 = +m[1], y1 = +m[2], x2 = b.x + b.w / 2, y2 = b.y, my = (y1 + y2) / 2;
        d = 'M ' + x1 + ' ' + y1 + ' C ' + x1 + ' ' + my + ', ' + x2 + ' ' + my + ', ' + x2 + ' ' + y2;
      } else {
        var a = boxOf(g.dataset.from);
        if (!a) return;
        var slot = +g.dataset.slot || 0, right = b.x > a.x;
        d = curve(right ? a.x + a.w : a.x, a.y + a.h / 2, b.x, b.y + b.h / 2 + slot, !right);
      }
      g.querySelectorAll('path').forEach(function (p) { p.setAttribute('d', d); });
    });
  }
  function grow() {
    // Keep every card inside the drawing when one is dropped near the edge.
    svg.querySelectorAll('.node-fo').forEach(function (fo) {
      baseW = Math.max(baseW, +fo.getAttribute('x') + +fo.getAttribute('width') + 60);
      baseH = Math.max(baseH, +fo.getAttribute('y') + +fo.getAttribute('height') + 60);
    });
    svg.setAttribute('viewBox', '0 0 ' + baseW + ' ' + baseH);
    svg.setAttribute('width', baseW);
    svg.setAttribute('height', baseH);
  }

  // The cards are links: without this the browser starts dragging the link
  // itself and the card never moves.
  svg.addEventListener('dragstart', function (e) { e.preventDefault(); });

  // The view is free, as on Railway/n8n: the drawing sits on a stage moved
  // and scaled by a transform. Drag the empty canvas (or scroll with the
  // trackpad) to pan in any direction; ctrl/⌘ + wheel or pinch zooms at the
  // pointer.
  var stage = document.getElementById('canvas-stage');
  var view = { x: 0, y: 0 };
  var area = scroll.closest('.canvas-area');
  // will-change keeps panning smooth, but the browser then keeps the stage
  // as the bitmap it painted at the old zoom and only stretches it: text gets
  // blurry. So it is on only while the view moves, and dropped once it rests
  // so the cards are painted sharp at the new zoom.
  var settle = 0;
  function applyView() {
    stage.classList.add('is-moving');
    clearTimeout(settle);
    settle = setTimeout(function () { stage.classList.remove('is-moving'); }, 150);
    stage.style.transform = 'translate(' + view.x + 'px,' + view.y + 'px) scale(' + zoom + ')';
    // The dot grid moves and scales with the drawing.
    area.style.backgroundPosition = view.x + 'px ' + view.y + 'px';
    area.style.backgroundSize = (16 * zoom) + 'px ' + (16 * zoom) + 'px';
  }
  var pan = null;
  scroll.addEventListener('pointerdown', function (e) {
    if (e.button !== 0 || e.target.closest('.node-fo, .node-port, .canvas-zoom, a, button')) return;
    pan = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, id: e.pointerId };
    scroll.setPointerCapture(e.pointerId);
    scroll.classList.add('is-panning');
  });
  scroll.addEventListener('pointermove', function (e) {
    if (!pan || e.pointerId !== pan.id) return;
    view.x = pan.vx + (e.clientX - pan.x);
    view.y = pan.vy + (e.clientY - pan.y);
    applyView();
  });
  function endPan(e) {
    if (!pan || e.pointerId !== pan.id) return;
    pan = null;
    scroll.classList.remove('is-panning');
  }
  scroll.addEventListener('pointerup', endPan);
  scroll.addEventListener('pointercancel', endPan);

  // Drag a card. A short press still opens the service (it is a link).
  var drag = null, justDragged = false;
  svg.addEventListener('pointerdown', function (e) {
    if (e.button !== 0 || e.target.closest('.node-port')) return;
    var fo = e.target.closest('.node-fo');
    if (!fo || fo.dataset.movable !== 'true') return;
    e.preventDefault();
    var p = toSvg(e.clientX, e.clientY);
    drag = { fo: fo, key: fo.dataset.key, dx: p.x - +fo.getAttribute('x'), dy: p.y - +fo.getAttribute('y'), sx: e.clientX, sy: e.clientY, moved: false, id: e.pointerId };
  });
  svg.addEventListener('pointermove', function (e) {
    if (!drag || e.pointerId !== drag.id) return;
    if (!drag.moved) {
      if (Math.abs(e.clientX - drag.sx) + Math.abs(e.clientY - drag.sy) < 5) return;
      drag.moved = true;
      drag.fo.classList.add('is-dragging');
      svg.classList.add('is-moving');
      svg.setPointerCapture(e.pointerId);
    }
    var p = toSvg(e.clientX, e.clientY);
    // Snap to the 16px dot grid behind the canvas. The canvas has no edge:
    // cards go left and up of where the drawing started as well.
    var x = Math.round((p.x - drag.dx) / 16) * 16;
    var y = Math.round((p.y - drag.dy) / 16) * 16;
    drag.fo.setAttribute('x', x);
    drag.fo.setAttribute('y', y);
    redraw(drag.key);
  });
  function drop(e) {
    if (!drag || e.pointerId !== drag.id) return;
    var d = drag;
    drag = null;
    if (!d.moved) return;
    justDragged = true;
    setTimeout(function () { justDragged = false; }, 0);
    d.fo.classList.remove('is-dragging');
    svg.classList.remove('is-moving');
    grow();
    var body = new URLSearchParams({ x: +d.fo.getAttribute('x') + PAD, y: +d.fo.getAttribute('y') + PAD });
    fetch('/p/' + project + '/s/' + d.key + '/position', {
      method: 'POST', body: body, credentials: 'same-origin', headers: { 'X-CSRF-Token': csrf }
    }).catch(function () {});
  }
  svg.addEventListener('pointerup', drop);
  svg.addEventListener('pointercancel', drop);
  svg.addEventListener('click', function (e) {
    if (justDragged) { e.preventDefault(); e.stopPropagation(); }
  }, true);

  // Zoom: buttons, ctrl/⌘ + wheel or pinch, kept around a point; the level
  // is remembered per browser.
  var label = document.getElementById('zoom-label');
  function zoomAt(z, cx, cy) {
    var nz = Math.min(2, Math.max(0.3, Math.round(z * 100) / 100));
    // Keep the point under (cx, cy) still while scaling.
    view.x = cx - (cx - view.x) * nz / zoom;
    view.y = cy - (cy - view.y) * nz / zoom;
    zoom = nz;
    applyView();
    if (label) label.textContent = Math.round(zoom * 100) + '%';
    try { localStorage.setItem('hangar.zoom.' + project, zoom); } catch (_) {}
  }
  function applyZoom(z) { zoomAt(z, scroll.clientWidth / 2, scroll.clientHeight / 2); }
  // bounds is the box around the cards (not the whole drawing), so the
  // services land in the middle of the screen.
  function bounds() {
    var b = null;
    svg.querySelectorAll('.node-fo').forEach(function (fo) {
      var x = +fo.getAttribute('x'), y = +fo.getAttribute('y');
      var r = x + +fo.getAttribute('width'), btm = y + +fo.getAttribute('height');
      b = b ? { x: Math.min(b.x, x), y: Math.min(b.y, y), r: Math.max(b.r, r), b: Math.max(b.b, btm) } : { x: x, y: y, r: r, b: btm };
    });
    return b || { x: 0, y: 0, r: baseW, b: baseH };
  }
  function center() {
    var b = bounds();
    view.x = scroll.clientWidth / 2 - (b.x + b.r) / 2 * zoom;
    view.y = scroll.clientHeight / 2 - (b.y + b.b) / 2 * zoom;
    applyView();
  }
  // A phone shows the whole drawing on arrival: the desktop zoom would leave
  // the cards outside the screen.
  var narrow = function () { return scroll.clientWidth < 640; };
  function fit() {
    var bb = bounds();
    var pad = narrow() ? 32 : 96;
    var z = Math.min(1.2, (scroll.clientWidth - pad) / (bb.r - bb.x), (scroll.clientHeight - pad) / (bb.b - bb.y));
    zoom = Math.max(0.3, Math.round(z * 100) / 100);
    if (label) label.textContent = Math.round(zoom * 100) + '%';
    center();
  }
  document.querySelectorAll('[data-zoom]').forEach(function (b) {
    b.addEventListener('click', function () {
      var k = b.dataset.zoom;
      if (k === 'in') applyZoom(zoom + 0.1);
      else if (k === 'out') applyZoom(zoom - 0.1);
      else if (k === 'reset') { zoom = 1; if (label) label.textContent = '100%'; center(); }
      else fit();
    });
  });
  scroll.addEventListener('wheel', function (e) {
    e.preventDefault();
    var r = scroll.getBoundingClientRect();
    if (e.ctrlKey || e.metaKey) {
      zoomAt(zoom * Math.exp(-e.deltaY * 0.01), e.clientX - r.left, e.clientY - r.top);
    } else {
      view.x -= e.deltaX;
      view.y -= e.deltaY;
      applyView();
    }
  }, { passive: false });
  try {
    var saved = parseFloat(localStorage.getItem('hangar.zoom.' + project));
    if (saved) zoom = Math.min(2, Math.max(0.3, saved));
  } catch (_) {}
  if (label) label.textContent = Math.round(zoom * 100) + '%';
  if (narrow()) fit(); else center();
  window.addEventListener('resize', function () { if (!pan) center(); });

  // Open a service in the side drawer without reloading: fetch the page and
  // swap only the drawer's content and the selected card. The logs tab
  // streams, so it still loads as a full page. Closing the drawer (X,
  // Escape, click outside) takes the address back to the project.
  var closingByCode = false;
  function select(slug) {
    svg.querySelectorAll('.node').forEach(function (n) {
      n.classList.toggle('is-selected', !!slug && n.dataset.slug === slug && !n.classList.contains('is-external'));
    });
  }
  // The X inside swapped content is not bound by Tucano: close through the
  // drawer instance (it animates and fires "close").
  document.addEventListener('click', function (e) {
    var x = e.target.closest('#svc-panel [data-tuc-drawer-close]');
    if (!x) return;
    var d = document.getElementById('svc-panel');
    e.preventDefault();
    e.stopPropagation();
    if (d._tucano && d._tucano.close) d._tucano.close(); else d.close();
  }, true);
  function closeDrawer() {
    var cur = document.getElementById('svc-panel');
    if (cur && cur.open) {
      closingByCode = true;
      if (cur._tucano && cur._tucano.close) cur._tucano.close(); else cur.close();
    }
  }
  document.addEventListener('close', function (e) {
    if (!e.target || e.target.id !== 'svc-panel') return;
    if (closingByCode) { closingByCode = false; return; }
    select('');
    var home = '/p/' + project;
    if (location.pathname !== home) history.pushState({ panel: false }, '', home);
  }, true);
  function swap(url, push) {
    // Feedback at once: the card being opened shows it is loading while
    // the drawer comes (only the drawer: X-Hangar-Fragment).
    var slug = (/\/s\/([^/?#]+)/.exec(url) || [])[1];
    var card = slug && svg.querySelector('.node[data-slug="' + slug + '"]');
    if (card) card.classList.add('is-loading');
    document.documentElement.classList.add('is-busy');
    return fetch(url, { credentials: 'same-origin', headers: { Accept: 'text/html', 'X-Hangar-Fragment': 'panel' } }).then(function (r) {
      if (!r.ok || r.redirected) throw new Error('reload');
      return r.text();
    }).then(function (html) {
      var doc = new DOMParser().parseFromString(html, 'text/html');
      var next = doc.getElementById('svc-panel');
      var cur = document.getElementById('svc-panel');
      if (window.HangarLogs) HangarLogs.stop();
      if (next && cur && cur.open) {
        // Same drawer, new content: swap what is inside the panel, keeping
        // the panel itself (Tucano holds it to animate and close).
        var panel = cur.querySelector('.tuc-drawer__panel');
        var fresh = document.importNode(next.querySelector('.tuc-drawer__panel'), true);
        panel.replaceChildren.apply(panel, Array.prototype.slice.call(fresh.childNodes));
        if (window.Tucano && Tucano.init) Tucano.init(panel);
      } else if (next) {
        if (cur) { cur.remove(); }
        var oldTrigger = document.getElementById('svc-open');
        if (oldTrigger) oldTrigger.remove();
        var trigger = document.importNode(doc.getElementById('svc-open'), true);
        next = document.importNode(next, true);
        area.appendChild(trigger);
        area.appendChild(next);
        if (window.Tucano && Tucano.init) Tucano.init(area);
        trigger.click();
      } else {
        closeDrawer();
      }
      if (window.HangarLogs) HangarLogs.start();
      select((/\/s\/([^/?#]+)/.exec(url) || [])[1]);
      if (doc.title) document.title = doc.title;
      if (push) history.pushState({ panel: true }, '', url);
    }).catch(function () { location.href = url; }).finally(function () {
      if (card) card.classList.remove('is-loading');
      document.documentElement.classList.remove('is-busy');
    });
  }
  function local(a) {
    if (!a || a.target || a.hasAttribute('download')) return false;
    var u = new URL(a.href, location.href);
    return u.origin === location.origin && (u.pathname === '/p/' + project || u.pathname.indexOf('/p/' + project + '/s/') === 0) && !/\/logs$/.test(u.pathname) && u.searchParams.get('tab') !== 'terminal';
  }
  document.addEventListener('click', function (e) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var a = e.target.closest('a');
    if (!a || !(a.closest('#canvas') || a.closest('#svc-panel')) || !local(a)) return;
    var u = new URL(a.href, location.href);
    if (u.searchParams.get('view') === 'list') return;
    e.preventDefault();
    swap(u.pathname + u.search, true);
  });
  window.addEventListener('popstate', function () { swap(location.pathname + location.search, false); });

  // While something deploys, the cards follow it without reloading the
  // page: every 2 s the project page is fetched and only the cards that
  // changed are updated, so the zoom, the open drawer (or a closed one)
  // and anything being typed stay as they are. A progress bar fills up to
  // the end before its card turns into the final state.
  function busy() {
    var a = document.activeElement;
    return document.querySelector('dialog[open]:not(#svc-panel)') ||
      (a && a.closest && a.closest('#svc-panel') && a.matches('input, textarea, select'));
  }
  function updateCard(cur, next) {
    var selected = cur.classList.contains('is-selected');
    var bar = cur.querySelector('.node-progress-bar');
    var nextBar = next.querySelector('.node-progress-bar');
    if (bar && nextBar) {
      // Still deploying: move the bar and the phase text, so the width
      // animates instead of jumping.
      bar.className = nextBar.className;
      var s = cur.querySelector('.node-progress');
      var ns = next.querySelector('.node-progress');
      if (s && ns && s.previousElementSibling && ns.previousElementSibling) {
        s.previousElementSibling.replaceWith(document.importNode(ns.previousElementSibling, true));
      }
      return;
    }
    var apply = function () {
      cur.className = next.className;
      cur.classList.toggle('is-selected', selected);
      cur.innerHTML = next.innerHTML;
    };
    if (bar) {
      bar.classList.add('is-done');
      setTimeout(apply, 700);
    } else {
      apply();
    }
  }
  var drawerStale = false;
  function poll() {
    if (busy()) { setTimeout(poll, 2000); return; }
    fetch('/p/' + project, { credentials: 'same-origin', headers: { Accept: 'text/html' } }).then(function (r) {
      if (!r.ok || r.redirected) throw new Error('poll');
      return r.text();
    }).then(function (html) {
      var doc = new DOMParser().parseFromString(html, 'text/html');
      var fresh = doc.getElementById('canvas');
      if (!fresh) return;
      fresh.querySelectorAll('.node-fo').forEach(function (nfo) {
        var fo = svg.querySelector('.node-fo[data-key="' + CSS.escape(nfo.dataset.key) + '"]');
        var cur = fo && fo.querySelector('.node'), next = nfo.querySelector('.node');
        if (!cur || !next || (cur.innerHTML === next.innerHTML && cur.className.replace(' is-selected', '') === next.className)) return;
        updateCard(cur, next);
        drawerStale = true;
      });
      if (fresh.dataset.deploying === 'true') {
        setTimeout(poll, 2000);
        return;
      }
      // Done: refresh the drawer once if it is open (its deploy list and
      // state changed), without touching a closed one.
      var panel = document.getElementById('svc-panel');
      if (drawerStale && panel && panel.open && /\/s\//.test(location.pathname)) {
        setTimeout(function () { swap(location.pathname + location.search, false); }, 800);
      }
    }).catch(function () { setTimeout(poll, 5000); });
  }
  if (svg.dataset.deploying === 'true') setTimeout(poll, 2000);
})();
