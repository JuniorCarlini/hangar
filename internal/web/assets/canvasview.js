// Project canvas: where the view starts (pan and zoom), set before the first
// frame. canvas.js is deferred, and the browser may paint (and a
// cross-document view transition snapshot) the page before it runs: the
// cards then showed at the drawing's origin and jumped to the middle a
// moment later. This file is loaded without defer right after the stage, so
// the stage is already parsed and laid out here, and the first frame already
// has the final view. canvas.js reuses the same geometry for its buttons.
(function () {
  // bounds is the box around the cards (not the whole drawing), so the
  // services land in the middle of the screen.
  function bounds(svg) {
    var b = null;
    svg.querySelectorAll('.node-fo').forEach(function (fo) {
      var x = +fo.getAttribute('x'), y = +fo.getAttribute('y');
      var r = x + +fo.getAttribute('width'), btm = y + +fo.getAttribute('height');
      b = b ? { x: Math.min(b.x, x), y: Math.min(b.y, y), r: Math.max(b.r, r), b: Math.max(b.b, btm) } : { x: x, y: y, r: r, b: btm };
    });
    return b || { x: 0, y: 0, r: +svg.getAttribute('width'), b: +svg.getAttribute('height') };
  }
  function clamp(z) { return Math.min(2, Math.max(0.3, z)); }
  // A phone shows the whole drawing on arrival: the desktop zoom would leave
  // the cards outside the screen.
  function narrow(scroll) { return scroll.clientWidth < 640; }
  // fitZoom is the zoom that shows every card.
  function fitZoom(svg, scroll) {
    var bb = bounds(svg);
    var pad = narrow(scroll) ? 32 : 96;
    var z = Math.min(1.2, (scroll.clientWidth - pad) / (bb.r - bb.x), (scroll.clientHeight - pad) / (bb.b - bb.y));
    return Math.max(0.3, Math.round(z * 100) / 100);
  }
  // center is the pan that puts the cards in the middle at zoom z.
  function center(svg, scroll, z) {
    var b = bounds(svg);
    return { x: scroll.clientWidth / 2 - (b.x + b.r) / 2 * z, y: scroll.clientHeight / 2 - (b.y + b.b) / 2 * z };
  }
  // paint moves and scales the stage, and the dot grid with it.
  function paint(stage, area, v) {
    stage.style.transform = 'translate(' + v.x + 'px,' + v.y + 'px) scale(' + v.zoom + ')';
    area.style.backgroundPosition = v.x + 'px ' + v.y + 'px';
    area.style.backgroundSize = (16 * v.zoom) + 'px ' + (16 * v.zoom) + 'px';
  }

  var view = { bounds: bounds, clamp: clamp, narrow: narrow, fitZoom: fitZoom, center: center, paint: paint, initial: null };
  window.HangarCanvasView = view;

  var svg = document.getElementById('canvas');
  var stage = document.getElementById('canvas-stage');
  if (!svg || !stage) return;
  var scroll = svg.closest('.canvas-scroll');
  var area = scroll.closest('.canvas-area');
  // The zoom is remembered per browser and project.
  var zoom = 1;
  try {
    var saved = parseFloat(localStorage.getItem('hangar.zoom.' + svg.dataset.project));
    if (saved) zoom = clamp(saved);
  } catch (_) {}
  if (narrow(scroll)) zoom = fitZoom(svg, scroll);
  var c = center(svg, scroll, zoom);
  view.initial = { x: c.x, y: c.y, zoom: zoom };
  paint(stage, area, view.initial);
})();
