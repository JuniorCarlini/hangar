// Cross-document view transitions (@view-transition in components.css).
// A navigation that starts while one runs (fast clicks, the ⌘K palette,
// back and forward) aborts it, and the browser rejects the transition's
// promises; nobody waits on them, so Chrome printed "Transition was
// aborted" in the console. Here they are marked as handled. A page revealed
// while hidden (another tab) skips the animation.
//
// Loaded without defer, in <head>: pagereveal fires before the first frame,
// before any deferred script runs.
(function () {
  function quiet(vt) {
    if (!vt) return;
    [vt.ready, vt.finished, vt.updateCallbackDone].forEach(function (p) {
      if (p && typeof p.catch === 'function') p.catch(function () {});
    });
  }
  window.addEventListener('pageswap', function (e) { quiet(e.viewTransition); });
  window.addEventListener('pagereveal', function (e) {
    quiet(e.viewTransition);
    if (e.viewTransition && document.visibilityState === 'hidden') e.viewTransition.skipTransition();
  });
})();
