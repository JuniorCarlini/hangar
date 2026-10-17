// Tucano writes Portuguese by default. The panel's language comes from the
// server catalog, in data-* attributes on <html>; Tucano waits for
// DOMContentLoaded before mounting, so this deferred script runs in time.
(function () {
  var d = document.documentElement.dataset;
  if (!window.Tucano || !d.tucShow) return;
  window.Tucano.setTexts({
    mask: { show: d.tucShow, hide: d.tucHide, invalid: d.tucInvalid },
    modal: { close: d.tucClose, confirm: d.tucConfirm, cancel: d.tucCancel },
    toast: { close: d.tucClose },
  });
})();
