// Validate a GitHub token typed in the "new credential" dialog without saving:
// a read token already identifies its account (GET /user), so as soon as the
// token is entered the panel shows whose profile it is and fills the account
// name. Saving stays disabled until a token checks out, so a wrong one can't
// even be submitted (without JS the button is enabled and the server checks).
// The dialog (#new-git-cred) is shared by the credentials page and the
// new-service dialog, so this wires up every form that declares data-gc-check.
(function () {
  "use strict";

  function wire(form) {
    var url = form.getAttribute("data-gc-check");
    var token = form.querySelector("#gc-token, [name=token]");
    if (!url || !token) return;
    var csrf = form.querySelector("[name=csrf]");
    var name = form.querySelector("#gc-name, [name=name]");
    var profile = form.querySelector("[data-gc-profile]");
    var login = form.querySelector("[data-gc-login]");
    var who = form.querySelector("[data-gc-name]");
    var err = form.querySelector("[data-gc-error]");
    var submit = form.querySelector("[type=submit]");

    function hide(el) { if (el) el.classList.add("hidden"); }
    function show(el) { if (el) el.classList.remove("hidden"); }
    function canSave(on) { if (submit) submit.disabled = !on; }

    // Nothing checked yet: no saving a token the panel has not accepted.
    canSave(false);

    var last = null;
    function check() {
      var tok = (token.value || "").trim();
      if (tok === last) return; // already looked this one up
      last = tok;
      hide(err);
      hide(profile);
      canSave(false);
      if (!tok) return;
      var csrfv = csrf ? csrf.value : "";
      fetch(url, {
        method: "POST",
        headers: { "X-CSRF-Token": csrfv, "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ csrf: csrfv, token: tok }).toString(),
      })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data && data.ok) {
            if (login) login.textContent = "@" + data.login;
            if (who) who.textContent = data.name || "";
            show(profile);
            if (name && !name.value.trim()) name.value = data.login;
            canSave(true);
          } else if (err) {
            err.textContent = (data && data.error) || form.getAttribute("data-gc-fail");
            show(err);
          }
        })
        .catch(function () {
          if (err) { err.textContent = form.getAttribute("data-gc-fail"); show(err); }
        });
    }

    // change fires when the field loses focus after being edited (paste + blur,
    // or typing + Tab), so the lookup runs once the token is in.
    token.addEventListener("change", check);
    token.addEventListener("input", function () {
      if ((token.value || "").trim() !== last) { hide(profile); hide(err); canSave(false); }
    });
  }

  function boot() {
    var forms = document.querySelectorAll("form[data-gc-check]");
    for (var i = 0; i < forms.length; i++) wire(forms[i]);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
