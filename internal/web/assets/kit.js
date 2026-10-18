// Recovery kit (docs/09): the backup keys are generated HERE, in the
// browser, and only the public key is sent to the panel. The private key
// lives in this page's memory until the operator downloads/prints it, and
// is never put in a form, a URL or a request.
//
// The kit is a valid age identity file (comments + AGE-SECRET-KEY-1...),
// so `age -d -i hangar-kit.txt` and hangar-cofre both open the backups.
// The confirmation code and its hash must match internal/backup/archive
// (ConfirmCode, CodeHash); kit_test.go checks this file against Go.
var HangarKit = (function () {
  'use strict';

  // --- bech32 (BIP 173), as age encodes its keys --------------------------
  var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

  function polymod(values) {
    var chk = 1;
    for (var i = 0; i < values.length; i++) {
      var top = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ values[i];
      for (var j = 0; j < 5; j++) if ((top >>> j) & 1) chk ^= GEN[j];
    }
    return chk >>> 0;
  }

  function hrpExpand(hrp) {
    var out = [];
    for (var i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
    out.push(0);
    for (i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
    return out;
  }

  function convertBits(data, from, to, pad) {
    var acc = 0, bits = 0, out = [], maxv = (1 << to) - 1;
    for (var i = 0; i < data.length; i++) {
      acc = (acc << from) | data[i];
      bits += from;
      while (bits >= to) {
        bits -= to;
        out.push((acc >> bits) & maxv);
      }
    }
    if (pad) {
      if (bits > 0) out.push((acc << (to - bits)) & maxv);
    } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
      return null;
    }
    return out;
  }

  function bech32Encode(hrp, bytes) {
    hrp = hrp.toLowerCase();
    var data = convertBits(bytes, 8, 5, true);
    var mod = polymod(hrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0])) ^ 1;
    var s = hrp + '1';
    for (var i = 0; i < data.length; i++) s += CHARSET.charAt(data[i]);
    for (i = 0; i < 6; i++) s += CHARSET.charAt((mod >> (5 * (5 - i))) & 31);
    return s;
  }

  function bech32Decode(str) {
    var s = str.toLowerCase();
    var pos = s.lastIndexOf('1');
    if (pos < 1 || pos + 7 > s.length) return null;
    var hrp = s.slice(0, pos), data = [];
    for (var i = pos + 1; i < s.length; i++) {
      var d = CHARSET.indexOf(s.charAt(i));
      if (d < 0) return null;
      data.push(d);
    }
    if (polymod(hrpExpand(hrp).concat(data)) !== 1) return null;
    var bytes = convertBits(data.slice(0, -6), 5, 8, false);
    return bytes ? { hrp: hrp, bytes: new Uint8Array(bytes) } : null;
  }

  // --- small helpers ------------------------------------------------------
  function b64urlToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function hex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return out;
  }

  var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function base32(bytes) {
    var bits = 0, value = 0, out = '';
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        out += B32.charAt((value >>> (bits - 5)) & 31);
        bits -= 5;
      }
    }
    if (bits > 0) out += B32.charAt((value << (5 - bits)) & 31);
    return out;
  }

  function sha256(text) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)).then(function (b) {
      return new Uint8Array(b);
    });
  }

  // --- keys ---------------------------------------------------------------
  function encodeSecret(bytes) {
    return bech32Encode('age-secret-key-', bytes).toUpperCase();
  }

  function encodePublic(bytes) {
    return bech32Encode('age', bytes);
  }

  // generate makes a new X25519 key pair (WebCrypto) and returns the age
  // strings.
  function generate() {
    return crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']).then(function (pair) {
      return crypto.subtle.exportKey('jwk', pair.privateKey);
    }).then(function (jwk) {
      return { secret: encodeSecret(b64urlToBytes(jwk.d)), public: encodePublic(b64urlToBytes(jwk.x)) };
    });
  }

  var PKCS8_PREFIX = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20];

  // publicOf derives the public key of an AGE-SECRET-KEY-1 string.
  function publicOf(secret) {
    var dec = bech32Decode(secret);
    if (!dec || dec.hrp !== 'age-secret-key-' || dec.bytes.length !== 32) return Promise.reject(new Error('bad key'));
    var der = new Uint8Array(PKCS8_PREFIX.length + 32);
    der.set(PKCS8_PREFIX);
    der.set(dec.bytes, PKCS8_PREFIX.length);
    return crypto.subtle.importKey('pkcs8', der, { name: 'X25519' }, true, ['deriveBits']).then(function (k) {
      return crypto.subtle.exportKey('jwk', k);
    }).then(function (jwk) {
      return encodePublic(b64urlToBytes(jwk.x));
    });
  }

  function confirmCode(secret) {
    return sha256('hangar-kit-confirm-v1\n' + secret).then(function (sum) {
      var c = base32(sum).slice(0, 12);
      return c.slice(0, 4) + '-' + c.slice(4, 8) + '-' + c.slice(8, 12);
    });
  }

  function normalizeCode(code) {
    return code.toUpperCase().replace(/[^A-Z2-7]/g, '');
  }

  function codeHash(code) {
    return sha256('hangar-kit-code-v1\n' + normalizeCode(code)).then(hex);
  }

  // findSecret returns the first AGE-SECRET-KEY-1 line of a kit file.
  function findSecret(text) {
    var lines = text.replace(/\r\n/g, '\n').split('\n');
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i].trim();
      if (l.indexOf('AGE-SECRET-KEY-1') === 0) return l;
    }
    return '';
  }

  // kitText fills the localized template; every template line becomes a
  // comment, and the private key goes last on its own line.
  function kitText(template, fields, secret) {
    var body = template.replace(/\{(\w+)\}/g, function (m, k) { return k in fields ? fields[k] : m; });
    var out = body.split('\n').map(function (l) { return l === '' ? '#' : '# ' + l; });
    out.push(secret, '');
    return out.join('\n');
  }

  return {
    bech32Encode: bech32Encode, bech32Decode: bech32Decode, encodeSecret: encodeSecret, encodePublic: encodePublic,
    generate: generate, publicOf: publicOf, confirmCode: confirmCode, codeHash: codeHash,
    findSecret: findSecret, kitText: kitText, normalizeCode: normalizeCode
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = HangarKit;
}

// --- page behaviour -------------------------------------------------------
(function () {
  if (typeof document === 'undefined') return;
  var app = document.getElementById('kit-app');
  if (!app) return;
  var K = HangarKit;
  var t = app.dataset;
  var state = null; // { secret, public, code } — memory only

  function $(sel) { return app.querySelector(sel); }
  function show(el, on) { if (el) el.hidden = !on; }
  function fail(msg) {
    var e = $('#kit-error');
    if (e) { e.querySelector('[data-kit-error-text]').textContent = msg; show(e, true); }
  }

  function drawQR(target, text) {
    if (!window.qrcode || !target) return;
    var qr = window.qrcode(0, 'M');
    qr.addData(text, 'Alphanumeric');
    qr.make();
    var n = qr.getModuleCount(), ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + (n + 8) + ' ' + (n + 8));
    svg.setAttribute('class', 'kit-qr');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', t.qrLabel || '');
    var bg = document.createElementNS(ns, 'rect');
    bg.setAttribute('width', n + 8);
    bg.setAttribute('height', n + 8);
    bg.setAttribute('class', 'kit-qr-bg');
    svg.appendChild(bg);
    var d = '';
    for (var r = 0; r < n; r++) for (var c = 0; c < n; c++) if (qr.isDark(r, c)) d += 'M' + (c + 4) + ' ' + (r + 4) + 'h1v1h-1z';
    var p = document.createElementNS(ns, 'path');
    p.setAttribute('d', d);
    p.setAttribute('class', 'kit-qr-dark');
    svg.appendChild(p);
    target.replaceChildren(svg);
  }

  var gen = $('[data-kit-generate]');
  if (gen) gen.addEventListener('click', function () {
    if (!window.crypto || !crypto.subtle) { fail(t.errorCrypto); return; }
    gen.disabled = true;
    var label = ($('#kit-label').value || '').trim() || t.defaultLabel;
    K.generate().then(function (keys) {
      state = keys;
      return K.confirmCode(keys.secret);
    }).then(function (code) {
      state.code = code;
      return K.codeHash(code);
    }).then(function (h) {
      var date = new Date().toLocaleString(t.locale || undefined);
      state.text = K.kitText(t.template, { label: label, date: date, public: state.public, code: state.code }, state.secret);
      $('#kit-public').textContent = state.public;
      $('#kit-paper-text').textContent = state.text;
      $('#kit-paper-label').textContent = label;
      $('#kit-paper-date').textContent = date;
      $('#kit-paper-code').textContent = state.code;
      $('#kit-paper-public').textContent = state.public;
      // The prefix whole, then groups of four, so the key can be read and
      // typed back by hand (the spaces are only for reading).
      var pre = 'AGE-SECRET-KEY-1';
      var sec = state.secret.indexOf(pre) === 0 ? state.secret.slice(pre.length) : state.secret;
      $('#kit-paper-secret').textContent = (state.secret.indexOf(pre) === 0 ? pre + ' ' : '') + sec.replace(/(.{4})/g, '$1 ').trim();
      drawQR($('#kit-paper-qr'), state.secret);
      $('#kit-form-label').value = label;
      $('#kit-form-public').value = state.public;
      $('#kit-form-hash').value = h;
      show($('#kit-out'), true);
      show($('#kit-start'), false);
    }).catch(function () {
      gen.disabled = false;
      fail(t.errorCrypto);
    });
  });

  var saved = { file: false, check: false };
  function updateRegister() {
    var btn = $('#kit-register-btn');
    if (btn) btn.disabled = !(saved.file && saved.check);
  }

  var dl = $('[data-kit-download]');
  if (dl) dl.addEventListener('click', function () {
    if (!state) return;
    var url = URL.createObjectURL(new Blob([state.text], { type: 'text/plain' }));
    var a = document.createElement('a');
    a.href = url;
    a.download = 'hangar-kit.txt';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    saved.file = true;
    updateRegister();
  });

  // On print, the sheet becomes the page's only content: it moves to the
  // end of <body> and everything else is left out (CSS, html.printing-kit),
  // so it is not squeezed into the panel's layout and no blank page follows.
  // Ctrl+P works the same as the button; afterwards it goes back.
  var paper = $('.kit-paper');
  var paperHome = paper && paper.parentNode;
  window.addEventListener('beforeprint', function () {
    if (!paper || !state) return;
    document.body.appendChild(paper);
    document.documentElement.classList.add('printing-kit');
  });
  window.addEventListener('afterprint', function () {
    if (!paper || paper.parentNode === paperHome) return;
    paperHome.appendChild(paper);
    document.documentElement.classList.remove('printing-kit');
  });

  var pr = $('[data-kit-print]');
  if (pr) pr.addEventListener('click', function () {
    window.print();
    saved.file = true;
    updateRegister();
  });

  var chk = $('#kit-saved');
  if (chk) chk.addEventListener('change', function () {
    saved.check = chk.checked;
    updateRegister();
  });

  // When the form leaves, the private key must go with nothing: clear it.
  var reg = $('#kit-register');
  if (reg) reg.addEventListener('submit', function () {
    state = null;
    ['#kit-paper-text', '#kit-paper-secret', '#kit-paper-code', '#kit-paper-public'].forEach(function (s) { $(s).textContent = ''; });
    $('#kit-paper-qr').replaceChildren();
  });

  // Confirmation: the kit file is read here, locally; only the code goes.
  // The picker is Tucano's upload: a file chosen or dropped arrives in its
  // tucano:change event; a plain change covers it without Tucano.
  document.querySelectorAll('[data-kit-file]').forEach(function (input) {
    function picked(f) {
      var form = input.closest('form');
      var msg = form.querySelector('[data-kit-file-msg]');
      if (!f) return;
      if (f.size > 64 * 1024) { msg.textContent = t.noKey; return; }
      f.text().then(function (text) {
        var secret = K.findSecret(text);
        if (!secret) throw new Error('nokey');
        return K.publicOf(secret).then(function (pub) {
          if (pub !== input.dataset.public) throw new Error('mismatch');
          return K.confirmCode(secret);
        }, function () {
          return K.confirmCode(secret); // no X25519 import here: the server still checks the code
        });
      }).then(function (code) {
        form.querySelector('input[name="code"]').value = code;
        msg.textContent = t.fileOk;
      }).catch(function (e) {
        msg.textContent = e && e.message === 'mismatch' ? t.mismatch : t.noKey;
      });
    }
    input.addEventListener('tucano:change', function (ev) {
      var files = (ev.detail && ev.detail.files) || [];
      picked(files.length ? files[files.length - 1].file : null);
    });
    input.addEventListener('change', function () {
      if (!input.hasAttribute('data-tuc-ready')) picked(input.files && input.files[0]);
    });
  });
})();
