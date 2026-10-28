/* Premium access gate — shared by index.html and premium.html
   The access code is never stored here, only a salted PBKDF2-SHA256 hash. */
(function () {
  var SALT = "5bf75bdccee59e839a9b348e82ae0777";
  var HASH = "b00cbf27be66be50edc1c99cf0f1917dbc9bf4ebe44659a056976a972e5293b6";
  var ITER = 200000;
  var KEY  = "sr_premium_v1";

  function hexToBytes(h) {
    var out = new Uint8Array(h.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToHex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) {
      return ("0" + b.toString(16)).slice(-2);
    }).join("");
  }
  function derive(code) {
    var enc = new TextEncoder();
    return crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"])
      .then(function (k) {
        return crypto.subtle.deriveBits(
          { name: "PBKDF2", salt: hexToBytes(SALT), iterations: ITER, hash: "SHA-256" }, k, 256);
      })
      .then(bytesToHex);
  }
  function read()  { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function write(v){ try { localStorage.setItem(KEY, v); } catch (e) {} }

  window.Premium = {
    isUnlocked: function () { return read() === HASH; },
    unlock: function (code) {
      if (!window.crypto || !crypto.subtle) return Promise.reject(new Error("insecure-context"));
      return derive(String(code || "").trim()).then(function (h) {
        if (h === HASH) { write(HASH); return true; }
        return false;
      });
    },
    lock: function () { try { localStorage.removeItem(KEY); } catch (e) {} }
  };
})();
