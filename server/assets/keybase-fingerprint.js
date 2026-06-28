(function () {
  "use strict";

  var startedAt = Date.now();
  var moves = [];
  var clicks = [];

  document.addEventListener("mousemove", function (event) {
    if (moves.length < 80) moves.push([event.clientX, event.clientY, Date.now()]);
  }, { passive: true });

  document.addEventListener("click", function () {
    if (clicks.length < 40) clicks.push(Date.now());
  }, { passive: true });

  function hashString(value) {
    var hash = 2166136261;
    for (var index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    return (hash >>> 0).toString(16);
  }

  function canvasFingerprint() {
    try {
      var canvas = document.createElement("canvas");
      canvas.width = 280;
      canvas.height = 80;
      var ctx = canvas.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "16px Arial";
      ctx.fillStyle = "#f60";
      ctx.fillRect(10, 10, 120, 40);
      ctx.fillStyle = "#069";
      ctx.fillText("KeyBase fingerprint 123", 14, 16);
      ctx.globalCompositeOperation = "multiply";
      ctx.fillStyle = "rgba(60,120,200,.65)";
      ctx.beginPath();
      ctx.arc(80, 40, 22, 0, Math.PI * 2, true);
      ctx.fill();
      return hashString(canvas.toDataURL());
    } catch (error) {
      return "";
    }
  }

  function webglInfo() {
    try {
      var canvas = document.createElement("canvas");
      var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return {};
      var debug = gl.getExtension("WEBGL_debug_renderer_info");
      return {
        webglVendor: debug ? gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        webglRenderer: debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER)
      };
    } catch (error) {
      return {};
    }
  }

  function audioFingerprint() {
    return new Promise(function (resolve) {
      try {
        var AudioContext = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!AudioContext) {
          resolve("");
          return;
        }
        var context = new AudioContext(1, 44100, 44100);
        var oscillator = context.createOscillator();
        var compressor = context.createDynamicsCompressor();
        oscillator.type = "triangle";
        oscillator.frequency.value = 10000;
        compressor.threshold.value = -50;
        compressor.knee.value = 40;
        compressor.ratio.value = 12;
        compressor.attack.value = 0;
        compressor.release.value = 0.25;
        oscillator.connect(compressor);
        compressor.connect(context.destination);
        oscillator.start(0);
        context.startRendering().then(function (buffer) {
          var sample = Array.prototype.slice.call(buffer.getChannelData(0), 4500, 5000).join(",");
          resolve(hashString(sample));
        }).catch(function () { resolve(""); });
      } catch (error) {
        resolve("");
      }
    });
  }

  function fontList() {
    var baseFonts = ["monospace", "sans-serif", "serif"];
    var candidates = ["Arial", "Calibri", "Cambria", "Consolas", "Courier New", "Georgia", "Segoe UI", "Tahoma", "Times New Roman", "Verdana"];
    var text = "mmmmmmmmmmlli";
    var size = "72px";
    var base = {};
    var detected = {};

    baseFonts.forEach(function (font) {
      var span = document.createElement("span");
      span.style.cssText = "position:absolute;left:-9999px;font-size:" + size + ";font-family:" + font;
      span.textContent = text;
      document.body.appendChild(span);
      base[font] = [span.offsetWidth, span.offsetHeight];
      document.body.removeChild(span);
    });

    candidates.forEach(function (candidate) {
      baseFonts.forEach(function (baseFont) {
        var span = document.createElement("span");
        span.style.cssText = "position:absolute;left:-9999px;font-size:" + size + ";font-family:'" + candidate + "'," + baseFont;
        span.textContent = text;
        document.body.appendChild(span);
        if (span.offsetWidth !== base[baseFont][0] || span.offsetHeight !== base[baseFont][1]) detected[candidate] = true;
        document.body.removeChild(span);
      });
    });
    return Object.keys(detected);
  }

  function mouseEntropy() {
    if (moves.length < 4) return 0;
    var buckets = {};
    for (var index = 1; index < moves.length; index += 1) {
      var dx = moves[index][0] - moves[index - 1][0];
      var dy = moves[index][1] - moves[index - 1][1];
      var bucket = Math.round(Math.atan2(dy, dx) * 4);
      buckets[bucket] = (buckets[bucket] || 0) + 1;
    }
    var total = moves.length - 1;
    var entropy = 0;
    Object.keys(buckets).forEach(function (key) {
      var p = buckets[key] / total;
      entropy -= p * Math.log2(p);
    });
    return entropy / 4;
  }

  function automationFlags() {
    return Boolean(
      navigator.webdriver ||
      window.__nightmare ||
      window.callPhantom ||
      window._phantom ||
      window.domAutomation ||
      window.domAutomationController
    );
  }

  function headlessFlags() {
    return /HeadlessChrome|PhantomJS|SlimerJS/i.test(navigator.userAgent || "") || navigator.plugins.length === 0;
  }

  function collectFingerprint() {
    var gl = webglInfo();
    return audioFingerprint().then(function (audio) {
      return {
        canvas: canvasFingerprint(),
        audio: audio,
        webglVendor: gl.webglVendor || "",
        webglRenderer: gl.webglRenderer || "",
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
        language: navigator.language || "",
        languages: navigator.languages || [],
        screen: {
          width: screen.width,
          height: screen.height,
          colorDepth: screen.colorDepth,
          pixelRatio: window.devicePixelRatio || 1
        },
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        touch: ("ontouchstart" in window) || navigator.maxTouchPoints > 0,
        fonts: fontList(),
        automation: automationFlags(),
        webdriver: Boolean(navigator.webdriver),
        headless: headlessFlags(),
        behavior: {
          dwellMs: Date.now() - startedAt,
          mouseMoves: moves.length,
          mouseEntropy: mouseEntropy(),
          clicks: clicks.length,
          clickIntervals: clicks.slice(1).map(function (time, index) { return time - clicks[index]; })
        }
      };
    });
  }

  window.KeyBaseFingerprint = { collect: collectFingerprint };
}());
