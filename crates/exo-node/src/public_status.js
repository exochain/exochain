(function() {
  'use strict';
  var PROBE_TIMEOUT_MS = 5000;
  async function show(path, elementId) {
    var el = document.getElementById(elementId);
    var controller = new AbortController();
    var timer = setTimeout(function() { controller.abort(); }, PROBE_TIMEOUT_MS);
    try {
      var resp = await fetch(path, { signal: controller.signal });
      var body = await resp.text();
      el.textContent = 'HTTP ' + resp.status + '\n' + body;
    } catch (err) {
      el.textContent = 'unreachable: ' + (err && err.message ? err.message : 'fetch failed');
    } finally {
      clearTimeout(timer);
    }
  }
  show('/health', 'health-probe');
  show('/ready', 'ready-probe');
})();
