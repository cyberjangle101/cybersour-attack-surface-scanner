// Tiny progressive enhancement; the UI works without it (CSP forbids inline script).
document.addEventListener('submit', function (e) {
  const msg = e.target.getAttribute && e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) { e.preventDefault(); }
});
document.addEventListener('click', function (e) {
  if (e.target && e.target.hasAttribute && e.target.hasAttribute('data-print')) { window.print(); }
});
// Long-running actions (e.g. connection checks): show progress and prevent double submits.
document.addEventListener('submit', function (e) {
  if (e.defaultPrevented) { return; }
  const btn = e.target.querySelector && e.target.querySelector('button[data-busy]');
  if (btn) {
    const label = btn.getAttribute('data-busy');
    setTimeout(function () { btn.disabled = true; btn.textContent = label; }, 0);
  }
});

// Live scan progress: poll /progress.json and update any bars on the page.
(function () {
  const bars = function () { return document.querySelectorAll('[data-prog]'); };
  if (!bars().length || !window.fetch) { return; }
  const set = function (el, k, v) { const n = el.querySelector('[data-p="' + k + '"]'); if (n) { n.textContent = v; } };
  const tick = function () {
    fetch('/progress.json', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (list) {
        if (!list) { return; }
        const seen = {};
        list.forEach(function (p) { seen[p.id] = p; });
        let finished = false;
        bars().forEach(function (el) {
          const p = seen[el.getAttribute('data-prog')];
          if (!p) { finished = true; return; }
          el.querySelector('progress').value = p.percent;
          set(el, 'pct', p.percent + '%');
          set(el, 'mode', p.active ? 'Active checks · ' : '');
          set(el, 'stage', p.stage);
          set(el, 'detail', p.detail ? ' \u00b7 ' + p.detail : '');
          set(el, 'stall', p.idle > 90 ? ' \u00b7 no progress for ' + p.idle + 's (a source is slow; it will time out and continue)' : '');
        });
        if (finished) { window.location.reload(); }
      })
      .catch(function () {});
  };
  setInterval(tick, 2000);
})();

// Settings: choose a file to fill a text box (certificate and key upload).
document.addEventListener('change', function (e) {
  const inp = e.target;
  if (!inp || !inp.hasAttribute || !inp.hasAttribute('data-fill') || !inp.files || !inp.files[0]) { return; }
  const box = document.getElementById(inp.getAttribute('data-fill'));
  if (!box || inp.files[0].size > 200000) { return; }
  const rd = new FileReader();
  rd.onload = function () { box.value = String(rd.result); };
  rd.readAsText(inp.files[0]);
});

// First-administrator setup: the agent opens /setup#code=... on the computer it was
// started on. The fragment never reaches the server or its logs; it is copied into the
// field and removed from the address bar (and so from the history entry).
(function () {
  const fill = function () {
    const box = document.getElementById('setup-code');
    const m = /^#code=([A-Za-z0-9-]{1,40})$/.exec(window.location.hash);
    if (!box || !m) { return; }
    box.value = m[1];
    if (window.history && window.history.replaceState) { window.history.replaceState(null, '', window.location.pathname); }
  };
  if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', fill); } else { fill(); }
})();