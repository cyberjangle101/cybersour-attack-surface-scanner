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
