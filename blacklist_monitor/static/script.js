function toggle(id) {
  const el = document.getElementById(id);
  if (!el) return;
  const style = el.style.display === 'none' ? '' : 'none';
  el.style.display = style;
  try {
    localStorage.setItem('collapse_' + id, style);
  } catch (e) {}
}

function restoreCollapse() {
  document.querySelectorAll('[data-collapse]').forEach(function(el) {
    const s = localStorage.getItem('collapse_' + el.id);
    if (s !== null) {
      el.style.display = s;
    }
  });
}

function toggleAll(src) {
  const tbl = src.closest('table');
  if (!tbl) return;
  tbl.querySelectorAll('input[type="checkbox"]').forEach(function(cb) {
    if (cb !== src) cb.checked = src.checked;
  });
}

window.addEventListener('load', restoreCollapse);
