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

function updateScheduleInputs() {
  const type = document.getElementById('schedule-type');
  if (!type) return;
  const weekly = document.getElementById('day-weekly');
  const monthly = document.getElementById('day-monthly');
  if (weekly) weekly.style.display = 'none';
  if (monthly) monthly.style.display = 'none';
  if (type.value === 'weekly') {
    if (weekly) weekly.style.display = '';
    if (weekly) weekly.querySelector('select').disabled = false;
    if (monthly) monthly.querySelector('input').disabled = true;
  } else if (type.value === 'monthly') {
    if (monthly) monthly.style.display = '';
    if (monthly) monthly.querySelector('input').disabled = false;
    if (weekly) weekly.querySelector('select').disabled = true;
  } else {
    if (weekly) weekly.querySelector('select').disabled = true;
    if (monthly) monthly.querySelector('input').disabled = true;
  }
}

window.addEventListener('load', updateScheduleInputs);
