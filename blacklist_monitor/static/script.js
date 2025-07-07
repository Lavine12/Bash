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

function handleScheduleInputs(typeId, weeklyId, monthlyId) {
  const type = document.getElementById(typeId);
  if (!type) return;
  const weekly = document.getElementById(weeklyId);
  const monthly = document.getElementById(monthlyId);
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

function updateScheduleInputs() {
  handleScheduleInputs('schedule-type', 'day-weekly', 'day-monthly');
}

function updateRowScheduleInputs(id) {
  handleScheduleInputs('row-' + id + '-type', 'row-' + id + '-day-weekly', 'row-' + id + '-day-monthly');
}

window.addEventListener('load', function() {
  updateScheduleInputs();
  document.querySelectorAll('.schedule-type-row').forEach(function(el) {
    const id = el.dataset.rowId;
    updateRowScheduleInputs(id);
  });
});
