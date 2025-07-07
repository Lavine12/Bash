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

function updateScheduleDisplay(prefix) {
  const daily = document.getElementById(prefix + '-daily');
  const weekly = document.getElementById(prefix + '-weekly');
  const monthly = document.getElementById(prefix + '-monthly');
  const hidden = document.getElementById(prefix + '-type');
  const weeklyWrap = document.getElementById(prefix + '-day-weekly');
  const monthlyWrap = document.getElementById(prefix + '-day-monthly');

  if (hidden) {
    if (daily && daily.checked) hidden.value = 'daily';
    else if (weekly && weekly.checked) hidden.value = 'weekly';
    else if (monthly && monthly.checked) hidden.value = 'monthly';
    else hidden.value = '';
  }

  if (weeklyWrap) {
    const show = weekly && weekly.checked;
    weeklyWrap.style.display = show ? '' : 'none';
    const sel = weeklyWrap.querySelector('select');
    if (sel) {
      sel.disabled = !show;
      // remove highlight color for weekly day dropdown
      sel.classList.remove('active');
    }
  }

  if (monthlyWrap) {
    const show = monthly && monthly.checked;
    monthlyWrap.style.display = show ? '' : 'none';
    const inp = monthlyWrap.querySelector('input');
    if (inp) inp.disabled = !show;
  }
}

function selectType(prefix, type) {
  const daily = document.getElementById(prefix + '-daily');
  const weekly = document.getElementById(prefix + '-weekly');
  const monthly = document.getElementById(prefix + '-monthly');

  if (type === 'daily') {
    if (daily) daily.checked = true;
    if (weekly) weekly.checked = false;
    if (monthly) monthly.checked = false;
  } else if (type === 'weekly') {
    if (daily) daily.checked = false;
    if (weekly) weekly.checked = true;
    if (monthly) monthly.checked = false;
  } else if (type === 'monthly') {
    if (daily) daily.checked = false;
    if (weekly) weekly.checked = false;
    if (monthly) monthly.checked = true;
  }
  updateScheduleDisplay(prefix);
}

window.addEventListener('load', function() {
  updateScheduleDisplay('schedule');
  document.querySelectorAll('.schedule-row').forEach(function(row) {
    const id = row.dataset.rowId;
    updateScheduleDisplay('row-' + id);
  });
  document.querySelectorAll('[id$="-day-monthly"] input').forEach(function(inp) {
    const key = 'cache_' + inp.name;
    const saved = localStorage.getItem(key);
    if (!inp.value && saved) {
      inp.value = saved;
    }
    inp.addEventListener('change', function() {
      localStorage.setItem(key, this.value);
    });
  });

  if (document.getElementById('log-output')) {
    function fetchLogs() {
      fetch('/log_feed').then(function(r) { return r.text(); }).then(function(t) {
        const pre = document.getElementById('log-output');
        if (pre) {
          const oldScroll = pre.scrollTop;
          const oldHeight = pre.scrollHeight;
          const atBottom = oldScroll + pre.clientHeight >= oldHeight - 20;
          pre.textContent = t;
          if (atBottom) {
            pre.scrollTop = pre.scrollHeight;
          } else {
            pre.scrollTop = oldScroll;
          }
        }
      });
    }
    fetchLogs();
    setInterval(fetchLogs, 2000);
  }

  if (document.getElementById('system-stats')) {
    function fetchStats() {
      fetch('/stats')
        .then(function(r) { return r.json(); })
        .then(function(d) {
          var el = document.getElementById('system-stats');
          if (el) {
            el.textContent = 'load: ' + d.load + '  cpu: ' + d.cpu + '%  mem: ' + d.mem + '%  disk: ' + d.disk + '%';
          }
        });
    }
    fetchStats();
    setInterval(fetchStats, 2000);
  }
});
