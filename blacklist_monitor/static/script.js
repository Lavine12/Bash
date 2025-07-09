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
  const hourly = document.getElementById(prefix + '-hourly');
  const hidden = document.getElementById(prefix + '-type');
  const weeklyWrap = document.getElementById(prefix + '-day-weekly');
  const monthlyWrap = document.getElementById(prefix + '-day-monthly');
  const ampmSel = document.getElementById(prefix + '-ampm');
  const timeLabel = document.getElementById(prefix + '-time-label');
  const hoursWord = document.getElementById(prefix + '-hours-word');
  const minutesWord = document.getElementById(prefix + '-minutes-word');

  if (hidden) {
    if (hourly && hourly.checked) hidden.value = 'hourly';
    else if (daily && daily.checked) hidden.value = 'daily';
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

  if (ampmSel) {
    const show = !(hourly && hourly.checked);
    ampmSel.style.display = show ? '' : 'none';
    ampmSel.disabled = !show;
  }

  if (timeLabel) {
    if (hourly && hourly.checked) {
      timeLabel.textContent = 'Per';
    } else {
      timeLabel.textContent = 'Time:';
    }
  }
  const showWords = hourly && hourly.checked;
  if (hoursWord) hoursWord.style.display = showWords ? '' : 'none';
  if (minutesWord) minutesWord.style.display = showWords ? '' : 'none';
}

function selectType(prefix, type) {
  const daily = document.getElementById(prefix + '-daily');
  const weekly = document.getElementById(prefix + '-weekly');
  const monthly = document.getElementById(prefix + '-monthly');
  const hourly = document.getElementById(prefix + '-hourly');

  if (type === 'hourly') {
    if (hourly) hourly.checked = true;
    if (daily) daily.checked = false;
    if (weekly) weekly.checked = false;
    if (monthly) monthly.checked = false;
  } else if (type === 'daily') {
    if (daily) daily.checked = true;
    if (weekly) weekly.checked = false;
    if (monthly) monthly.checked = false;
    if (hourly) hourly.checked = false;
  } else if (type === 'weekly') {
    if (daily) daily.checked = false;
    if (weekly) weekly.checked = true;
    if (monthly) monthly.checked = false;
    if (hourly) hourly.checked = false;
  } else if (type === 'monthly') {
    if (daily) daily.checked = false;
    if (weekly) weekly.checked = false;
    if (monthly) monthly.checked = true;
    if (hourly) hourly.checked = false;
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
    let logTimer;
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
    function startLogs() {
      fetchLogs();
      logTimer = setInterval(fetchLogs, 2000);
    }
    function stopLogs() {
      if (logTimer) {
        clearInterval(logTimer);
        logTimer = null;
      }
    }
    const toggle = document.getElementById('log-toggle');
    if (toggle) {
      toggle.addEventListener('click', function() {
        if (logTimer) {
          stopLogs();
          this.textContent = 'Resume';
        } else {
          startLogs();
          this.textContent = 'Stop';
        }
      });
    }
    startLogs();
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

  document.querySelectorAll('.checkbox-dropdown').forEach(function(dd) {
    var btn = dd.querySelector('button');
    var menu = dd.querySelector('.checkbox-dropdown-menu');
    function updateText() {
      var checked = menu.querySelectorAll('input[type="checkbox"]:checked');
      if (checked.length === 0) {
        btn.textContent = 'Select';
      } else {
        var names = Array.from(checked).map(function(cb){
          return cb.parentNode.textContent.trim();
        });
        btn.textContent = names.join(', ');
      }
    }
    btn.addEventListener('click', function(e) {
      e.preventDefault();
      menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
    });
    menu.querySelectorAll('input[type="checkbox"]').forEach(function(cb) {
      cb.addEventListener('change', updateText);
    });
    updateText();
  });

  document.querySelectorAll('.dropdown-details').forEach(function(dd) {
    var summary = dd.querySelector('summary');
    function updateText() {
      var checked = dd.querySelectorAll('input[type="checkbox"]:checked');
      if (checked.length === 0) {
        summary.textContent = 'Select';
      } else {
        var names = Array.from(checked).map(function(cb){
          return cb.parentNode.textContent.trim();
        });
        summary.textContent = names.join(', ');
      }
    }
    dd.addEventListener('toggle', updateText);
    dd.querySelectorAll('input[type="checkbox"]').forEach(function(cb) {
      cb.addEventListener('change', updateText);
    });
    updateText();
  });

  // Persist dig test fields across visits
  document.querySelectorAll('input[name^="dig_ip_"],
                           input[name^="dig_server_"],
                           input[name^="dig_arg_"]').forEach(function(inp) {
    var key = 'cache_' + inp.name;
    var saved = localStorage.getItem(key);
    if (!inp.value && saved) {
      inp.value = saved;
    } else if (inp.value) {
      localStorage.setItem(key, inp.value);
    }
    inp.addEventListener('input', function() {
      localStorage.setItem(key, this.value);
    });
  });
});
