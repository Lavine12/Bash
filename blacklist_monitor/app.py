import os
import re
import sqlite3
import requests
from flask import Flask, render_template, request, redirect, url_for
from apscheduler.schedulers.background import BackgroundScheduler
import ipaddress
import dns.resolver
import datetime
import logging
from collections import deque
import subprocess

DB_PATH = os.path.join(os.path.dirname(__file__), 'data.db')
DB_TIMEOUT = 30  # seconds
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

app = Flask(__name__)
CHECK_INTERVAL_MINUTES = int(float(os.environ.get('CHECK_INTERVAL_HOURS', '0')) * 60)
sched = BackgroundScheduler()

# Keep recent logs for display in the web interface
log_history = deque(maxlen=200)


class MemoryLogHandler(logging.Handler):
    """Collect log records in memory."""
    def emit(self, record):
        msg = self.format(record)
        if "GET /log_feed" in msg:
            return
        # remove ANSI color codes
        msg = re.sub(r"\x1b\[[0-9;]*m", "", msg)
        log_history.append(msg)


log_handler = MemoryLogHandler()
log_handler.setFormatter(logging.Formatter('%(message)s'))
logging.getLogger('werkzeug').addHandler(log_handler)
logging.getLogger('werkzeug').setLevel(logging.INFO)


def get_setting(key, default=''):
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        row = c.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return row[0] if row else default


def set_setting(key, value):
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()


def init_db():
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS ip_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            last_checked TEXT,
            group_id INTEGER,
            excluded INTEGER DEFAULT 0,
            remark TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS dnsbls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS ip_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS check_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_id INTEGER,
            dnsbl_id INTEGER,
            listed INTEGER,
            checked_at TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS telegram_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT,
            chat_id TEXT,
            name TEXT,
            active INTEGER DEFAULT 1,
            alert_message TEXT,
            resend_period INTEGER
        )''')
        c.execute("""CREATE TABLE IF NOT EXISTS group_chats (
            group_id INTEGER,
            chat_id INTEGER,
            PRIMARY KEY (group_id, chat_id)
        )""")
        c.execute('''CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            status TEXT,
            error TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS backup_check_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_id INTEGER,
            ip_id INTEGER,
            dnsbl_id INTEGER,
            listed INTEGER,
            checked_at TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS backup_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER,
            type TEXT,
            day TEXT,
            hour INTEGER,
            minute INTEGER,
            date_full TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS check_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER,
            type TEXT,
            day TEXT,
            hour INTEGER,
            minute INTEGER,
            date_full TEXT
        )''')
        try:
            c.execute('ALTER TABLE check_schedules ADD COLUMN date_full TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            c.execute('ALTER TABLE backup_schedules ADD COLUMN date_full TEXT')
        except sqlite3.OperationalError:
            pass
        # ensure upgrade columns exist
        try:
            c.execute('ALTER TABLE ip_addresses ADD COLUMN group_id INTEGER')
        except sqlite3.OperationalError:
            pass
        try:
            c.execute('ALTER TABLE ip_addresses ADD COLUMN excluded INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        try:
            c.execute('ALTER TABLE ip_addresses ADD COLUMN remark TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            c.execute('ALTER TABLE telegram_chats ADD COLUMN alert_message TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            c.execute('ALTER TABLE telegram_chats ADD COLUMN resend_period INTEGER')
        except sqlite3.OperationalError:
            pass
        try:
            c.execute('ALTER TABLE telegram_chats ADD COLUMN name TEXT')
        except sqlite3.OperationalError:
            pass
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('RESEND_PERIODIC', '1'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('RESEND_TIMES', '0'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_RETENTION_DAYS', '0'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_KEEP_COUNT', '0'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_SCHEDULE_TYPE', ''))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_SCHEDULE_DAY', ''))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_SCHEDULE_HOUR', '0'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_SCHEDULE_MINUTE', '0'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('LOG_HISTORY_SIZE', '200'))
        if TELEGRAM_TOKEN:
            c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                      ('TELEGRAM_TOKEN', TELEGRAM_TOKEN))
        if TELEGRAM_CHAT_ID:
            c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                      ('TELEGRAM_CHAT_ID', TELEGRAM_CHAT_ID))
        conn.commit()


@app.route('/')

def index():
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        ips = c.execute('''SELECT id, ip, last_checked, group_id, excluded,
                                 (SELECT MAX(listed) FROM check_results
                                  WHERE ip_id=ip_addresses.id
                                  AND checked_at=ip_addresses.last_checked),
                                 remark
                          FROM ip_addresses''').fetchall()
        ip_count = len(ips)
        groups = c.execute('SELECT id, name FROM ip_groups').fetchall()
        dnsbl_map = {}
        for ip in ips:
            if not ip[2]:
                dnsbl_map[ip[0]] = []
            else:
                rows = c.execute('''SELECT dnsbls.domain FROM check_results
                                    JOIN dnsbls ON dnsbls.id=check_results.dnsbl_id
                                    WHERE check_results.ip_id=? AND check_results.checked_at=? AND check_results.listed=1''',
                                 (ip[0], ip[2])).fetchall()
                dnsbl_map[ip[0]] = [r[0] for r in rows]
        schedules = c.execute('SELECT id, group_id FROM check_schedules').fetchall()
        chat_rows = c.execute('''SELECT group_id, telegram_chats.name
                                 FROM group_chats JOIN telegram_chats
                                   ON telegram_chats.id = group_chats.chat_id''').fetchall()
        group_chats = {}
        for gid, cname in chat_rows:
            group_chats.setdefault(gid, []).append(cname)
    group_next = {}
    for sid, gid in schedules:
        job = sched.get_job(f'check_job_{sid}')
        if job and job.next_run_time:
            t = job.next_run_time
            if gid not in group_next or t < group_next[gid]:
                group_next[gid] = t
    group_next_map = {gid: t.strftime('%d/%m/%Y %I:%M %p').lower()
                       for gid, t in group_next.items() if t}
    return render_template("index.html", ips=ips, ip_count=ip_count,
                           groups=groups, dnsbl_map=dnsbl_map,
                           group_next=group_next_map, group_chats=group_chats)


@app.route('/ips', methods=['GET', 'POST'])
def manage_ips():
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            ip_range = request.form['ip']
            group_id = request.form.get('group_id') or None
            try:
                net = ipaddress.ip_network(ip_range, strict=False)
                for ip in net.hosts():
                    try:
                        c.execute('INSERT OR IGNORE INTO ip_addresses (ip, group_id, excluded, remark) VALUES (?, ?, 0, ?)', (str(ip), group_id, ''))
                        row = c.execute('SELECT id FROM ip_addresses WHERE ip=?', (str(ip),)).fetchone()
                        if row:
                            check_ip(row[0])
                    except sqlite3.IntegrityError:
                        pass
            except ValueError:
                pass
            conn.commit()
            return redirect(url_for('manage_ips'))
        ips = c.execute('SELECT id, ip, group_id, excluded FROM ip_addresses').fetchall()
        groups = c.execute('SELECT id, name FROM ip_groups').fetchall()
    return render_template('ips.html', ips=ips, groups=groups)


@app.route('/ips/bulk', methods=['POST'])
def bulk_ips():
    entries = request.form.get('ips_bulk', '')
    group_id = request.form.get('group_id') or None
    lines = [line.strip() for line in entries.splitlines()]
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for line in lines:
            if not line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                for ip in net.hosts():
                    c.execute('INSERT OR IGNORE INTO ip_addresses (ip, group_id, excluded, remark) VALUES (?, ?, 0, ?)', (str(ip), group_id, ''))
                    row = c.execute('SELECT id FROM ip_addresses WHERE ip=?', (str(ip),)).fetchone()
                    if row:
                        check_ip(row[0])
            except ValueError:
                pass
        conn.commit()
    return redirect(url_for('manage_ips'))


@app.route('/ips/delete/<int:ip_id>', methods=['POST'])
def delete_ip(ip_id):
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM ip_addresses WHERE id=?', (ip_id,))
        conn.commit()
    return redirect(url_for('manage_ips'))


@app.route('/ips/delete_selected', methods=['POST'])
def delete_selected_ips():
    ids = request.form.getlist('ip_id')
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for ip_id in ids:
            try:
                c.execute('DELETE FROM ip_addresses WHERE id=?', (ip_id,))
            except sqlite3.Error:
                pass
        conn.commit()
    return redirect(url_for('manage_ips'))


@app.route('/dnsbls', methods=['GET', 'POST'])
def manage_dnsbls():
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            domain = request.form['dnsbl']
            c.execute('INSERT OR IGNORE INTO dnsbls (domain) VALUES (?)', (domain,))
            conn.commit()
            check_blacklists()
            return redirect(url_for('manage_dnsbls'))
        dnsbls = c.execute('SELECT id, domain FROM dnsbls').fetchall()
    return render_template('dnsbls.html', dnsbls=dnsbls, dig_results=None)


@app.route('/dnsbls/bulk', methods=['POST'])
def bulk_dnsbls():
    entries = request.form.get('dnsbls_bulk', '')
    lines = [line.strip() for line in entries.splitlines()]
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for line in lines:
            if line:
                c.execute('INSERT OR IGNORE INTO dnsbls (domain) VALUES (?)', (line,))
        conn.commit()
    check_blacklists()
    return redirect(url_for('manage_dnsbls'))


@app.route('/dnsbls/delete/<int:dnsbl_id>', methods=['POST'])
def delete_dnsbl(dnsbl_id):
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM dnsbls WHERE id=?', (dnsbl_id,))
        conn.commit()
    return redirect(url_for('manage_dnsbls'))


@app.route('/dnsbls/delete_selected', methods=['POST'])
def delete_selected_dnsbls():
    ids = request.form.getlist('dnsbl_id')
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for dnsbl_id in ids:
            try:
                c.execute('DELETE FROM dnsbls WHERE id=?', (dnsbl_id,))
            except sqlite3.Error:
                pass
        conn.commit()
    return redirect(url_for('manage_dnsbls'))


@app.route('/dnsbls/dig_selected', methods=['POST'])
def dig_selected_dnsbls():
    ids = request.form.getlist('dnsbl_id')
    results = {}
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for did in ids:
            row = c.execute('SELECT domain FROM dnsbls WHERE id=?', (did,)).fetchone()
            if not row:
                continue
            domain = row[0]
            ip = request.form.get(f'dig_ip_{did}', '').strip()
            server = request.form.get(f'dig_server_{did}', '').strip()
            args = request.form.get(f'dig_arg_{did}', '')
            query = domain
            if ip:
                try:
                    rev = '.'.join(reversed(ip.split('.')))
                    query = f'{rev}.{domain}'
                except Exception:
                    pass
            cmd = ['dig', '+short', query]
            if server:
                cmd.append('@' + server)
            cmd += args.split()
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True, timeout=5)
                lines = [l for l in out.splitlines() if l.strip()]
                results[int(did)] = lines[-1] if lines else ''
            except Exception:
                results[int(did)] = 'error'
    dnsbls = c.execute('SELECT id, domain FROM dnsbls').fetchall()
    return render_template('dnsbls.html', dnsbls=dnsbls, dig_results=results)


@app.route('/groups', methods=['GET', 'POST'])
def manage_groups():
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            name = request.form['group']
            chat_ids = [cid for cid in request.form.getlist('add_chats') if cid]
            c.execute('INSERT OR IGNORE INTO ip_groups (name) VALUES (?)', (name,))
            gid = c.execute('SELECT id FROM ip_groups WHERE name=?', (name,)).fetchone()[0]
            c.execute('DELETE FROM group_chats WHERE group_id=?', (gid,))
            for cid in chat_ids:
                c.execute('INSERT OR IGNORE INTO group_chats (group_id, chat_id) VALUES (?, ?)', (gid, cid))
            conn.commit()
            return redirect(url_for('manage_groups'))
        groups = c.execute('SELECT id, name FROM ip_groups').fetchall()
        chats = c.execute('SELECT id, name FROM telegram_chats').fetchall()
        chat_map_rows = c.execute('SELECT group_id, chat_id FROM group_chats').fetchall()
        group_chat_map = {}
        for gid, cid in chat_map_rows:
            group_chat_map.setdefault(gid, []).append(cid)
    return render_template('groups.html', groups=groups, chats=chats, group_chats=group_chat_map)


@app.route('/groups/delete/<int:group_id>', methods=['POST'])
def delete_group(group_id):
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM ip_groups WHERE id=?', (group_id,))
        c.execute('DELETE FROM group_chats WHERE group_id=?', (group_id,))
        c.execute('UPDATE ip_addresses SET group_id=NULL WHERE group_id=?', (group_id,))
        conn.commit()
    return redirect(url_for('manage_groups'))


@app.route('/groups/update/<int:group_id>', methods=['POST'])
def update_group(group_id):
    new_name = request.form.get('group_name', '').strip()
    chat_ids = [cid for cid in request.form.getlist('chats') if cid]
    if new_name:
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute('UPDATE ip_groups SET name=? WHERE id=?', (new_name, group_id))
            c.execute('DELETE FROM group_chats WHERE group_id=?', (group_id,))
            for cid in chat_ids:
                c.execute('INSERT OR IGNORE INTO group_chats (group_id, chat_id) VALUES (?, ?)', (group_id, cid))
            conn.commit()
    return redirect(url_for('manage_groups'))


@app.route('/groups/update_selected', methods=['POST'])
def update_selected_groups():
    ids = request.form.getlist('group_id')
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for gid in ids:
            name = request.form.get(f'group_name_{gid}', '').strip()
            if name:
                try:
                    c.execute('UPDATE ip_groups SET name=? WHERE id=?', (name, gid))
                except sqlite3.Error:
                    pass
            chat_ids = [cid for cid in request.form.getlist(f'chats_{gid}') if cid]
            c.execute('DELETE FROM group_chats WHERE group_id=?', (gid,))
            for cid in chat_ids:
                c.execute('INSERT OR IGNORE INTO group_chats (group_id, chat_id) VALUES (?, ?)', (gid, cid))
        conn.commit()
    return redirect(url_for('manage_groups'))


@app.route('/groups/delete_selected', methods=['POST'])
def delete_selected_groups():
    ids = request.form.getlist('group_id')
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for gid in ids:
            try:
                c.execute('DELETE FROM ip_groups WHERE id=?', (gid,))
                c.execute('DELETE FROM group_chats WHERE group_id=?', (gid,))
                c.execute('UPDATE ip_addresses SET group_id=NULL WHERE group_id=?', (gid,))
            except sqlite3.Error:
                pass
        conn.commit()
    return redirect(url_for('manage_groups'))


@app.route('/ips/set_group', methods=['POST'])
def set_group():
    group_id = request.form.get('group_id') or None
    ip_ids = request.form.getlist('ip_id')
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for ip_id in ip_ids:
            c.execute('UPDATE ip_addresses SET group_id=? WHERE id=?', (group_id, ip_id))
        conn.commit()
    return redirect(url_for('manage_ips'))


@app.route('/exclude_selected', methods=['POST'])
def exclude_selected():
    ids = request.form.getlist('ip_id')
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for ip_id in ids:
            try:
                c.execute('UPDATE ip_addresses SET excluded=1 WHERE id=?', (ip_id,))
            except sqlite3.Error:
                pass
        conn.commit()
    return redirect(url_for('index'))


@app.route('/include_selected', methods=['POST'])
def include_selected():
    ids = request.form.getlist('ip_id')
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for ip_id in ids:
            try:
                c.execute('UPDATE ip_addresses SET excluded=0 WHERE id=?', (ip_id,))
            except sqlite3.Error:
                pass
        conn.commit()
    return redirect(url_for('index'))


@app.route('/update_selected', methods=['POST'])
def update_selected():
    ids = request.form.getlist('ip_id')
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        for ip_id in ids:
            remark = request.form.get(f'remark_{ip_id}', '').strip()
            try:
                c.execute('UPDATE ip_addresses SET remark=? WHERE id=?', (remark, ip_id))
            except sqlite3.Error:
                pass
        conn.commit()
    return redirect(url_for('index'))


def check_blacklists(group_id=None):
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        if group_id is None:
            ips = c.execute('SELECT id FROM ip_addresses WHERE excluded=0').fetchall()
        else:
            ips = c.execute('SELECT id FROM ip_addresses WHERE excluded=0 AND group_id=?', (group_id,)).fetchall()
        for (ip_id,) in ips:
            check_ip(ip_id)
        conn.commit()

def check_ip(ip_id):
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        row = c.execute('SELECT ip, excluded, remark, group_id FROM ip_addresses WHERE id=?', (ip_id,)).fetchone()
        if not row or row[1]:
            return
        ip = row[0]
        remark = row[2]
        group_id = row[3]
        dnsbls = c.execute('SELECT id, domain FROM dnsbls').fetchall()
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        listed_info = []
        for dnsbl_id, dnsbl in dnsbls:
            query = '.'.join(reversed(ip.split('.'))) + '.' + dnsbl
            listed = 0
            prev_time = None
            try:
                dns.resolver.resolve(query, 'A')
                listed = 1
                prev = c.execute(
                    '''SELECT listed, checked_at FROM check_results WHERE ip_id=? AND dnsbl_id=? AND listed=1 ORDER BY checked_at DESC LIMIT 1''',
                    (ip_id, dnsbl_id),
                ).fetchone()
                if prev:
                    prev_time = datetime.datetime.strptime(prev[1], '%Y-%m-%d %H:%M:%S')
                listed_info.append((dnsbl, prev_time))
            except dns.resolver.NXDOMAIN:
                listed = 0
            except Exception as e:
                print('DNS check error:', e)
            c.execute(
                'INSERT INTO check_results (ip_id, dnsbl_id, listed, checked_at) VALUES (?, ?, ?, ?)',
                (ip_id, dnsbl_id, listed, timestamp),
            )
        c.execute('UPDATE ip_addresses SET last_checked=? WHERE id=?', (timestamp, ip_id))
        conn.commit()
    if listed_info:
        send_telegram_alerts(ip, listed_info, remark, group_id)


def send_telegram_alerts(ip, dnsbl_info, remark='', group_id=None):
    """Send a single alert message listing all DNSBLs where the IP is found.

    dnsbl_info should be a list of (dnsbl_name, prev_time) tuples. The resend
    logic is evaluated for each dnsbl and the message is sent if any of them
    qualifies for sending.
    """
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        if group_id is not None:
            rows = c.execute('''SELECT telegram_chats.token, telegram_chats.chat_id, telegram_chats.active, telegram_chats.alert_message, telegram_chats.resend_period
                                FROM telegram_chats JOIN group_chats ON telegram_chats.id = group_chats.chat_id
                                WHERE group_chats.group_id=?''', (group_id,)).fetchall()
        else:
            rows = []
        if not rows:
            rows = c.execute('SELECT token, chat_id, active, alert_message, resend_period FROM telegram_chats').fetchall()
    if not rows:
        token = get_setting('TELEGRAM_TOKEN', TELEGRAM_TOKEN)
        chat_id = get_setting('TELEGRAM_CHAT_ID', TELEGRAM_CHAT_ID)
        if token and chat_id:
            msg = get_setting('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}')
            period = int(get_setting('RESEND_TIMES', '0'))
            rows = [(token, chat_id, 1, msg, period)]

    default_msg = get_setting('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}')
    default_period = int(get_setting('RESEND_TIMES', '0'))
    dnsbl_names = [d for d, _ in dnsbl_info]
    now = datetime.datetime.now()
    fmt_args = {
        'date': now.strftime('%Y-%m-%d'),
        'time': now.strftime('%H:%M'),
        'count': len(dnsbl_names),
    }
    for token, chat_id, active, msg, period in rows:
        if not active:
            continue
        message = msg or default_msg
        resend = period if period is not None else default_period
        should_send = False
        for _, prev_time in dnsbl_info:
            send = True
            if resend == 0:
                if prev_time:
                    send = False
            else:
                minutes = minutes_until_next_check(group_id)
                period_minutes = minutes // (resend + 1)
                if prev_time and datetime.datetime.now() - prev_time < datetime.timedelta(minutes=period_minutes):
                    send = False
            if send:
                should_send = True
                break
        if should_send:
            url = f'https://api.telegram.org/bot{token}/sendMessage'
            try:
                requests.post(
                    url,
                    data={'chat_id': chat_id, 'text': message.format(ip=ip, dnsbl=', '.join(dnsbl_names), remark=remark, **fmt_args)},
                    timeout=5,
                )
            except requests.RequestException as e:
                print('Telegram send error:', e)
            else:
                if resend:
                    total = minutes_until_next_check(group_id)
                    interval = max(1, total) / (resend + 1)
                    for i in range(resend):
                        run_time = datetime.datetime.now() + datetime.timedelta(minutes=interval * (i + 1))
                        job_id = f'resend_{chat_id}_{int(run_time.timestamp())}'
                        sched.add_job(requests.post, 'date', run_date=run_time, id=job_id,
                                      args=(url,), kwargs={'data': {'chat_id': chat_id, 'text': message.format(ip=ip, dnsbl=', '.join(dnsbl_names), remark=remark, **fmt_args)}, 'timeout': 5})


def send_test_message(token=None, chat_id=None, message='Test message'):
    if token and chat_id:
        rows = [(token, chat_id)]
    else:
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            rows = c.execute('SELECT token, chat_id FROM telegram_chats WHERE active=1').fetchall()
        if not rows:
            t = get_setting('TELEGRAM_TOKEN', TELEGRAM_TOKEN)
            c_id = get_setting('TELEGRAM_CHAT_ID', TELEGRAM_CHAT_ID)
            if t and c_id:
                rows = [(t, c_id)]
    for tok, cid in rows:
        url = f'https://api.telegram.org/bot{tok}/sendMessage'
        try:
            requests.post(url, data={'chat_id': cid, 'text': message}, timeout=5)
        except requests.RequestException as e:
            print('Telegram send error:', e)


@app.route('/check/<int:ip_id>', methods=['POST'])
def manual_check(ip_id):
    check_ip(ip_id)
    return redirect(url_for('index'))


@app.route('/check_selected', methods=['POST'])
def check_selected():
    ids = request.form.getlist('ip_id')
    for ip_id in ids:
        try:
            check_ip(int(ip_id))
        except ValueError:
            pass
    return redirect(url_for('index'))


@app.route('/telegram', methods=['GET', 'POST'])
def telegram_settings():
    alert_message = get_setting('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}')
    resend_period = int(get_setting('RESEND_TIMES', '0'))
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            action = request.form.get('action', '')
            if action == 'Add':
                tok = request.form.get('token', '').strip()
                chat = request.form.get('chat_id', '').strip()
                name = request.form.get('chat_name', '').strip() or None
                active = 1 if request.form.get('active') == 'on' else 0
                msg = request.form.get('alert_message', '').strip() or None
                try:
                    period_val = int(request.form.get('resend_times', 0))
                except ValueError:
                    period_val = None
                if tok and chat:
                    c.execute('INSERT INTO telegram_chats (token, chat_id, name, active, alert_message, resend_period) VALUES (?, ?, ?, ?, ?, ?)',
                              (tok, chat, name, active, msg, period_val))
            else:
                ids = request.form.getlist('chat_id')
                if action == 'Activate':
                    for cid in ids:
                        c.execute('UPDATE telegram_chats SET active=1 WHERE id=?', (cid,))
                elif action == 'Deactivate':
                    for cid in ids:
                        c.execute('UPDATE telegram_chats SET active=0 WHERE id=?', (cid,))
                elif action == 'Delete':
                    for cid in ids:
                        c.execute('DELETE FROM telegram_chats WHERE id=?', (cid,))
                elif action == 'Update':
                    for cid in ids:
                        tok = request.form.get(f'token_{cid}', '').strip()
                        chat = request.form.get(f'chatid_{cid}', '').strip()
                        name = request.form.get(f'chatname_{cid}', '').strip() or None
                        active = 1 if request.form.get(f'active_{cid}') == 'on' else 0
                        msg = request.form.get(f'alert_message_{cid}', '').strip() or None
                        try:
                            period_val = int(request.form.get(f'resend_times_{cid}', 0))
                        except ValueError:
                            period_val = None
                        c.execute('UPDATE telegram_chats SET token=?, chat_id=?, name=?, active=?, alert_message=?, resend_period=? WHERE id=?',
                                  (tok, chat, name, active, msg, period_val, cid))
                elif action == 'Test':
                    if ids:
                        for cid in ids:
                            row = c.execute('SELECT token, chat_id FROM telegram_chats WHERE id=?', (cid,)).fetchone()
                            msg = request.form.get(f'alert_message_{cid}', '').strip() or 'Test Message'
                            if row:
                                send_test_message(token=row[0], chat_id=row[1], message=msg)
                    else:
                        send_test_message(message='Test Message')
        conn.commit()
        chats = c.execute('SELECT id, token, chat_id, name, active, alert_message, resend_period FROM telegram_chats').fetchall()
    times_disp = resend_period
    chat_settings = []
    for row in chats:
        rperiod = row[6] if row[6] is not None else resend_period
        chat_settings.append((row[0], row[1], row[2], row[3], row[4], row[5], rperiod))
    return render_template('telegram.html', chats=chat_settings, message=alert_message,
                           resend_times=times_disp)


@app.route('/schedule', methods=['GET', 'POST'])
def schedule_view():
    action = request.form.get('action', '') if request.method == 'POST' else ''
    if action == 'schedule_add':
        stype = request.form.get('type', '')
        day = request.form.get('day', '')
        date_full = day if stype == 'monthly' and day else None
        hour = int(request.form.get('hour', '0') or 0)
        minute = int(request.form.get('minute', '0') or 0)
        ampm = request.form.get('ampm', 'am')
        group_ids = request.form.getlist('group_ids')
        sched_id = request.form.get('schedule_id')
        if stype != 'hourly':
            if stype != 'hourly':
                if ampm == 'pm' and hour < 12:
                    hour += 12
                if ampm == 'am' and hour == 12:
                    hour = 0
        if stype == 'monthly' and day:
            try:
                day = str(int(day.split('-')[-1]))
            except Exception:
                day = ''
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            if sched_id:
                gid = group_ids[0] if group_ids else None
                c.execute('''UPDATE check_schedules SET group_id=?, type=?, day=?, hour=?, minute=?, date_full=? WHERE id=?''',
                          (gid, stype, day, hour, minute, date_full, sched_id))
            else:
                ids_list = group_ids if group_ids else ['']
                for gid in ids_list:
                    gval = gid or None
                    c.execute('INSERT INTO check_schedules (group_id, type, day, hour, minute, date_full) VALUES (?, ?, ?, ?, ?, ?)',
                              (gval, stype, day, hour, minute, date_full))
            conn.commit()
        schedule_check_jobs()
        return redirect(url_for('schedule_view'))
    elif action == 'schedule_update':
        ids = request.form.getlist('schedule_id')
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            for sid in ids:
                stype = request.form.get(f'type_{sid}', '')
                day = request.form.get(f'day_{sid}', '')
                date_full = day if stype == 'monthly' and day else None
                hour = int(request.form.get(f'hour_{sid}', '0') or 0)
                minute = int(request.form.get(f'minute_{sid}', '0') or 0)
                ampm = request.form.get(f'ampm_{sid}', 'am')
                group_id = request.form.get(f'group_id_{sid}') or None
                if stype != 'hourly':
                    if stype != 'hourly':
                        if ampm == 'pm' and hour < 12:
                            hour += 12
                        if ampm == 'am' and hour == 12:
                            hour = 0
                if stype == 'monthly' and day:
                    try:
                        day = str(int(day.split('-')[-1]))
                    except Exception:
                        day = ''
                c.execute('''UPDATE check_schedules SET group_id=?, type=?, day=?, hour=?, minute=?, date_full=? WHERE id=?''',
                          (group_id, stype, day, hour, minute, date_full, sid))
            conn.commit()
        schedule_check_jobs()
        return redirect(url_for('schedule_view'))
    elif action == 'schedule_delete':
        ids = request.form.getlist('schedule_id')
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            for sid in ids:
                c.execute('DELETE FROM check_schedules WHERE id=?', (sid,))
            conn.commit()
        schedule_check_jobs()
        return redirect(url_for('schedule_view'))

    edit_schedule = None
    if request.args.get('edit'):
        sid = request.args.get('edit')
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            row = c.execute('SELECT id, group_id, type, day, hour, minute, date_full FROM check_schedules WHERE id=?', (sid,)).fetchone()
        if row:
            rid, g_id, typ, d, h, m, dfull = row
            am = 'AM'
            hour12 = h
            if typ != 'hourly':
                if hour12 >= 12:
                    am = 'PM'
                    if hour12 > 12:
                        hour12 -= 12
                if hour12 == 0:
                    hour12 = 12
            date_val = ''
            if typ == 'monthly':
                if dfull:
                    date_val = dfull
                elif d:
                    date_val = f"2000-01-{int(d):02d}"
            edit_schedule = {
                'id': rid,
                'group_id': g_id,
                'type': typ,
                'day': d,
                'hour': hour12,
                'minute': m,
                'ampm': am,
                'date_value': date_val,
            }
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        schedules = c.execute('''SELECT check_schedules.id, check_schedules.group_id, ip_groups.name, check_schedules.type, check_schedules.day, check_schedules.hour, check_schedules.minute, check_schedules.date_full FROM check_schedules LEFT JOIN ip_groups ON ip_groups.id=check_schedules.group_id''').fetchall()
        groups = c.execute('SELECT id, name FROM ip_groups').fetchall()
    display_schedules = []
    for sid, gid, gname, stype, day, hour, minute, date_full in schedules:
        ampm = 'AM'
        h = hour
        if stype != 'hourly':
            if h >= 12:
                ampm = 'PM'
                if h > 12:
                    h -= 12
            if h == 0:
                h = 12
        date_val = ''
        if stype == 'monthly':
            if date_full:
                date_val = date_full
            elif day:
                date_val = f"2000-01-{int(day):02d}"
        display_schedules.append({'id': sid, 'group_id': gid, 'group_name': gname, 'type': stype, 'day': day, 'hour': h, 'minute': minute, 'ampm': ampm, 'date_value': date_val})
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    return render_template('schedule.html', schedules=display_schedules, groups=groups,
                           edit_schedule=edit_schedule, current_date=current_date)
@app.route('/backups', methods=['GET', 'POST'])
def backups_view():
    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'create':
            create_backup()
            # redirect without view parameter so backup data is hidden
            return redirect(url_for('backups_view'))
        elif action == 'view':
            ids = request.form.getlist('backup_id')
            if ids:
                return redirect(url_for('backups_view', view=ids[0]))
            return redirect(url_for('backups_view'))
        elif action == 'delete':
            ids = request.form.getlist('backup_id')
            with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
                c = conn.cursor()
                for bid in ids:
                    c.execute('DELETE FROM backup_check_results WHERE backup_id=?', (bid,))
                    c.execute('DELETE FROM backups WHERE id=?', (bid,))
                conn.commit()
        elif action == 'retention':
            days = request.form.get('days', '').strip()
            count = request.form.get('count', '').strip()
            if days.isdigit():
                set_setting('BACKUP_RETENTION_DAYS', days)
            if count.isdigit():
                set_setting('BACKUP_KEEP_COUNT', count)
            cleanup_old_backups()
        elif action == 'schedule_add':
            stype = request.form.get('type', '')
            day = request.form.get('day', '')
            date_full = day if stype == 'monthly' and day else None
            hour = int(request.form.get('hour', '0') or 0)
            minute = int(request.form.get('minute', '0') or 0)
            ampm = request.form.get('ampm', 'am')
            group_id = request.form.get('group_id') or None
            sched_id = request.form.get('schedule_id')
            if ampm == 'pm' and hour < 12:
                hour += 12
            if ampm == 'am' and hour == 12:
                hour = 0
            if stype == 'monthly' and day:
                try:
                    day = str(int(day.split('-')[-1]))
                except Exception:
                    day = ''
            with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
                c = conn.cursor()
                if sched_id:
                    c.execute('''UPDATE backup_schedules SET group_id=?, type=?, day=?, hour=?, minute=?, date_full=?
                                 WHERE id=?''',
                              (group_id, stype, day, hour, minute, date_full, sched_id))
                else:
                    c.execute('INSERT INTO backup_schedules (group_id, type, day, hour, minute, date_full) VALUES (?, ?, ?, ?, ?, ?)',
                              (group_id, stype, day, hour, minute, date_full))
                conn.commit()
            schedule_backup_jobs()
        elif action == 'schedule_update':
            ids = request.form.getlist('schedule_id')
            with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
                c = conn.cursor()
                for sid in ids:
                    stype = request.form.get(f'type_{sid}', '')
                    day = request.form.get(f'day_{sid}', '')
                    date_full = day if stype == 'monthly' and day else None
                    hour = int(request.form.get(f'hour_{sid}', '0') or 0)
                    minute = int(request.form.get(f'minute_{sid}', '0') or 0)
                    ampm = request.form.get(f'ampm_{sid}', 'am')
                    group_id = request.form.get(f'group_id_{sid}') or None
                    if ampm == 'pm' and hour < 12:
                        hour += 12
                    if ampm == 'am' and hour == 12:
                        hour = 0
                    if stype == 'monthly' and day:
                        try:
                            day = str(int(day.split('-')[-1]))
                        except Exception:
                            day = ''
                    c.execute('''UPDATE backup_schedules SET group_id=?, type=?, day=?, hour=?, minute=?, date_full=?
                                 WHERE id=?''',
                              (group_id, stype, day, hour, minute, date_full, sid))
                conn.commit()
            schedule_backup_jobs()
        elif action == 'schedule_delete':
            ids = request.form.getlist('schedule_id')
            with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
                c = conn.cursor()
                for sid in ids:
                    c.execute('DELETE FROM backup_schedules WHERE id=?', (sid,))
                conn.commit()
            schedule_backup_jobs()
        return redirect(url_for('backups_view'))

    retention_days = int(get_setting('BACKUP_RETENTION_DAYS', '0'))
    retention_count = int(get_setting('BACKUP_KEEP_COUNT', '0'))
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        backups = c.execute('SELECT id, created_at, status, error FROM backups ORDER BY created_at DESC').fetchall()
        schedules = c.execute('''SELECT backup_schedules.id, backup_schedules.group_id, ip_groups.name, backup_schedules.type,
                                       backup_schedules.day, backup_schedules.hour, backup_schedules.minute,
                                       backup_schedules.date_full
                                FROM backup_schedules LEFT JOIN ip_groups ON ip_groups.id=backup_schedules.group_id''').fetchall()
        groups = c.execute('SELECT id, name FROM ip_groups').fetchall()
    last_backup = backups[0] if backups else None
    display_schedules = []
    for sid, gid, gname, stype, day, hour, minute, date_full in schedules:
        ampm = 'AM'
        h = hour
        if stype != 'hourly':
            if h >= 12:
                ampm = 'PM'
                if h > 12:
                    h -= 12
            if h == 0:
                h = 12
        date_val = ''
        if stype == 'monthly':
            if date_full:
                date_val = date_full
            elif day:
                date_val = f"2000-01-{int(day):02d}"
        display_schedules.append({'id': sid,
                                 'group_id': gid,
                                 'group_name': gname,
                                 'type': stype,
                                 'day': day,
                                 'hour': h,
                                 'minute': minute,
                                 'ampm': ampm,
                                 'date_value': date_val})

    edit_schedule = None
    if request.args.get('edit'):
        sid = request.args.get('edit')
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            row = c.execute('SELECT id, group_id, type, day, hour, minute, date_full FROM backup_schedules WHERE id=?', (sid,)).fetchone()
        if row:
            rid, g_id, typ, d, h, m, dfull = row
            am = 'AM'
            hour12 = h
            if typ != 'hourly':
                if hour12 >= 12:
                    am = 'PM'
                    if hour12 > 12:
                        hour12 -= 12
                if hour12 == 0:
                    hour12 = 12
            date_val = ''
            if typ == 'monthly':
                if dfull:
                    date_val = dfull
                elif d:
                    date_val = f"2000-01-{int(d):02d}"
            edit_schedule = {
                'id': rid,
                'group_id': g_id,
                'type': typ,
                'day': d,
                'hour': hour12,
                'minute': m,
                'ampm': am,
                'date_value': date_val,
            }
    results = None
    view_id = request.args.get('view')
    if view_id:
        results = get_backup_results(view_id)
    elif request.args:
        q = '''SELECT b.created_at, ip_addresses.ip, dnsbls.domain, r.listed, r.checked_at
                FROM backup_check_results r
                JOIN backups b ON b.id=r.backup_id
                JOIN ip_addresses ON ip_addresses.id=r.ip_id
                JOIN dnsbls ON dnsbls.id=r.dnsbl_id WHERE 1=1'''
        params = []
        start = request.args.get('start', '')
        end = request.args.get('end', '')
        ip = request.args.get('ip', '').strip()
        dnsbl = request.args.get('dnsbl', '').strip()
        listed = request.args.get('listed', '')
        if start:
            q += ' AND b.created_at >= ?'
            params.append(start)
        if end:
            q += ' AND b.created_at <= ?'
            params.append(end + ' 23:59:59')
        if ip:
            q += ' AND ip_addresses.ip LIKE ?'
            params.append(ip)
        if dnsbl:
            q += ' AND dnsbls.domain LIKE ?'
            params.append(dnsbl)
        if listed in ('0', '1'):
            q += ' AND r.listed = ?'
            params.append(int(listed))
        q += ' ORDER BY b.created_at DESC LIMIT 100'
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            results = c.execute(q, params).fetchall()

    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    return render_template('backups.html', backups=backups, last_backup=last_backup,
                           retention_days=retention_days, retention_count=retention_count,
                           schedules=display_schedules, groups=groups,
                           results=results, edit_schedule=edit_schedule,
                           view_id=view_id, current_date=current_date)


def scheduled_check(group_id=None):
    check_blacklists(group_id)


def cleanup_old_backups():
    days = int(get_setting('BACKUP_RETENTION_DAYS', '0') or 0)
    count = int(get_setting('BACKUP_KEEP_COUNT', '0') or 0)
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        if days > 0:
            cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
            ids = [r[0] for r in c.execute('SELECT id FROM backups WHERE created_at < ?', (cutoff,))]
            for bid in ids:
                c.execute('DELETE FROM backup_check_results WHERE backup_id=?', (bid,))
                c.execute('DELETE FROM backups WHERE id=?', (bid,))
        if count > 0:
            total = c.execute('SELECT COUNT(*) FROM backups').fetchone()[0]
            if total > count:
                rm = total - count
                ids = [r[0] for r in c.execute('SELECT id FROM backups ORDER BY created_at ASC LIMIT ?', (rm,))]
                for bid in ids:
                    c.execute('DELETE FROM backup_check_results WHERE backup_id=?', (bid,))
                    c.execute('DELETE FROM backups WHERE id=?', (bid,))
        conn.commit()

def get_backup_results(bid):
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        return c.execute('''SELECT b.created_at, ip_addresses.ip, dnsbls.domain,
                                   r.listed, r.checked_at
                            FROM backup_check_results r
                            JOIN backups b ON b.id=r.backup_id
                            JOIN ip_addresses ON ip_addresses.id=r.ip_id
                            JOIN dnsbls ON dnsbls.id=r.dnsbl_id
                            WHERE b.id=?
                            ORDER BY r.checked_at DESC''', (bid,)).fetchall()


def create_backup():
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    bid = None
    try:
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO backups (created_at, status) VALUES (?, ?)', (timestamp, 'running'))
            bid = c.lastrowid
            rows = c.execute('SELECT ip_id, dnsbl_id, listed, checked_at FROM check_results').fetchall()
            for r in rows:
                c.execute('INSERT INTO backup_check_results (backup_id, ip_id, dnsbl_id, listed, checked_at) VALUES (?, ?, ?, ?, ?)', (bid, r[0], r[1], r[2], r[3]))
            c.execute('UPDATE backups SET status=? WHERE id=?', ('success', bid))
            conn.commit()
    except Exception as e:
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            if bid is None:
                c.execute('INSERT INTO backups (created_at, status, error) VALUES (?, ?, ?)', (timestamp, 'failed', str(e)))
            else:
                c.execute('UPDATE backups SET status=?, error=? WHERE id=?', ('failed', str(e), bid))
            conn.commit()
    cleanup_old_backups()
    return bid


def schedule_backup_jobs():
    # remove existing jobs
    for job in sched.get_jobs():
        if job.id.startswith('backup_job_'):
            sched.remove_job(job.id)
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        rows = c.execute('SELECT id, type, day, hour, minute FROM backup_schedules').fetchall()
    for r in rows:
        sid, stype, day, hour, minute = r
        job_id = f'backup_job_{sid}'
        if stype == 'daily':
            sched.add_job(create_backup, 'cron', hour=hour, minute=minute, id=job_id)
        elif stype == 'weekly':
            sched.add_job(create_backup, 'cron', day_of_week=day or 'mon', hour=hour, minute=minute, id=job_id)
        elif stype == 'monthly':
            sched.add_job(create_backup, 'cron', day=day or '1', hour=hour, minute=minute, id=job_id)
        elif stype == 'hourly':
            sched.add_job(create_backup, 'interval', hours=hour, minutes=minute, id=job_id)

def schedule_check_jobs():
    for job in sched.get_jobs():
        if job.id.startswith("check_job_"):
            sched.remove_job(job.id)
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        rows = c.execute("SELECT id, group_id, type, day, hour, minute FROM check_schedules").fetchall()
    for sid, gid, stype, day, hour, minute in rows:
        job_id = f"check_job_{sid}"
        kwargs = {"group_id": gid}
        if stype == "daily":
            sched.add_job(scheduled_check, "cron", hour=hour, minute=minute, id=job_id, kwargs=kwargs)
        elif stype == "weekly":
            sched.add_job(scheduled_check, "cron", day_of_week=day or "mon", hour=hour, minute=minute, id=job_id, kwargs=kwargs)
        elif stype == "monthly":
            sched.add_job(scheduled_check, "cron", day=day or "1", hour=hour, minute=minute, id=job_id, kwargs=kwargs)
        elif stype == "hourly":
            sched.add_job(scheduled_check, "interval", hours=hour, minutes=minute, id=job_id, kwargs=kwargs)

def minutes_until_next_check(group_id=None):
    jobs = []
    if group_id is not None:
        jobs = [j for j in sched.get_jobs() if j.id.startswith('check_job_') and j.kwargs.get('group_id') == group_id]
    if not jobs:
        jobs = [j for j in sched.get_jobs() if j.id.startswith('check_job_')]
    if not jobs:
        return CHECK_INTERVAL_MINUTES if CHECK_INTERVAL_MINUTES > 0 else 1440
    next_run = None
    for j in jobs:
        if j.next_run_time and (next_run is None or j.next_run_time < next_run):
            next_run = j.next_run_time
    if not next_run:
        return CHECK_INTERVAL_MINUTES if CHECK_INTERVAL_MINUTES > 0 else 1440
    now = datetime.datetime.now(tz=next_run.tzinfo)
    diff = next_run - now
    return max(1, int(diff.total_seconds() / 60))


@app.route('/logs', methods=['GET', 'POST'])
def view_logs():
    global log_history
    if request.method == 'POST':
        size = request.form.get('history_size', '').strip()
        if size.isdigit() and int(size) > 0:
            set_setting('LOG_HISTORY_SIZE', size)
            log_history = deque(list(log_history), maxlen=int(size))
    hist_size = get_setting('LOG_HISTORY_SIZE', '200')
    return render_template('logs.html', history_size=hist_size)


@app.route('/log_feed')
def log_feed():
    return '\n'.join(log_history)


@app.route('/stats')
def stats():
    """Return simple system statistics for the dashboard."""
    try:
        import psutil
        load = os.getloadavg()[0]
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
    except Exception:
        load = cpu = mem = disk = 0
    return {
        'load': round(load, 2),
        'cpu': round(cpu, 2),
        'mem': round(mem, 2),
        'disk': round(disk, 2)
    }
if __name__ == '__main__':
    init_db()
    log_history = deque(maxlen=int(get_setting('LOG_HISTORY_SIZE', '200')))
    schedule_check_jobs()
    schedule_backup_jobs()
    sched.start()
    app.run(host='0.0.0.0', port=5000)
