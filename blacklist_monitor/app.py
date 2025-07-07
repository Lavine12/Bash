import os
import sqlite3
import requests
from flask import Flask, render_template, request, redirect, url_for
from apscheduler.schedulers.background import BackgroundScheduler
import ipaddress
import dns.resolver
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'data.db')
DB_TIMEOUT = 30  # seconds
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

app = Flask(__name__)
CHECK_INTERVAL_MINUTES = int(float(os.environ.get('CHECK_INTERVAL_HOURS', '0')) * 60)
sched = BackgroundScheduler()


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
            excluded INTEGER DEFAULT 0
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
            minute INTEGER
        )''')
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
                  ('RESEND_PERIOD', '0'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_RETENTION_DAYS', '30'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_SCHEDULE_TYPE', ''))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_SCHEDULE_DAY', ''))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_SCHEDULE_HOUR', '0'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('BACKUP_SCHEDULE_MINUTE', '0'))
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
                                  AND checked_at=ip_addresses.last_checked)
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
    next_run = None
    job = sched.get_job('blacklist_check')
    if job:
        next_run = job.next_run_time
    return render_template('index.html', ips=ips, ip_count=ip_count,
                           next_run=next_run, groups=groups, dnsbl_map=dnsbl_map)


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
                        c.execute('INSERT OR IGNORE INTO ip_addresses (ip, group_id, excluded) VALUES (?, ?, 0)', (str(ip), group_id))
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
                    c.execute('INSERT OR IGNORE INTO ip_addresses (ip, group_id, excluded) VALUES (?, ?, 0)', (str(ip), group_id))
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
    return render_template('dnsbls.html', dnsbls=dnsbls)


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


@app.route('/groups', methods=['GET', 'POST'])
def manage_groups():
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            name = request.form['group']
            c.execute('INSERT OR IGNORE INTO ip_groups (name) VALUES (?)', (name,))
            conn.commit()
            return redirect(url_for('manage_groups'))
        groups = c.execute('SELECT id, name FROM ip_groups').fetchall()
    return render_template('groups.html', groups=groups)


@app.route('/groups/delete/<int:group_id>', methods=['POST'])
def delete_group(group_id):
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM ip_groups WHERE id=?', (group_id,))
        c.execute('UPDATE ip_addresses SET group_id=NULL WHERE group_id=?', (group_id,))
        conn.commit()
    return redirect(url_for('manage_groups'))


@app.route('/groups/update/<int:group_id>', methods=['POST'])
def update_group(group_id):
    new_name = request.form.get('group_name', '').strip()
    if new_name:
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute('UPDATE ip_groups SET name=? WHERE id=?', (new_name, group_id))
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


def check_blacklists():
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        ips = c.execute('SELECT id FROM ip_addresses WHERE excluded=0').fetchall()
        for (ip_id,) in ips:
            check_ip(ip_id)
        conn.commit()

def check_ip(ip_id):
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        row = c.execute('SELECT ip, excluded FROM ip_addresses WHERE id=?', (ip_id,)).fetchone()
        if not row or row[1]:
            return
        ip = row[0]
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
        send_telegram_alerts(ip, listed_info)


def send_telegram_alerts(ip, dnsbl_info):
    """Send a single alert message listing all DNSBLs where the IP is found.

    dnsbl_info should be a list of (dnsbl_name, prev_time) tuples. The resend
    logic is evaluated for each dnsbl and the message is sent if any of them
    qualifies for sending.
    """
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        rows = c.execute(
            'SELECT token, chat_id, active, alert_message, resend_period FROM telegram_chats'
        ).fetchall()
    if not rows:
        token = get_setting('TELEGRAM_TOKEN', TELEGRAM_TOKEN)
        chat_id = get_setting('TELEGRAM_CHAT_ID', TELEGRAM_CHAT_ID)
        if token and chat_id:
            msg = get_setting('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}')
            period = int(get_setting('RESEND_PERIOD', '0'))
            rows = [(token, chat_id, 1, msg, period)]

    default_msg = get_setting('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}')
    default_period = int(get_setting('RESEND_PERIOD', '0'))
    dnsbl_names = [d for d, _ in dnsbl_info]
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
                if prev_time and datetime.datetime.now() - prev_time < datetime.timedelta(minutes=resend):
                    send = False
            if send:
                should_send = True
                break
        if should_send:
            url = f'https://api.telegram.org/bot{token}/sendMessage'
            try:
                requests.post(
                    url,
                    data={'chat_id': chat_id, 'text': message.format(ip=ip, dnsbl=', '.join(dnsbl_names))},
                    timeout=5,
                )
            except requests.RequestException as e:
                print('Telegram send error:', e)


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
    resend_period = int(get_setting('RESEND_PERIOD', '0'))
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
                    rh = int(request.form.get('resend_hours', 0))
                    rm = int(request.form.get('resend_minutes', 0))
                    period_val = rh * 60 + rm
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
                            rh = int(request.form.get(f'resend_hours_{cid}', 0))
                            rm = int(request.form.get(f'resend_minutes_{cid}', 0))
                            period_val = rh * 60 + rm
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
    rh_disp = resend_period // 60
    rm_disp = resend_period % 60
    chat_settings = []
    for row in chats:
        rperiod = row[6] if row[6] is not None else resend_period
        chat_settings.append((row[0], row[1], row[2], row[3], row[4], row[5], rperiod // 60, rperiod % 60))
    return render_template('telegram.html', chats=chat_settings, message=alert_message,
                           resend_hours=rh_disp, resend_minutes=rm_disp)


@app.route('/schedule', methods=['GET', 'POST'])
def schedule_view():
    global CHECK_INTERVAL_MINUTES
    if request.method == 'POST':
        try:
            hours = int(request.form.get('hours', 0))
            minutes = int(request.form.get('minutes', 0))
            interval = hours * 60 + minutes
            CHECK_INTERVAL_MINUTES = interval
            job = sched.get_job('blacklist_check')
            if interval <= 0:
                if job:
                    sched.remove_job('blacklist_check')
            else:
                if job:
                    sched.reschedule_job('blacklist_check', trigger='interval', minutes=interval)
                else:
                    sched.add_job(scheduled_check, 'interval', minutes=interval, id='blacklist_check')
        except ValueError:
            pass
    job = sched.get_job('blacklist_check')
    next_run = job.next_run_time if job else None
    h = CHECK_INTERVAL_MINUTES // 60
    m = CHECK_INTERVAL_MINUTES % 60
    return render_template('schedule.html', hours=h, minutes=m, next_run=next_run)


@app.route('/backups', methods=['GET', 'POST'])
def backups_view():
    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'create':
            create_backup()
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
            if days.isdigit():
                set_setting('BACKUP_RETENTION_DAYS', days)
        elif action == 'schedule_add':
            stype = request.form.get('type', '')
            day = request.form.get('day', '')
            hour = int(request.form.get('hour', '0') or 0)
            minute = int(request.form.get('minute', '0') or 0)
            ampm = request.form.get('ampm', 'am')
            group_id = request.form.get('group_id') or None
            if ampm == 'pm' and hour < 12:
                hour += 12
            if ampm == 'am' and hour == 12:
                hour = 0
            with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
                c = conn.cursor()
                c.execute('INSERT INTO backup_schedules (group_id, type, day, hour, minute) VALUES (?, ?, ?, ?, ?)',
                          (group_id, stype, day, hour, minute))
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

    retention_days = int(get_setting('BACKUP_RETENTION_DAYS', '30'))
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        backups = c.execute('SELECT id, created_at, status, error FROM backups ORDER BY created_at DESC').fetchall()
        schedules = c.execute('''SELECT backup_schedules.id, ip_groups.name, backup_schedules.type,
                                       backup_schedules.day, backup_schedules.hour, backup_schedules.minute
                                FROM backup_schedules LEFT JOIN ip_groups ON ip_groups.id=backup_schedules.group_id''').fetchall()
        groups = c.execute('SELECT id, name FROM ip_groups').fetchall()
    last_backup = backups[0] if backups else None
    display_schedules = []
    for sid, gname, stype, day, hour, minute in schedules:
        ampm = 'AM'
        h = hour
        if h >= 12:
            ampm = 'PM'
            if h > 12:
                h -= 12
        if h == 0:
            h = 12
        display_schedules.append((sid, gname, stype, day, f"{h:02d}:{minute:02d} {ampm}"))

    results = None
    if request.args:
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

    return render_template('backups.html', backups=backups, last_backup=last_backup,
                           retention_days=retention_days, schedules=display_schedules,
                           groups=groups, results=results)


def scheduled_check():
    if CHECK_INTERVAL_MINUTES > 0:
        check_blacklists()


def cleanup_old_backups():
    days = int(get_setting('BACKUP_RETENTION_DAYS', '0') or 0)
    if days <= 0:
        return
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as conn:
        c = conn.cursor()
        ids = [r[0] for r in c.execute('SELECT id FROM backups WHERE created_at < ?', (cutoff,))]
        for bid in ids:
            c.execute('DELETE FROM backup_check_results WHERE backup_id=?', (bid,))
            c.execute('DELETE FROM backups WHERE id=?', (bid,))
        conn.commit()


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


if __name__ == '__main__':
    init_db()
    if CHECK_INTERVAL_MINUTES > 0:
        sched.add_job(scheduled_check, 'interval', minutes=CHECK_INTERVAL_MINUTES, id='blacklist_check')
    schedule_backup_jobs()
    sched.start()
    app.run(host='0.0.0.0', port=5000)
