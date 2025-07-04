import os
import sqlite3
import requests
from flask import Flask, render_template, request, redirect, url_for
from apscheduler.schedulers.background import BackgroundScheduler
import ipaddress
import dns.resolver
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'data.db')
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

app = Flask(__name__)
CHECK_INTERVAL_MINUTES = int(float(os.environ.get('CHECK_INTERVAL_HOURS', '0')) * 60)
sched = BackgroundScheduler()


def get_setting(key, default=''):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        row = c.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return row[0] if row else default


def set_setting(key, value):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
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
            active INTEGER DEFAULT 1,
            alert_message TEXT,
            resend_period INTEGER
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
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
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('RESEND_PERIODIC', '1'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('RESEND_PERIOD', '0'))
        if TELEGRAM_TOKEN:
            c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                      ('TELEGRAM_TOKEN', TELEGRAM_TOKEN))
        if TELEGRAM_CHAT_ID:
            c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                      ('TELEGRAM_CHAT_ID', TELEGRAM_CHAT_ID))
        conn.commit()


@app.route('/')
def index():
    with sqlite3.connect(DB_PATH) as conn:
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
    with sqlite3.connect(DB_PATH) as conn:
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
    with sqlite3.connect(DB_PATH) as conn:
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
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM ip_addresses WHERE id=?', (ip_id,))
        conn.commit()
    return redirect(url_for('manage_ips'))


@app.route('/ips/delete_selected', methods=['POST'])
def delete_selected_ips():
    ids = request.form.getlist('ip_id')
    with sqlite3.connect(DB_PATH) as conn:
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
    with sqlite3.connect(DB_PATH) as conn:
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
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        for line in lines:
            if line:
                c.execute('INSERT OR IGNORE INTO dnsbls (domain) VALUES (?)', (line,))
        conn.commit()
    check_blacklists()
    return redirect(url_for('manage_dnsbls'))


@app.route('/dnsbls/delete/<int:dnsbl_id>', methods=['POST'])
def delete_dnsbl(dnsbl_id):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM dnsbls WHERE id=?', (dnsbl_id,))
        conn.commit()
    return redirect(url_for('manage_dnsbls'))


@app.route('/dnsbls/delete_selected', methods=['POST'])
def delete_selected_dnsbls():
    ids = request.form.getlist('dnsbl_id')
    with sqlite3.connect(DB_PATH) as conn:
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
    with sqlite3.connect(DB_PATH) as conn:
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
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM ip_groups WHERE id=?', (group_id,))
        c.execute('UPDATE ip_addresses SET group_id=NULL WHERE group_id=?', (group_id,))
        conn.commit()
    return redirect(url_for('manage_groups'))


@app.route('/groups/update/<int:group_id>', methods=['POST'])
def update_group(group_id):
    new_name = request.form.get('group_name', '').strip()
    if new_name:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('UPDATE ip_groups SET name=? WHERE id=?', (new_name, group_id))
            conn.commit()
    return redirect(url_for('manage_groups'))


@app.route('/ips/set_group', methods=['POST'])
def set_group():
    group_id = request.form.get('group_id') or None
    ip_ids = request.form.getlist('ip_id')
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        for ip_id in ip_ids:
            c.execute('UPDATE ip_addresses SET group_id=? WHERE id=?', (group_id, ip_id))
        conn.commit()
    return redirect(url_for('manage_ips'))


@app.route('/exclude_selected', methods=['POST'])
def exclude_selected():
    ids = request.form.getlist('ip_id')
    with sqlite3.connect(DB_PATH) as conn:
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
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        for ip_id in ids:
            try:
                c.execute('UPDATE ip_addresses SET excluded=0 WHERE id=?', (ip_id,))
            except sqlite3.Error:
                pass
        conn.commit()
    return redirect(url_for('index'))


def check_blacklists():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        ips = c.execute('SELECT id FROM ip_addresses WHERE excluded=0').fetchall()
        for (ip_id,) in ips:
            check_ip(ip_id)
        conn.commit()

def check_ip(ip_id):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        row = c.execute('SELECT ip, excluded FROM ip_addresses WHERE id=?', (ip_id,)).fetchone()
        if not row or row[1]:
            return
        ip = row[0]
        dnsbls = c.execute('SELECT id, domain FROM dnsbls').fetchall()
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        for dnsbl_id, dnsbl in dnsbls:
            query = '.'.join(reversed(ip.split('.'))) + '.' + dnsbl
            listed = 0
            try:
                dns.resolver.resolve(query, 'A')
                listed = 1
                prev = c.execute('''SELECT listed, checked_at FROM check_results WHERE ip_id=? AND dnsbl_id=? AND listed=1 ORDER BY checked_at DESC LIMIT 1''',
                                 (ip_id, dnsbl_id)).fetchone()
                prev_time = None
                if prev:
                    prev_time = datetime.datetime.strptime(prev[1], '%Y-%m-%d %H:%M:%S')
                send_telegram_alerts(ip, dnsbl, prev_time)
            except dns.resolver.NXDOMAIN:
                listed = 0
            except Exception as e:
                print('DNS check error:', e)
            c.execute('INSERT INTO check_results (ip_id, dnsbl_id, listed, checked_at) VALUES (?, ?, ?, ?)',
                      (ip_id, dnsbl_id, listed, timestamp))
        c.execute('UPDATE ip_addresses SET last_checked=? WHERE id=?', (timestamp, ip_id))
        conn.commit()


def send_telegram_alerts(ip, dnsbl, prev_time=None):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        rows = c.execute('SELECT token, chat_id, active, alert_message, resend_period FROM telegram_chats').fetchall()
    if not rows:
        token = get_setting('TELEGRAM_TOKEN', TELEGRAM_TOKEN)
        chat_id = get_setting('TELEGRAM_CHAT_ID', TELEGRAM_CHAT_ID)
        if token and chat_id:
            msg = get_setting('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}')
            period = int(get_setting('RESEND_PERIOD', '0'))
            rows = [(token, chat_id, 1, msg, period)]
    default_msg = get_setting('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}')
    default_period = int(get_setting('RESEND_PERIOD', '0'))
    for token, chat_id, active, msg, period in rows:
        if not active:
            continue
        message = msg or default_msg
        resend = period if period is not None else default_period
        send = True
        if resend == 0:
            if prev_time:
                send = False
        else:
            if prev_time and datetime.datetime.now() - prev_time < datetime.timedelta(minutes=resend):
                send = False
        if send:
            url = f'https://api.telegram.org/bot{token}/sendMessage'
            try:
                requests.post(url, data={'chat_id': chat_id, 'text': message.format(ip=ip, dnsbl=dnsbl)}, timeout=5)
            except requests.RequestException as e:
                print('Telegram send error:', e)


def send_test_message(token=None, chat_id=None, message='Test message'):
    if token and chat_id:
        rows = [(token, chat_id)]
    else:
        with sqlite3.connect(DB_PATH) as conn:
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
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            action = request.form.get('action', '')
            if action == 'Add':
                tok = request.form.get('token', '').strip()
                chat = request.form.get('chat_id', '').strip()
                active = 1 if request.form.get('active') == 'on' else 0
                msg = request.form.get('alert_message', '').strip() or None
                try:
                    rh = int(request.form.get('resend_hours', 0))
                    rm = int(request.form.get('resend_minutes', 0))
                    period_val = rh * 60 + rm
                except ValueError:
                    period_val = None
                if tok and chat:
                    c.execute('INSERT INTO telegram_chats (token, chat_id, active, alert_message, resend_period) VALUES (?, ?, ?, ?, ?)',
                              (tok, chat, active, msg, period_val))
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
                        active = 1 if request.form.get(f'active_{cid}') == 'on' else 0
                        msg = request.form.get(f'alert_message_{cid}', '').strip() or None
                        try:
                            rh = int(request.form.get(f'resend_hours_{cid}', 0))
                            rm = int(request.form.get(f'resend_minutes_{cid}', 0))
                            period_val = rh * 60 + rm
                        except ValueError:
                            period_val = None
                        c.execute('UPDATE telegram_chats SET token=?, chat_id=?, active=?, alert_message=?, resend_period=? WHERE id=?',
                                  (tok, chat, active, msg, period_val, cid))
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
        chats = c.execute('SELECT id, token, chat_id, active, alert_message, resend_period FROM telegram_chats').fetchall()
    rh_disp = resend_period // 60
    rm_disp = resend_period % 60
    chat_settings = []
    for row in chats:
        rperiod = row[5] if row[5] is not None else resend_period
        chat_settings.append((row[0], row[1], row[2], row[3], row[4], rperiod // 60, rperiod % 60))
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


def scheduled_check():
    if CHECK_INTERVAL_MINUTES > 0:
        check_blacklists()


if __name__ == '__main__':
    init_db()
    if CHECK_INTERVAL_MINUTES > 0:
        sched.add_job(scheduled_check, 'interval', minutes=CHECK_INTERVAL_MINUTES, id='blacklist_check')
    sched.start()
    app.run(host='0.0.0.0', port=5000)
