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
CHECK_INTERVAL_MINUTES = int(float(os.environ.get('CHECK_INTERVAL_HOURS', '6')) * 60)
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
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}'))
        c.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                  ('RESEND_PERIODIC', '1'))
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
            group_id = request.form.get('group_id')
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
    group_id = request.form.get('group_id')
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


@app.route('/ips/set_group', methods=['POST'])
def set_group():
    group_id = request.form.get('group_id')
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
        row = c.execute('SELECT ip FROM ip_addresses WHERE id=?', (ip_id,)).fetchone()
        if not row:
            return
        ip = row[0]
        dnsbls = c.execute('SELECT id, domain FROM dnsbls').fetchall()
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        for dnsbl_id, dnsbl in dnsbls:
            query = '.'.join(reversed(ip.split('.'))) + '.' + dnsbl
            listed = 0
            try:
                dns.resolver.resolve(query, 'A')
                listed = 1
                alert_message = get_setting('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}')
                resend = int(get_setting('RESEND_PERIODIC', '1'))
                send = True
                if not resend:
                    prev = c.execute('''SELECT listed FROM check_results WHERE ip_id=? AND dnsbl_id=? ORDER BY checked_at DESC LIMIT 1''',
                                     (ip_id, dnsbl_id)).fetchone()
                    if prev and prev[0] == 1:
                        send = False
                if send:
                    send_telegram_alert(alert_message.format(ip=ip, dnsbl=dnsbl))
            except dns.resolver.NXDOMAIN:
                listed = 0
            except Exception as e:
                print('DNS check error:', e)
            c.execute('INSERT INTO check_results (ip_id, dnsbl_id, listed, checked_at) VALUES (?, ?, ?, ?)',
                      (ip_id, dnsbl_id, listed, timestamp))
        c.execute('UPDATE ip_addresses SET last_checked=? WHERE id=?', (timestamp, ip_id))
        conn.commit()


def send_telegram_alert(message):
    token = get_setting('TELEGRAM_TOKEN', TELEGRAM_TOKEN)
    chat_id = get_setting('TELEGRAM_CHAT_ID', TELEGRAM_CHAT_ID)
    if not token or not chat_id:
        return
    text = message
    url = f'https://api.telegram.org/bot{token}/sendMessage'
    try:
        requests.post(url, data={'chat_id': chat_id, 'text': text}, timeout=5)
    except requests.RequestException as e:
        print('Telegram send error:', e)


def send_test_message(token, chat_id):
    if not token or not chat_id:
        return
    url = f'https://api.telegram.org/bot{token}/sendMessage'
    try:
        requests.post(url, data={'chat_id': chat_id, 'text': 'Test message'}, timeout=5)
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
    token = get_setting('TELEGRAM_TOKEN', TELEGRAM_TOKEN)
    chat_id = get_setting('TELEGRAM_CHAT_ID', TELEGRAM_CHAT_ID)
    alert_message = get_setting('ALERT_MESSAGE', 'IP {ip} is blacklisted in {dnsbl}')
    resend = int(get_setting('RESEND_PERIODIC', '1'))
    if request.method == 'POST':
        action = request.form.get('action')
        new_token = request.form.get('token', '').strip()
        new_chat = request.form.get('chat_id', '').strip()
        new_msg = request.form.get('alert_message', '').strip()
        resend_flag = 1 if request.form.get('resend_periodic') == 'on' else 0
        if action == 'Test':
            send_test_message(new_token or token, new_chat or chat_id)
        else:
            if new_token:
                set_setting('TELEGRAM_TOKEN', new_token)
                token = new_token
            if new_chat:
                set_setting('TELEGRAM_CHAT_ID', new_chat)
                chat_id = new_chat
            if new_msg:
                set_setting('ALERT_MESSAGE', new_msg)
                alert_message = new_msg
            set_setting('RESEND_PERIODIC', str(resend_flag))
            resend = resend_flag
            new_token = ''
            new_chat = ''
    return render_template('telegram.html', token_display=token,
                           chat_id_display=chat_id, message=alert_message,
                           resend_periodic=resend)


@app.route('/schedule', methods=['GET', 'POST'])
def schedule_view():
    global CHECK_INTERVAL_MINUTES
    if request.method == 'POST':
        try:
            hours = int(request.form.get('hours', 0))
            minutes = int(request.form.get('minutes', 0))
            interval = hours * 60 + minutes
            if interval <= 0:
                interval = 1
            CHECK_INTERVAL_MINUTES = interval
            sched.reschedule_job('blacklist_check', trigger='interval', minutes=interval)
        except ValueError:
            pass
    job = sched.get_job('blacklist_check')
    next_run = job.next_run_time if job else None
    h = CHECK_INTERVAL_MINUTES // 60
    m = CHECK_INTERVAL_MINUTES % 60
    return render_template('schedule.html', hours=h, minutes=m, next_run=next_run)


@sched.scheduled_job('interval', minutes=CHECK_INTERVAL_MINUTES, id='blacklist_check')
def scheduled_check():
    check_blacklists()


if __name__ == '__main__':
    init_db()
    sched.start()
    app.run(host='0.0.0.0', port=5000)
