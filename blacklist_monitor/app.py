import os
import sqlite3
import requests
from flask import Flask, render_template, request, redirect, url_for
from apscheduler.schedulers.background import BackgroundScheduler
import ipaddress
import dns.resolver

DB_PATH = os.path.join(os.path.dirname(__file__), 'data.db')
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

app = Flask(__name__)
sched = BackgroundScheduler()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS ip_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            last_checked TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS dnsbls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE
        )''')
        conn.commit()


@app.route('/')
def index():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        ips = c.execute('SELECT id, ip, last_checked FROM ip_addresses').fetchall()
    return render_template('index.html', ips=ips)


@app.route('/ips', methods=['GET', 'POST'])
def manage_ips():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            ip_range = request.form['ip']
            try:
                net = ipaddress.ip_network(ip_range, strict=False)
                for ip in net.hosts():
                    try:
                        c.execute('INSERT OR IGNORE INTO ip_addresses (ip) VALUES (?)', (str(ip),))
                    except sqlite3.IntegrityError:
                        pass
            except ValueError:
                pass
            conn.commit()
            return redirect(url_for('manage_ips'))
        ips = c.execute('SELECT id, ip FROM ip_addresses').fetchall()
    return render_template('ips.html', ips=ips)


@app.route('/ips/delete/<int:ip_id>', methods=['POST'])
def delete_ip(ip_id):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM ip_addresses WHERE id=?', (ip_id,))
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
            return redirect(url_for('manage_dnsbls'))
        dnsbls = c.execute('SELECT id, domain FROM dnsbls').fetchall()
    return render_template('dnsbls.html', dnsbls=dnsbls)


@app.route('/dnsbls/delete/<int:dnsbl_id>', methods=['POST'])
def delete_dnsbl(dnsbl_id):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM dnsbls WHERE id=?', (dnsbl_id,))
        conn.commit()
    return redirect(url_for('manage_dnsbls'))


def check_blacklists():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        ips = c.execute('SELECT id, ip FROM ip_addresses').fetchall()
        dnsbls = c.execute('SELECT domain FROM dnsbls').fetchall()

        for ip_id, ip in ips:
            for (dnsbl,) in dnsbls:
                query = '.'.join(reversed(ip.split('.'))) + '.' + dnsbl
                try:
                    dns.resolver.resolve(query, 'A')
                    send_telegram_alert(ip, dnsbl)
                except dns.resolver.NXDOMAIN:
                    pass
                except Exception as e:
                    print('DNS check error:', e)
            c.execute('UPDATE ip_addresses SET last_checked=datetime("now") WHERE id=?', (ip_id,))
        conn.commit()


def send_telegram_alert(ip, dnsbl):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    text = f'IP {ip} is blacklisted in {dnsbl}'
    url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
    try:
        requests.post(url, data={'chat_id': TELEGRAM_CHAT_ID, 'text': text}, timeout=5)
    except requests.RequestException as e:
        print('Telegram send error:', e)


@sched.scheduled_job('interval', hours=6)
def scheduled_check():
    check_blacklists()


if __name__ == '__main__':
    init_db()
    sched.start()
    app.run(host='0.0.0.0', port=5000)
