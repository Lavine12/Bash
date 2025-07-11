# Web Blacklist Monitor

This simple Flask application monitors a list of IP addresses against a set of DNSBL services.

Features:
- Add or remove single IPs or CIDR ranges.
- Add or remove DNSBL domains (bulk import supported).
- Create groups and assign IPs using checkboxes.
- Manual blacklist check for a single IP.
- Adjustable check schedule via the web UI.
- Periodic checks run according to the configured schedule.
- Alerts are sent to a Telegram chat when an IP is blacklisted.
- Dashboard shows last and next check times along with blacklist results.
- Backup past check results with searchable history and configurable schedule.

## DNSBLs

The **DNSBLs** page manages the blacklist domains that will be queried.
Each listed DNSBL supports a **Dig Test** feature to perform ad-hoc lookups.
You may optionally provide:

* **IP** – reversed before being appended to the DNSBL domain
* **Server** – DNS server to query (same syntax as the `@server` option)
* **Args** – additional flags or record types passed verbatim to `dig`

Example of a complex dig test command produced by these fields:

```bash
dig +short 2.0.0.127.dnsbl.example.com @8.8.8.8 TXT -p 5300 +time=2 +tries=1
```


## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set the environment variables `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` for Telegram alerts.
   Optionally set `CHECK_INTERVAL_HOURS` to change the default check interval.
   Alert messages support placeholders such as `{ip}`, `{dnsbl}`, `{remark}`, `{date}`, `{time}` and `{count}`.
3. Run the app:
   ```bash
   python app.py
   ```
To keep the monitor running without locking the terminal, you can start it in the background:
```bash
nohup python app.py >/dev/null 2>&1 &
```

The web interface will be available at `http://localhost:5000`.

## Docker

You can also run the application using Docker. Build the image from the
`blacklist_monitor` directory:

```bash
docker build -t blacklist-monitor .
```

Then start a container while providing the required environment variables and
exposing port `5000`:

```bash
docker run -d -p 5000:5000 blacklist-monitor
```

The web interface will then be available at `http://localhost:5000`.

## Logs

The sidebar includes a **Logs** page that streams recent application output.
This allows you to watch requests in real time without accessing the console.

Example output:

```
203.0.113.42 - - [07/Jul/2025 17:14:03] "GET /ips HTTP/1.1" 200 -
203.0.113.42 - - [07/Jul/2025 17:14:03] "GET /static/style.css HTTP/1.1" 304 -
203.0.113.42 - - [07/Jul/2025 17:14:03] "GET /static/script.js HTTP/1.1" 304 -
203.0.113.42 - - [07/Jul/2025 17:14:04] "GET / HTTP/1.1" 200 -
```

