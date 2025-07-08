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
docker run -p 5000:5000 \
  -e TELEGRAM_TOKEN=<your token> \
  -e TELEGRAM_CHAT_ID=<your chat id> \
  blacklist-monitor
```

The web interface will then be available at `http://localhost:5000`.

## Logs

The sidebar includes a **Logs** page that streams recent application output.
This allows you to watch requests in real time without accessing the console.
You can configure how many recent entries are kept using the *History size* setting.

Example output:

```
124.217.240.99 - - [07/Jul/2025 17:14:03] "GET /ips HTTP/1.1" 200 -
124.217.240.99 - - [07/Jul/2025 17:14:03] "GET /static/style.css HTTP/1.1" 304 -
124.217.240.99 - - [07/Jul/2025 17:14:03] "GET /static/script.js HTTP/1.1" 304 -
124.217.240.99 - - [07/Jul/2025 17:14:04] "GET / HTTP/1.1" 200 -
```

