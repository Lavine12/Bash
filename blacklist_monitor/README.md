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

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set the environment variables `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` for Telegram alerts.
   Optionally set `CHECK_INTERVAL_HOURS` to change the default check interval.
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
