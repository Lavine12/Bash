# Web Blacklist Monitor

This simple Flask application monitors a list of IP addresses against a set of DNSBL services.

Features:
- Add or remove single IPs or CIDR ranges.
- Add or remove DNSBL domains.
- Periodic checks every 6 hours.
- Alerts are sent to a Telegram chat when an IP is blacklisted.
- Web interface shows all monitored IPs and their last check time.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set the environment variables `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` for Telegram alerts.
3. Run the app:
   ```bash
   python app.py
   ```

The web interface will be available at `http://localhost:5000`.
