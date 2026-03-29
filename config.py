"""
Configuration for Pump.fun Coordinated Wallet Scanner (Webhook Edition).
Set these via environment variables in Railway.
"""

import os

# ---------------------------------------------------------------------------
# Required credentials
# ---------------------------------------------------------------------------
HELIUS_API_KEY = os.environ.get("HELIUS_API_KEY", "915dd768-93a2-44dc-9577-32d6cc548601")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8628775758:AAH76VBVEHvxV2lw2nqG-qAHgW9YDTIp8yg")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "1768528319")

# Your Railway public URL — e.g. https://yourapp.up.railway.app
# Find it in Railway: your service → Settings → Networking → Public URL
RAILWAY_PUBLIC_URL = os.environ.get("RAILWAY_PUBLIC_URL", "https://scanner-production-631c.up.railway.app")

# Secret header value Helius will send with every webhook call.
# Set this to any random string (e.g. openssl rand -hex 16) in Railway env vars
# and paste the same value when registering the webhook.
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")

# Port the webhook HTTP server listens on (Railway maps this automatically)
WEBHOOK_PORT = int(os.environ.get("PORT", "8080"))

# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------
SUPPLY_THRESHOLD_PCT   = float(os.environ.get("SUPPLY_THRESHOLD_PCT", "5.0"))
TIME_WINDOW_SECONDS    = int(os.environ.get("TIME_WINDOW_SECONDS", "300"))   # 5 minutes
MIN_COORDINATED_WALLETS = int(os.environ.get("MIN_COORDINATED_WALLETS", "2"))
BUY_SIZE_RATIO_MAX     = float(os.environ.get("BUY_SIZE_RATIO_MAX", "2.0"))

# ---------------------------------------------------------------------------
# Wallet classification
# ---------------------------------------------------------------------------
MAX_WALLET_TX_COUNT = int(os.environ.get("MAX_WALLET_TX_COUNT", "10"))
MAX_WALLET_AGE_DAYS = int(os.environ.get("MAX_WALLET_AGE_DAYS", "30"))

# ---------------------------------------------------------------------------
# Token filters
# ---------------------------------------------------------------------------
TOKEN_MIN_AGE_SECONDS = int(os.environ.get("TOKEN_MIN_AGE_SECONDS", "86400"))  # 24h

# ---------------------------------------------------------------------------
# Operational
# ---------------------------------------------------------------------------
ALERT_COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "3600"))  # 1h
