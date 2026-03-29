"""
Configuration for Pump.fun Coordinated Wallet Scanner.
Set these via environment variables or edit directly.
"""

import os

# ---------------------------------------------------------------------------
# Required credentials — set as environment variables on Railway
# ---------------------------------------------------------------------------
HELIUS_API_KEY = os.environ.get("HELIUS_API_KEY", "915dd768-93a2-44dc-9577-32d6cc548601")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8628775758:AAH76VBVEHvxV2lw2nqG-qAHgW9YDTIp8yg")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "1768528319")

# ---------------------------------------------------------------------------
# Detection thresholds — tune these to reduce noise or catch more signals
# ---------------------------------------------------------------------------

# Minimum % of total token supply collectively held to trigger alert
SUPPLY_THRESHOLD_PCT = float(os.environ.get("SUPPLY_THRESHOLD_PCT", "5.0"))

# Time window in seconds — buys must occur within this window to count as coordinated
TIME_WINDOW_SECONDS = int(os.environ.get("TIME_WINDOW_SECONDS", "300"))  # 5 minutes

# Minimum number of distinct suspicious wallets buying in the same window
MIN_COORDINATED_WALLETS = int(os.environ.get("MIN_COORDINATED_WALLETS", "2"))

# Max ratio between largest and smallest buy size (2x = within same ballpark)
BUY_SIZE_RATIO_MAX = float(os.environ.get("BUY_SIZE_RATIO_MAX", "2.0"))

# ---------------------------------------------------------------------------
# Wallet classification — what counts as suspicious
# ---------------------------------------------------------------------------

# Wallets with this many or fewer total transactions = fresh/low-activity
MAX_WALLET_TX_COUNT = int(os.environ.get("MAX_WALLET_TX_COUNT", "10"))

# Wallets older than this (in days) with few txs = dormant
MAX_WALLET_AGE_DAYS = int(os.environ.get("MAX_WALLET_AGE_DAYS", "30"))

# ---------------------------------------------------------------------------
# Token filters
# ---------------------------------------------------------------------------

# Only scan tokens older than this (seconds). Default = 24 hours
TOKEN_MIN_AGE_SECONDS = int(os.environ.get("TOKEN_MIN_AGE_SECONDS", "86400"))

# ---------------------------------------------------------------------------
# Operational settings
# ---------------------------------------------------------------------------

# How often to run a full scan cycle (seconds)
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "30"))

# Don't re-alert the same cluster within this window (seconds). Default = 1 hour
ALERT_COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "3600"))
