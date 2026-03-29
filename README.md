# Pump.fun Coordinated Wallet Scanner

Monitors older pump.fun tokens for coordinated accumulation by fresh/dormant wallets and fires Telegram alerts.

---

## How it works

Every 30 seconds the scanner:
1. Fetches recent transactions for pump.fun tokens older than 24 hours
2. Identifies buy transactions and classifies buyer wallets (fresh, dormant, low-activity)
3. Groups suspicious wallets buying the same token within a 5-minute window
4. Fires a Telegram alert if ≥2 suspicious wallets collectively hold >5% of supply with similar buy sizes

---

## Setup

### 1. Get a Helius API key (free)
- Go to [helius.dev](https://helius.dev) and sign up
- Copy your API key from the dashboard

### 2. Create a Telegram bot
- Message [@BotFather](https://t.me/BotFather) on Telegram
- Send `/newbot` and follow the prompts
- Copy the bot token it gives you

### 3. Get your Telegram chat ID
- Start a chat with your new bot (send it any message)
- Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
- Find `"chat":{"id": XXXXXXXXX}` — that number is your chat ID

### 4. Deploy to Railway (free)

1. Push this folder to a GitHub repo
2. Go to [railway.app](https://railway.app) and sign in with GitHub
3. Click **New Project → Deploy from GitHub repo** → select your repo
4. Go to your service → **Variables** tab → add:

| Variable | Value |
|---|---|
| `HELIUS_API_KEY` | your Helius key |
| `TELEGRAM_BOT_TOKEN` | your bot token |
| `TELEGRAM_CHAT_ID` | your chat ID |

5. Railway will auto-deploy. Your bot sends a startup message when it's live.

---

## Tuning (optional environment variables)

| Variable | Default | Description |
|---|---|---|
| `SUPPLY_THRESHOLD_PCT` | `5.0` | Min % of supply to trigger alert |
| `TIME_WINDOW_SECONDS` | `300` | Buy window to detect coordination (seconds) |
| `MIN_COORDINATED_WALLETS` | `2` | Min suspicious wallets in cluster |
| `BUY_SIZE_RATIO_MAX` | `2.0` | Max size ratio between buys (similar size check) |
| `MAX_WALLET_TX_COUNT` | `10` | Max txs for a wallet to count as fresh/low-activity |
| `MAX_WALLET_AGE_DAYS` | `30` | Age threshold (days) for dormant classification |
| `TOKEN_MIN_AGE_SECONDS` | `86400` | Min token age to scan (default 24h) |
| `POLL_INTERVAL_SECONDS` | `30` | Scan frequency |
| `ALERT_COOLDOWN_SECONDS` | `3600` | Min time between repeat alerts for same cluster |

---

## Alert format

```
🚨 Coordinated Accumulation Detected

🪙 Token: <mint address>
🔗 View on Pump.fun

📊 3 wallets bought 7.42% of supply within 5 min window
⏰ Window started: 14:23:01 UTC

Wallet Breakdown:
🆕 Fresh [abc1…ef23] — 2 txs, 1d old, 2.8% supply
💤 Dormant [xyz9…ab12] — 8 txs, 94d old, 2.3% supply
🆕 Fresh [qqq4…cc89] — 1 tx, age unknown, 2.3% supply

Full token on Solscan
```

---

## Running locally

```bash
pip install -r requirements.txt
export HELIUS_API_KEY=...
export TELEGRAM_BOT_TOKEN=...
export TELEGRAM_CHAT_ID=...
python scanner.py
```
