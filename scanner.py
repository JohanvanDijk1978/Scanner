"""
Pump.fun Coordinated Wallet Scanner — Webhook Edition
Real-time detection via Helius webhooks. No polling.

Helius pushes every pump.fun transaction to /webhook instantly.
We run a lightweight aiohttp server to receive them.

Commands (all users):
  /info         — current thresholds + live stats
  /status       — uptime, tokens processed, last tx time
  /threshold N  — set supply % trigger
  /minwallets N — set min coordinated wallets
  /window N     — set time window in minutes
  /dormantage N — set dormant wallet age threshold in days
  /wallet ADDR  — profile a specific wallet
  /token MINT   — show suspicious holders for a token
  /cluster MINT — show all detected clusters for a token
  /recent       — last 10 alerts fired
  /stats        — detection totals

Owner only:
  /users        — see who has interacted with the bot
"""

import asyncio
import json
import logging
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from aiohttp import web
import httpx
from telegram import Bot, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

from config import (
    HELIUS_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    WEBHOOK_SECRET,
    SUPPLY_THRESHOLD_PCT,
    TIME_WINDOW_SECONDS,
    MIN_COORDINATED_WALLETS,
    BUY_SIZE_RATIO_MAX,
    TOKEN_MIN_AGE_SECONDS,
    ALERT_COOLDOWN_SECONDS,
    MAX_WALLET_TX_COUNT,
    MAX_WALLET_AGE_DAYS,
    WEBHOOK_PORT,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

HELIUS_RPC = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
PUMP_FUN_PROGRAM = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"

# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------
state = {
    "supply_threshold_pct": SUPPLY_THRESHOLD_PCT,
    "time_window_seconds": TIME_WINDOW_SECONDS,
    "min_coordinated_wallets": MIN_COORDINATED_WALLETS,
    "buy_size_ratio_max": BUY_SIZE_RATIO_MAX,
    "max_wallet_tx_count": MAX_WALLET_TX_COUNT,
    "max_wallet_age_days": MAX_WALLET_AGE_DAYS,
}

STATE_FILE = Path("/app/state.json")
USERS_FILE = Path("/app/users.json")

alerted_clusters: dict[str, float] = {}
# Per-token sliding window of buys: {mint: [{"wallet", "amount", "timestamp"}]}
token_buy_windows: dict[str, deque] = {}
token_clusters: dict[str, list] = {}
recent_alerts: deque = deque(maxlen=10)
known_users: dict[str, dict] = {}

BOT_START_TIME: float = 0.0
LAST_TX_TIME: float = 0.0
TOTAL_TXS_RECEIVED: int = 0
TOTAL_CLUSTERS_FOUND: int = 0
TOTAL_ALERTS_SENT: int = 0

_http_client: httpx.AsyncClient | None = None
_app: Application | None = None  # telegram app ref for webhook handler


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def load_state():
    global state
    try:
        if STATE_FILE.exists():
            saved = json.loads(STATE_FILE.read_text())
            for k in state:
                if k in saved:
                    state[k] = saved[k]
            log.info("Loaded persisted state")
    except Exception as e:
        log.warning(f"Could not load state: {e}")


def save_state():
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2))
    except Exception as e:
        log.warning(f"Could not save state: {e}")


def load_users():
    global known_users
    try:
        if USERS_FILE.exists():
            known_users = json.loads(USERS_FILE.read_text())
            log.info(f"Loaded {len(known_users)} known users")
    except Exception as e:
        log.warning(f"Could not load users: {e}")


def save_users():
    try:
        USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        USERS_FILE.write_text(json.dumps(known_users, indent=2))
    except Exception as e:
        log.warning(f"Could not save users: {e}")


def is_owner(update: Update) -> bool:
    return str(update.effective_chat.id) == str(TELEGRAM_CHAT_ID)


async def track_user(update: Update, app: Application):
    chat_id = str(update.effective_chat.id)
    user = update.effective_user
    username = f"@{user.username}" if user and user.username else (user.full_name if user else "unknown")
    command = update.message.text.split()[0] if update.message and update.message.text else "unknown"
    now = time.time()
    is_new = chat_id not in known_users

    if is_new:
        known_users[chat_id] = {
            "username": username,
            "first_seen": now,
            "last_seen": now,
            "command_count": 1,
            "last_command": command,
        }
    else:
        known_users[chat_id]["last_seen"] = now
        known_users[chat_id]["command_count"] = known_users[chat_id].get("command_count", 0) + 1
        known_users[chat_id]["last_command"] = command
        known_users[chat_id]["username"] = username

    save_users()

    if is_new and not is_owner(update):
        strangers = sum(1 for uid in known_users if uid != str(TELEGRAM_CHAT_ID))
        try:
            await app.bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=(
                    f"👀 *New user found your bot*\n\n"
                    f"  User: `{username}`\n"
                    f"  Chat ID: `{chat_id}`\n"
                    f"  Command: `{command}`\n"
                    f"  Time: `{datetime.fromtimestamp(now, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}`\n\n"
                    f"Total non-owner users: `{strangers}`"
                ),
                parse_mode=ParseMode.MARKDOWN,
            )
        except Exception as e:
            log.warning(f"Could not send new user alert: {e}")


# ---------------------------------------------------------------------------
# RPC / Helius helpers
# ---------------------------------------------------------------------------

async def rpc_post(method: str, params: list) -> dict:
    resp = await _http_client.post(
        HELIUS_RPC,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data.get("result", {})


async def get_token_supply(mint: str) -> int:
    result = await rpc_post("getTokenSupply", [mint])
    return int(result.get("value", {}).get("amount", 0))


async def get_wallet_info(wallet: str) -> dict:
    sigs_result = await rpc_post("getSignaturesForAddress", [wallet, {"limit": 1000}])
    tx_count = len(sigs_result) if isinstance(sigs_result, list) else 0
    age_days = None
    first_seen = None
    last_seen = None
    if isinstance(sigs_result, list) and sigs_result:
        block_time = sigs_result[-1].get("blockTime")
        if block_time:
            age_days = (time.time() - block_time) / 86400
        first_seen = sigs_result[-1].get("blockTime")
        last_seen = sigs_result[0].get("blockTime")
    return {
        "address": wallet,
        "tx_count": tx_count,
        "age_days": age_days,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


async def get_wallet_swaps(wallet: str) -> list[dict]:
    url = (
        f"https://api.helius.xyz/v0/addresses/{wallet}/transactions"
        f"?api-key={HELIUS_API_KEY}&limit=100&type=SWAP"
    )
    resp = await _http_client.get(url, timeout=30)
    resp.raise_for_status()
    txs = resp.json()
    # Attach timestamps clearly for time-window filtering
    return txs


async def get_wallet_token_balances(wallet: str) -> list[dict]:
    result = await rpc_post(
        "getTokenAccountsByOwner",
        [
            wallet,
            {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
            {"encoding": "jsonParsed"},
        ],
    )
    balances = []
    for acc in result.get("value", []):
        parsed = acc.get("account", {}).get("data", {}).get("parsed", {})
        info = parsed.get("info", {})
        mint = info.get("mint")
        amount = float(info.get("tokenAmount", {}).get("uiAmount") or 0)
        if mint and amount > 0:
            balances.append({"mint": mint, "amount": amount})
    return balances


async def get_recent_token_txs(mint: str) -> list[dict]:
    url = (
        f"https://api.helius.xyz/v0/addresses/{mint}/transactions"
        f"?api-key={HELIUS_API_KEY}&limit=50&type=SWAP"
    )
    resp = await _http_client.get(url, timeout=20)
    resp.raise_for_status()
    return resp.json()


async def get_jupiter_prices(mints: list[str]) -> dict[str, float]:
    if not mints:
        return {}
    ids = ",".join(mints[:100])
    try:
        resp = await _http_client.get(f"https://price.jup.ag/v6/price?ids={ids}", timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {mint: data[mint]["price"] for mint in data if "price" in data[mint]}
    except Exception as e:
        log.warning(f"Jupiter price fetch failed: {e}")
        return {}


async def register_helius_webhook(public_url: str):
    """Register (or update) the Helius webhook pointing to our /webhook endpoint."""
    endpoint = f"https://api.helius.xyz/v0/webhooks?api-key={HELIUS_API_KEY}"

    # Check if webhook already exists
    resp = await _http_client.get(endpoint, timeout=10)
    resp.raise_for_status()
    existing = resp.json()

    webhook_url = f"{public_url}/webhook"
    payload = {
        "webhookURL": webhook_url,
        "transactionTypes": ["SWAP"],
        "accountAddresses": [PUMP_FUN_PROGRAM],
        "webhookType": "enhanced",
        "authHeader": WEBHOOK_SECRET,
    }

    for hook in existing:
        if hook.get("webhookURL") == webhook_url:
            hook_id = hook["webhookID"]
            r = await _http_client.put(
                f"https://api.helius.xyz/v0/webhooks/{hook_id}?api-key={HELIUS_API_KEY}",
                json=payload,
                timeout=10,
            )
            r.raise_for_status()
            log.info(f"Updated existing Helius webhook {hook_id} → {webhook_url}")
            return

    r = await _http_client.post(endpoint, json=payload, timeout=10)
    r.raise_for_status()
    log.info(f"Registered new Helius webhook → {webhook_url}")


# ---------------------------------------------------------------------------
# Wallet classification
# ---------------------------------------------------------------------------

def is_suspicious_wallet(wallet_info: dict) -> bool:
    tx_count = wallet_info.get("tx_count", 9999)
    age_days = wallet_info.get("age_days")
    if tx_count <= state["max_wallet_tx_count"]:
        return True
    if age_days is not None and age_days > state["max_wallet_age_days"] and tx_count <= state["max_wallet_tx_count"] * 3:
        return True
    return False


def wallet_label(wallet_info: dict) -> str:
    tx_count = wallet_info.get("tx_count", 9999)
    age_days = wallet_info.get("age_days")
    if tx_count <= 5:
        return "🆕 Fresh"
    if age_days is not None and age_days > state["max_wallet_age_days"]:
        return "💤 Dormant"
    return "⚠️ Low-activity"


def parse_trade_pnl(txs: list[dict], wallet: str, since: float | None = None) -> dict:
    """
    Parse swap history to compute win rate, best/worst trade, open positions.
    If `since` is provided (unix timestamp), only include transactions after that time.
    """
    SOL_MINT = "So11111111111111111111111111111111111111112"
    token_flows: dict[str, dict] = {}

    for tx in txs:
        ts = tx.get("timestamp", 0)
        if since is not None and ts < since:
            continue

        native = tx.get("nativeTransfers", [])
        sol_spent = sum(t.get("amount", 0) / 1e9 for t in native if t.get("fromUserAccount") == wallet)
        sol_received = sum(t.get("amount", 0) / 1e9 for t in native if t.get("toUserAccount") == wallet)

        for t in tx.get("tokenTransfers", []):
            mint = t.get("mint")
            if not mint or mint == SOL_MINT:
                continue
            if mint not in token_flows:
                token_flows[mint] = {"sol_in": 0, "sol_out": 0, "token_in": 0, "token_out": 0}
            amount = int(t.get("tokenAmount", 0))
            if t.get("toUserAccount") == wallet:
                token_flows[mint]["token_in"] += amount
                token_flows[mint]["sol_in"] += sol_spent
            elif t.get("fromUserAccount") == wallet:
                token_flows[mint]["token_out"] += amount
                token_flows[mint]["sol_out"] += sol_received

    trades = []
    open_positions = {}
    for mint, flow in token_flows.items():
        if flow["sol_in"] == 0:
            continue
        pnl_sol = flow["sol_out"] - flow["sol_in"]
        if flow["sol_out"] > 0:
            trades.append({
                "mint": mint,
                "sol_in": flow["sol_in"],
                "sol_out": flow["sol_out"],
                "pnl_sol": pnl_sol,
                "won": pnl_sol > 0,
            })
        if flow["token_in"] > flow["token_out"]:
            open_positions[mint] = {
                "mint": mint,
                "token_balance": flow["token_in"] - flow["token_out"],
                "sol_invested": flow["sol_in"],
                "sol_recovered": flow["sol_out"],
            }

    wins = sum(1 for t in trades if t["won"])
    total_closed = len(trades)
    return {
        "trades": trades,
        "win_rate": (wins / total_closed * 100) if total_closed > 0 else None,
        "total_closed": total_closed,
        "wins": wins,
        "best_trade": max(trades, key=lambda t: t["pnl_sol"]) if trades else None,
        "worst_trade": min(trades, key=lambda t: t["pnl_sol"]) if trades else None,
        "open_positions": open_positions,
    }


# ---------------------------------------------------------------------------
# Core detection — called on every incoming webhook transaction
# ---------------------------------------------------------------------------

def is_token_old_enough(mint: str) -> bool:
    """Only process tokens that have been seen for > TOKEN_MIN_AGE_SECONDS."""
    first_seen = token_buy_windows.get(mint + ":first_seen")
    if first_seen is None:
        return False
    return (time.time() - first_seen) >= TOKEN_MIN_AGE_SECONDS


def record_token_first_seen(mint: str, ts: float):
    key = mint + ":first_seen"
    if key not in token_buy_windows:
        token_buy_windows[key] = ts


async def process_transaction(tx: dict):
    """Process a single transaction pushed by Helius webhook."""
    global TOTAL_TXS_RECEIVED, TOTAL_CLUSTERS_FOUND, LAST_TX_TIME

    TOTAL_TXS_RECEIVED += 1
    LAST_TX_TIME = time.time()

    ts = tx.get("timestamp", time.time())

    # Extract token transfers — find buys (wallet received tokens)
    for transfer in tx.get("tokenTransfers", []):
        mint = transfer.get("mint")
        to_user = transfer.get("toUserAccount")
        amount = int(transfer.get("tokenAmount", 0))

        if not mint or not to_user or amount == 0:
            continue

        # Track when we first saw each token
        record_token_first_seen(mint, ts)

        # Skip tokens younger than TOKEN_MIN_AGE_SECONDS
        if not is_token_old_enough(mint):
            continue

        # Add to per-token sliding window
        if mint not in token_buy_windows:
            token_buy_windows[mint] = deque()

        token_buy_windows[mint].append({
            "wallet": to_user,
            "amount": amount,
            "timestamp": ts,
        })

        # Prune entries older than the time window
        tw = state["time_window_seconds"]
        while token_buy_windows[mint] and ts - token_buy_windows[mint][0]["timestamp"] > tw:
            token_buy_windows[mint].popleft()

        # Check for coordination in current window
        window = list(token_buy_windows[mint])
        if len(window) < state["min_coordinated_wallets"]:
            continue

        # Deduplicate by wallet (keep largest buy per wallet)
        seen: dict[str, dict] = {}
        for b in window:
            w = b["wallet"]
            if w not in seen or b["amount"] > seen[w]["amount"]:
                seen[w] = b

        if len(seen) < state["min_coordinated_wallets"]:
            continue

        # Similar buy size check
        amounts = [v["amount"] for v in seen.values()]
        min_amt, max_amt = min(amounts), max(amounts)
        if min_amt == 0 or (max_amt / min_amt) > state["buy_size_ratio_max"]:
            continue

        # Supply threshold check
        try:
            total_supply = await get_token_supply(mint)
        except Exception as e:
            log.warning(f"Could not get supply for {mint}: {e}")
            continue

        if total_supply == 0:
            continue

        total_bought = sum(amounts)
        pct = (total_bought / total_supply) * 100
        if pct < state["supply_threshold_pct"]:
            continue

        # Fetch wallet profiles
        wallet_infos = {}
        for entry in seen.values():
            w = entry["wallet"]
            try:
                wallet_infos[w] = await get_wallet_info(w)
            except Exception as e:
                log.warning(f"Wallet info failed for {w}: {e}")
                wallet_infos[w] = {}

        # All must be suspicious
        all_suspicious = all(is_suspicious_wallet(wallet_infos.get(e["wallet"], {})) for e in seen.values())
        if not all_suspicious:
            continue

        cluster = {
            "wallets": list(seen.values()),
            "total_bought": total_bought,
            "supply_pct": pct,
            "window_start": window[0]["timestamp"],
            "window_end": ts,
        }

        TOTAL_CLUSTERS_FOUND += 1
        token_clusters[mint] = token_clusters.get(mint, []) + [cluster]

        await send_telegram_alert(_app.bot, mint, cluster, wallet_infos)


# ---------------------------------------------------------------------------
# Webhook HTTP server
# ---------------------------------------------------------------------------

async def handle_webhook(request: web.Request) -> web.Response:
    """Receive and process Helius webhook POST."""
    # Verify secret
    auth = request.headers.get("Authorization", "")
    if WEBHOOK_SECRET and auth != WEBHOOK_SECRET:
        log.warning("Webhook received with invalid secret")
        return web.Response(status=401, text="Unauthorized")

    try:
        txs = await request.json()
        if not isinstance(txs, list):
            txs = [txs]
    except Exception as e:
        log.warning(f"Could not parse webhook body: {e}")
        return web.Response(status=400, text="Bad Request")

    # Process each transaction asynchronously (don't block the response)
    for tx in txs:
        asyncio.create_task(process_transaction(tx))

    return web.Response(status=200, text="OK")


async def handle_health(request: web.Request) -> web.Response:
    return web.Response(status=200, text="OK")


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def cluster_key(mint: str, cluster: dict) -> str:
    wallets = sorted(w["wallet"] for w in cluster["wallets"])
    return f"{mint}:{':'.join(wallets)}"


async def send_telegram_alert(bot: Bot, mint: str, cluster: dict, wallet_infos: dict):
    global TOTAL_ALERTS_SENT
    now = time.time()
    key = cluster_key(mint, cluster)
    if key in alerted_clusters and (now - alerted_clusters[key]) < ALERT_COOLDOWN_SECONDS:
        return
    alerted_clusters[key] = now
    TOTAL_ALERTS_SENT += 1

    pct = cluster["supply_pct"]
    n = len(cluster["wallets"])
    tw_min = state["time_window_seconds"] // 60
    window_start = datetime.fromtimestamp(cluster["window_start"], tz=timezone.utc).strftime("%H:%M:%S UTC")

    lines = [
        "🚨 *Coordinated Accumulation Detected*",
        "",
        f"🪙 Token: `{mint}`",
        f"🔗 [Pump.fun](https://pump.fun/{mint}) | [Solscan](https://solscan.io/token/{mint})",
        "",
        f"📊 *{n} wallets* accumulated *{pct:.2f}% of supply* in {tw_min}min window",
        f"⏰ Window: {window_start}",
        "",
        "*Wallet Breakdown:*",
    ]

    for entry in cluster["wallets"]:
        w = entry["wallet"]
        amt = entry["amount"]
        info = wallet_infos.get(w, {})
        tx_count = info.get("tx_count", "?")
        age = info.get("age_days")
        age_str = f"{age:.0f}d old" if age is not None else "age unknown"
        individual_pct = (amt / cluster["total_bought"]) * pct
        label = wallet_label(info)
        lines.append(
            f"{label} [`{w[:6]}…{w[-4:]}`](https://solscan.io/account/{w}) "
            f"— {tx_count} txs, {age_str}, {individual_pct:.2f}% supply"
        )

    recent_alerts.appendleft({
        "mint": mint,
        "pct": pct,
        "n_wallets": n,
        "timestamp": now,
    })

    try:
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text="\n".join(lines),
            parse_mode=ParseMode.MARKDOWN,
            disable_web_page_preview=True,
        )
        log.info(f"Alert sent for {mint}, {n} wallets, {pct:.2f}%")
    except Exception as e:
        log.error(f"Telegram send failed: {e}")


# ---------------------------------------------------------------------------
# Bot commands
# ---------------------------------------------------------------------------

def fmt_uptime() -> str:
    secs = int(time.time() - BOT_START_TIME)
    h, r = divmod(secs, 3600)
    m, s = divmod(r, 60)
    return f"{h}h {m}m {s}s"


async def cmd_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    s = state
    msg = (
        "ℹ️ *Scanner Info*\n\n"
        "*Detection Thresholds*\n"
        f"  Supply threshold: `{s['supply_threshold_pct']}%`\n"
        f"  Time window: `{s['time_window_seconds'] // 60} min`\n"
        f"  Min coordinated wallets: `{s['min_coordinated_wallets']}`\n"
        f"  Max buy size ratio: `{s['buy_size_ratio_max']}x`\n\n"
        "*Wallet Classification*\n"
        f"  Max txs (fresh): `{s['max_wallet_tx_count']}`\n"
        f"  Dormant age: `{s['max_wallet_age_days']} days`\n\n"
        "*Token Filters*\n"
        f"  Min token age: `{TOKEN_MIN_AGE_SECONDS // 3600}h`\n\n"
        "*Operational*\n"
        f"  Mode: `webhook (real-time)`\n"
        f"  Alert cooldown: `{ALERT_COOLDOWN_SECONDS // 3600}h`\n"
        f"  Tokens tracked: `{len([k for k in token_buy_windows if not k.endswith(':first_seen')])}`\n"
        f"  Clusters alerted: `{len(alerted_clusters)}`\n"
        f"  Uptime: `{fmt_uptime()}`\n\n"
        "*Commands*\n"
        "/status /threshold /minwallets /window /dormantage\n"
        "/wallet /token /cluster /recent /stats"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    last_tx = (
        datetime.fromtimestamp(LAST_TX_TIME, tz=timezone.utc).strftime("%H:%M:%S UTC")
        if LAST_TX_TIME else "none yet"
    )
    msg = (
        "📡 *Scanner Status*\n\n"
        f"  Mode: `webhook (real-time)`\n"
        f"  Uptime: `{fmt_uptime()}`\n"
        f"  Last tx received: `{last_tx}`\n"
        f"  Txs processed: `{TOTAL_TXS_RECEIVED}`\n"
        f"  Clusters found: `{TOTAL_CLUSTERS_FOUND}`\n"
        f"  Alerts sent: `{TOTAL_ALERTS_SENT}`\n"
        f"  Tokens in window: `{len([k for k in token_buy_windows if not k.endswith(':first_seen')])}`\n"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_threshold(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    try:
        val = float(context.args[0])
        assert 0.1 <= val <= 100
    except (IndexError, ValueError, AssertionError):
        await update.message.reply_text("Usage: `/threshold 3` (0.1–100)", parse_mode=ParseMode.MARKDOWN)
        return
    old = state["supply_threshold_pct"]
    state["supply_threshold_pct"] = val
    save_state()
    await update.message.reply_text(f"✅ Supply threshold: `{old}%` → `{val}%`", parse_mode=ParseMode.MARKDOWN)


async def cmd_minwallets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    try:
        val = int(context.args[0])
        assert 2 <= val <= 20
    except (IndexError, ValueError, AssertionError):
        await update.message.reply_text("Usage: `/minwallets 3` (2–20)", parse_mode=ParseMode.MARKDOWN)
        return
    old = state["min_coordinated_wallets"]
    state["min_coordinated_wallets"] = val
    save_state()
    await update.message.reply_text(f"✅ Min wallets: `{old}` → `{val}`", parse_mode=ParseMode.MARKDOWN)


async def cmd_window(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    try:
        val = int(context.args[0])
        assert 1 <= val <= 60
    except (IndexError, ValueError, AssertionError):
        await update.message.reply_text("Usage: `/window 10` (1–60 minutes)", parse_mode=ParseMode.MARKDOWN)
        return
    old = state["time_window_seconds"] // 60
    state["time_window_seconds"] = val * 60
    save_state()
    await update.message.reply_text(f"✅ Time window: `{old} min` → `{val} min`", parse_mode=ParseMode.MARKDOWN)


async def cmd_dormantage(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    try:
        val = int(context.args[0])
        assert 1 <= val <= 3650
    except (IndexError, ValueError, AssertionError):
        await update.message.reply_text("Usage: `/dormantage 60` (days)", parse_mode=ParseMode.MARKDOWN)
        return
    old = state["max_wallet_age_days"]
    state["max_wallet_age_days"] = val
    save_state()
    await update.message.reply_text(f"✅ Dormant age: `{old} days` → `{val} days`", parse_mode=ParseMode.MARKDOWN)


async def cmd_wallet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    if not context.args:
        await update.message.reply_text("Usage: `/wallet <solana_address>`", parse_mode=ParseMode.MARKDOWN)
        return

    addr = context.args[0].strip()
    await update.message.reply_text(
        f"🔍 Pulling full profile for `{addr[:8]}…` — this takes a few seconds…",
        parse_mode=ParseMode.MARKDOWN,
    )

    try:
        info, swaps, balances = await asyncio.gather(
            get_wallet_info(addr),
            get_wallet_swaps(addr),
            get_wallet_token_balances(addr),
        )
    except Exception as e:
        await update.message.reply_text(f"❌ Error fetching wallet data: {e}")
        return

    trading_all  = parse_trade_pnl(swaps, addr)
    trading_30d  = parse_trade_pnl(swaps, addr, since=time.time() - 86400 * 30)
    trading_24h  = parse_trade_pnl(swaps, addr, since=time.time() - 86400)

    all_mints = list(set(list(trading_all["open_positions"].keys()) + [b["mint"] for b in balances[:10]]))
    prices = await get_jupiter_prices(all_mints) if all_mints else {}

    tx_count = info.get("tx_count", 0)
    age_days = info.get("age_days")
    first_seen = info.get("first_seen")
    last_seen = info.get("last_seen")
    suspicious = is_suspicious_wallet(info)
    label = wallet_label(info)

    lines = [
        f"👛 *Wallet Profile*",
        f"[`{addr[:6]}…{addr[-4:]}`](https://solscan.io/account/{addr})",
        f"",
        f"*Identity*",
        f"  Classification: {label} {'⚠️' if suspicious else '✅'}",
        f"  Age: `{age_days:.0f}d`" if age_days else "  Age: `unknown`",
        f"  Txs: `{tx_count}`",
        f"  First tx: `{datetime.fromtimestamp(first_seen, tz=timezone.utc).strftime('%Y-%m-%d') if first_seen else 'unknown'}`",
        f"  Last tx: `{datetime.fromtimestamp(last_seen, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if last_seen else 'unknown'}`",
        f"",
        f"*Trading Stats*",
    ]

    def fmt_window(label: str, t: dict) -> str:
        if t["total_closed"] == 0:
            return f"  {label}: `no closed trades`"
        wr = t["win_rate"]
        wins = t["wins"]
        total = t["total_closed"]
        pnl = sum(tr["pnl_sol"] for tr in t["trades"])
        sign = "+" if pnl >= 0 else ""
        return f"  {label}: `{wr:.1f}%` ({wins}W/{total - wins}L) — PnL: `{sign}{pnl:.3f} SOL`"

    lines.append(fmt_window("Last 24h ", trading_24h))
    lines.append(fmt_window("Last 30d ", trading_30d))
    lines.append(fmt_window("All-time ", trading_all))

    # Best and worst from all-time
    if trading_all["best_trade"]:
        b = trading_all["best_trade"]
        sign = "+" if b["pnl_sol"] >= 0 else ""
        lines.append(f"  Best trade: `{sign}{b['pnl_sol']:.3f} SOL` ([`{b['mint'][:6]}…`](https://solscan.io/token/{b['mint']}))")
    if trading_all["worst_trade"] and trading_all["worst_trade"]["mint"] != (trading_all["best_trade"]["mint"] if trading_all["best_trade"] else None):
        w = trading_all["worst_trade"]
        lines.append(f"  Worst trade: `{w['pnl_sol']:.3f} SOL` ([`{w['mint'][:6]}…`](https://solscan.io/token/{w['mint']}))")

    if trading_all["open_positions"]:
        lines += ["", "*Open Positions*"]
        for mint, pos in list(trading_all["open_positions"].items())[:5]:
            price_usd = prices.get(mint)
            unrealised = f" ≈ ${pos['token_balance'] * price_usd / 1e6:.2f}" if price_usd else ""
            lines.append(f"  [`{mint[:6]}…`](https://solscan.io/token/{mint}) — {pos['sol_invested']:.3f} SOL in, {pos['sol_recovered']:.3f} SOL out{unrealised}")

    if balances:
        lines += ["", "*Current Token Holdings*"]
        for b in balances[:5]:
            price_usd = prices.get(b["mint"])
            val_str = f" ≈ ${b['amount'] * price_usd:.2f}" if price_usd else ""
            lines.append(f"  [`{b['mint'][:6]}…`](https://solscan.io/token/{b['mint']}) — {b['amount']:,.0f} tokens{val_str}")
        if len(balances) > 5:
            lines.append(f"  _…and {len(balances) - 5} more_")

    lines.append(f"\n[View on Solscan](https://solscan.io/account/{addr})")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)


async def cmd_token(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    if not context.args:
        await update.message.reply_text("Usage: `/token <mint_address>`", parse_mode=ParseMode.MARKDOWN)
        return

    mint = context.args[0].strip()
    await update.message.reply_text(f"🔍 Scanning token `{mint[:8]}…`", parse_mode=ParseMode.MARKDOWN)

    try:
        supply = await get_token_supply(mint)
        txs = await get_recent_token_txs(mint)
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")
        return

    buys = []
    for tx in txs:
        for transfer in tx.get("tokenTransfers", []):
            if transfer.get("mint") != mint:
                continue
            to_user = transfer.get("toUserAccount")
            amount = int(transfer.get("tokenAmount", 0))
            if to_user and amount > 0:
                buys.append({"wallet": to_user, "amount": amount})

    if not buys:
        await update.message.reply_text("No recent buy activity found.")
        return

    suspicious_found = []
    for w in list({b["wallet"] for b in buys})[:20]:
        try:
            info = await get_wallet_info(w)
            if is_suspicious_wallet(info):
                total_bought = sum(b["amount"] for b in buys if b["wallet"] == w)
                pct = (total_bought / supply * 100) if supply else 0
                suspicious_found.append({"info": info, "wallet": w, "pct": pct})
        except Exception:
            continue

    if not suspicious_found:
        await update.message.reply_text(f"✅ No suspicious wallets found for `{mint[:8]}…`", parse_mode=ParseMode.MARKDOWN)
        return

    lines = [
        f"🪙 *Suspicious holders of* `{mint[:8]}…`",
        f"[Pump.fun](https://pump.fun/{mint}) | [Solscan](https://solscan.io/token/{mint})",
        f"Found `{len(suspicious_found)}` suspicious wallet(s):\n",
    ]
    for entry in suspicious_found:
        w = entry["wallet"]
        info = entry["info"]
        age = info.get("age_days")
        lines.append(
            f"{wallet_label(info)} [`{w[:6]}…{w[-4:]}`](https://solscan.io/account/{w}) "
            f"— {info['tx_count']} txs, {f'{age:.0f}d' if age else '?'} old, ~{entry['pct']:.2f}%"
        )

    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)


async def cmd_cluster(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    if not context.args:
        await update.message.reply_text("Usage: `/cluster <mint_address>`", parse_mode=ParseMode.MARKDOWN)
        return

    mint = context.args[0].strip()
    clusters = token_clusters.get(mint)

    if not clusters:
        await update.message.reply_text(f"No clusters detected for `{mint[:8]}…` yet.", parse_mode=ParseMode.MARKDOWN)
        return

    lines = [f"🔬 *Clusters for* `{mint[:8]}…`\n"]
    for i, c in enumerate(clusters, 1):
        ws = datetime.fromtimestamp(c["window_start"], tz=timezone.utc).strftime("%H:%M:%S UTC")
        lines.append(f"*Cluster {i}* — {len(c['wallets'])} wallets, {c['supply_pct']:.2f}% supply, at {ws}")
        for entry in c["wallets"]:
            w = entry["wallet"]
            lines.append(f"  • [`{w[:6]}…{w[-4:]}`](https://solscan.io/account/{w})")
        lines.append("")

    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)


async def cmd_recent(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    if not recent_alerts:
        await update.message.reply_text("No alerts fired yet this session.")
        return

    lines = ["📋 *Recent Alerts*\n"]
    for i, a in enumerate(recent_alerts, 1):
        ts = datetime.fromtimestamp(a["timestamp"], tz=timezone.utc).strftime("%m/%d %H:%M UTC")
        mint = a["mint"]
        lines.append(f"`{i}.` [{mint[:8]}…](https://pump.fun/{mint}) — {a['n_wallets']} wallets, {a['pct']:.2f}% — {ts}")

    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    alert_rate = f"{(TOTAL_ALERTS_SENT / TOTAL_CLUSTERS_FOUND * 100):.1f}%" if TOTAL_CLUSTERS_FOUND > 0 else "n/a"
    msg = (
        "📊 *Detection Stats*\n\n"
        f"  Txs received: `{TOTAL_TXS_RECEIVED}`\n"
        f"  Clusters found: `{TOTAL_CLUSTERS_FOUND}`\n"
        f"  Alerts sent: `{TOTAL_ALERTS_SENT}`\n"
        f"  Alert rate: `{alert_rate}` of clusters\n"
        f"  Uptime: `{fmt_uptime()}`\n"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    if not is_owner(update):
        return

    owner_id = str(TELEGRAM_CHAT_ID)
    strangers = {uid: u for uid, u in known_users.items() if uid != owner_id}

    lines = [
        "👥 *User Activity*\n",
        f"Total unique visitors: `{len(known_users)}`",
        f"Non-owner attempts: `{len(strangers)}`\n",
    ]
    if not strangers:
        lines.append("No unauthorised users have tried the bot yet.")
    else:
        lines.append("*Unauthorised users:*")
        for uid, u in sorted(strangers.items(), key=lambda x: x[1].get("last_seen", 0), reverse=True):
            first = datetime.fromtimestamp(u["first_seen"], tz=timezone.utc).strftime("%m/%d %H:%M")
            last = datetime.fromtimestamp(u["last_seen"], tz=timezone.utc).strftime("%m/%d %H:%M")
            lines.append(
                f"\n  `{u['username']}` (ID: `{uid}`)\n"
                f"  {u.get('command_count', 1)} attempt(s) | first: {first} | last: {last}\n"
                f"  Last cmd: `{u.get('last_command', '?')}`"
            )

    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    global BOT_START_TIME, _http_client, _app

    log.info("🚀 Pump.fun Webhook Scanner starting...")

    from config import RAILWAY_PUBLIC_URL
    if not HELIUS_API_KEY or HELIUS_API_KEY == "YOUR_HELIUS_API_KEY":
        raise RuntimeError("HELIUS_API_KEY env var is not set")
    if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN":
        raise RuntimeError("TELEGRAM_BOT_TOKEN env var is not set")
    if not TELEGRAM_CHAT_ID or TELEGRAM_CHAT_ID == "YOUR_CHAT_ID":
        raise RuntimeError("TELEGRAM_CHAT_ID env var is not set")
    if not RAILWAY_PUBLIC_URL:
        raise RuntimeError("RAILWAY_PUBLIC_URL env var is not set (e.g. https://yourapp.up.railway.app)")

    BOT_START_TIME = time.time()
    load_state()
    load_users()
    _http_client = httpx.AsyncClient()

    # Build Telegram app
    _app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    _app.add_handler(CommandHandler("info",       cmd_info))
    _app.add_handler(CommandHandler("status",     cmd_status))
    _app.add_handler(CommandHandler("threshold",  cmd_threshold))
    _app.add_handler(CommandHandler("minwallets", cmd_minwallets))
    _app.add_handler(CommandHandler("window",     cmd_window))
    _app.add_handler(CommandHandler("dormantage", cmd_dormantage))
    _app.add_handler(CommandHandler("wallet",     cmd_wallet))
    _app.add_handler(CommandHandler("token",      cmd_token))
    _app.add_handler(CommandHandler("cluster",    cmd_cluster))
    _app.add_handler(CommandHandler("recent",     cmd_recent))
    _app.add_handler(CommandHandler("stats",      cmd_stats))
    _app.add_handler(CommandHandler("users",      cmd_users))

    # Register Helius webhook
    await register_helius_webhook(RAILWAY_PUBLIC_URL.rstrip("/"))

    # Start aiohttp webhook server
    web_app = web.Application()
    web_app.router.add_post("/webhook", handle_webhook)
    web_app.router.add_get("/health", handle_health)
    runner = web.AppRunner(web_app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", WEBHOOK_PORT)
    await site.start()
    log.info(f"Webhook server listening on port {WEBHOOK_PORT}")

    async with _app:
        await _app.start()
        await _app.updater.start_polling(drop_pending_updates=True)

        try:
            await _app.bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=(
                    "✅ *Scanner online \\(webhook mode\\)*\n"
                    "Receiving real\\-time transactions from Helius\\.\n\n"
                    "*Commands*\n"
                    "/info — thresholds and config\n"
                    "/status — uptime and stats\n"
                    "/stats — detection totals\n"
                    "/recent — last 10 alerts\n\n"
                    "/threshold N — set supply % trigger\n"
                    "/minwallets N — set min wallets\n"
                    "/window N — set time window \\(minutes\\)\n"
                    "/dormantage N — set dormant age \\(days\\)\n\n"
                    "/wallet \\<address\\> — profile a wallet\n"
                    "/token \\<mint\\> — scan suspicious holders\n"
                    "/cluster \\<mint\\> — show detected clusters\n"
                    "/users — bot visitor log \\(owner only\\)"
                ),
                parse_mode=ParseMode.MARKDOWN_V2,
            )
        except Exception as e:
            log.error(f"Startup message failed: {e}")

        # Run forever — webhook server handles incoming txs
        try:
            await asyncio.Event().wait()
        finally:
            await _http_client.aclose()
            await runner.cleanup()
            await _app.updater.stop()
            await _app.stop()


if __name__ == "__main__":
    asyncio.run(main())
