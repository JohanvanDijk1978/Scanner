"""
Pump.fun Coordinated Wallet Scanner
Detects coordinated accumulation by suspicious wallets on older pump.fun tokens.

Commands (all users):
  /info         — current thresholds + live stats
  /status       — uptime, tokens scanned, last scan time
  /threshold N  — set supply % trigger (e.g. /threshold 3)
  /minwallets N — set min coordinated wallets (e.g. /minwallets 3)
  /window N     — set time window in minutes (e.g. /window 10)
  /dormantage N — set dormant wallet age threshold in days
  /wallet ADDR  — profile a specific wallet
  /token MINT   — show suspicious holders for a token
  /cluster MINT — show all detected clusters for a token
  /recent       — last 10 alerts fired
  /stats        — detection totals and hit rate

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

import httpx
from telegram import Bot, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

from config import (
    HELIUS_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    SUPPLY_THRESHOLD_PCT,
    TIME_WINDOW_SECONDS,
    MIN_COORDINATED_WALLETS,
    BUY_SIZE_RATIO_MAX,
    TOKEN_MIN_AGE_SECONDS,
    POLL_INTERVAL_SECONDS,
    ALERT_COOLDOWN_SECONDS,
    MAX_WALLET_TX_COUNT,
    MAX_WALLET_AGE_DAYS,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

HELIUS_RPC = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
PUMP_FUN_PROGRAM = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"

# ---------------------------------------------------------------------------
# Runtime state — all mutable settings live here so commands can change them
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

alerted_clusters: dict[str, float] = {}   # cluster_key -> last_alert_timestamp
known_tokens: dict[str, float] = {}        # mint -> first_seen_timestamp
token_clusters: dict[str, list] = {}       # mint -> list of detected clusters
recent_alerts: deque = deque(maxlen=10)    # last 10 alert dicts

# User tracking: {chat_id_str: {username, first_seen, last_seen, command_count, last_command}}
known_users: dict[str, dict] = {}

BOT_START_TIME: float = 0.0
LAST_SCAN_TIME: float = 0.0
TOTAL_TOKENS_SCANNED: int = 0
TOTAL_CLUSTERS_FOUND: int = 0
TOTAL_ALERTS_SENT: int = 0
SCAN_CYCLES: int = 0

# Shared httpx client (set in main)
_http_client: httpx.AsyncClient | None = None


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def load_state():
    """Load persisted settings from disk, falling back to config defaults."""
    global state
    try:
        if STATE_FILE.exists():
            saved = json.loads(STATE_FILE.read_text())
            for k in state:
                if k in saved:
                    state[k] = saved[k]
            log.info(f"Loaded persisted state from {STATE_FILE}")
        else:
            log.info("No persisted state found, using config defaults")
    except Exception as e:
        log.warning(f"Could not load state file: {e} — using defaults")


def save_state():
    """Write current mutable settings to disk."""
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2))
    except Exception as e:
        log.warning(f"Could not save state file: {e}")


def load_users():
    """Load persisted user records from disk."""
    global known_users
    try:
        if USERS_FILE.exists():
            known_users = json.loads(USERS_FILE.read_text())
            log.info(f"Loaded {len(known_users)} known users")
    except Exception as e:
        log.warning(f"Could not load users file: {e}")


def save_users():
    """Write user records to disk."""
    try:
        USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        USERS_FILE.write_text(json.dumps(known_users, indent=2))
    except Exception as e:
        log.warning(f"Could not save users file: {e}")


def is_owner(update: Update) -> bool:
    return str(update.effective_chat.id) == str(TELEGRAM_CHAT_ID)


async def track_user(update: Update, app: Application):
    """Record every user who interacts with the bot. Alert owner on first contact from strangers."""
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

    # Alert owner when a new non-owner user tries the bot
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
# RPC helpers
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


async def get_program_accounts() -> list[str]:
    url = (
        f"https://api.helius.xyz/v0/addresses/{PUMP_FUN_PROGRAM}/transactions"
        f"?api-key={HELIUS_API_KEY}&limit=100&type=CREATE"
    )
    resp = await _http_client.get(url, timeout=30)
    resp.raise_for_status()
    txs = resp.json()
    mints = []
    now = time.time()
    for tx in txs:
        ts = tx.get("timestamp", 0)
        if (now - ts) < TOKEN_MIN_AGE_SECONDS:
            continue
        for account in tx.get("accountData", []):
            mint = account.get("account")
            if mint and mint not in known_tokens:
                known_tokens[mint] = ts
                mints.append(mint)
            elif mint in known_tokens:
                mints.append(mint)
    return list(set(mints))


async def get_token_supply(mint: str) -> int:
    result = await rpc_post("getTokenSupply", [mint])
    return int(result.get("value", {}).get("amount", 0))


async def get_recent_token_txs(mint: str) -> list[dict]:
    url = (
        f"https://api.helius.xyz/v0/addresses/{mint}/transactions"
        f"?api-key={HELIUS_API_KEY}&limit=50&type=SWAP"
    )
    resp = await _http_client.get(url, timeout=20)
    resp.raise_for_status()
    return resp.json()


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
    return resp.json()


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


async def get_jupiter_prices(mints: list[str]) -> dict[str, float]:
    if not mints:
        return {}
    ids = ",".join(mints[:100])
    try:
        resp = await _http_client.get(
            f"https://price.jup.ag/v6/price?ids={ids}",
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {mint: data[mint]["price"] for mint in data if "price" in data[mint]}
    except Exception as e:
        log.warning(f"Jupiter price fetch failed: {e}")
        return {}


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


def parse_trade_pnl(txs: list[dict], wallet: str) -> dict:
    """Parse swap history to compute win rate, best PnL, open positions."""
    SOL_MINT = "So11111111111111111111111111111111111111112"
    token_flows: dict[str, dict] = {}

    for tx in txs:
        transfers = tx.get("tokenTransfers", [])
        native = tx.get("nativeTransfers", [])

        sol_spent = sum(
            t.get("amount", 0) / 1e9
            for t in native
            if t.get("fromUserAccount") == wallet
        )
        sol_received = sum(
            t.get("amount", 0) / 1e9
            for t in native
            if t.get("toUserAccount") == wallet
        )

        for t in transfers:
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
        has_sold = flow["sol_out"] > 0
        pnl_sol = flow["sol_out"] - flow["sol_in"]
        if has_sold:
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
    win_rate = (wins / total_closed * 100) if total_closed > 0 else None
    best_trade = max(trades, key=lambda t: t["pnl_sol"]) if trades else None
    worst_trade = min(trades, key=lambda t: t["pnl_sol"]) if trades else None

    return {
        "trades": trades,
        "win_rate": win_rate,
        "total_closed": total_closed,
        "wins": wins,
        "best_trade": best_trade,
        "worst_trade": worst_trade,
        "open_positions": open_positions,
    }


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def extract_buys(txs: list[dict], mint: str) -> list[dict]:
    buys = []
    for tx in txs:
        ts = tx.get("timestamp", 0)
        for transfer in tx.get("tokenTransfers", []):
            if transfer.get("mint") != mint:
                continue
            to_user = transfer.get("toUserAccount")
            amount = int(transfer.get("tokenAmount", 0))
            if to_user and amount > 0:
                buys.append({
                    "wallet": to_user,
                    "amount": amount,
                    "timestamp": ts,
                    "signature": tx.get("signature", ""),
                })
    return buys


def find_coordinated_clusters(buys: list[dict], total_supply: int) -> list[dict]:
    if not buys or total_supply == 0:
        return []

    tw = state["time_window_seconds"]
    min_wallets = state["min_coordinated_wallets"]
    ratio_max = state["buy_size_ratio_max"]
    threshold_pct = state["supply_threshold_pct"]

    buys_sorted = sorted(buys, key=lambda x: x["timestamp"])
    clusters = []

    for i, anchor in enumerate(buys_sorted):
        window = [b for b in buys_sorted[i:] if b["timestamp"] - anchor["timestamp"] <= tw]
        if len(window) < min_wallets:
            continue

        seen = {}
        for b in window:
            w = b["wallet"]
            if w not in seen or b["amount"] > seen[w]["amount"]:
                seen[w] = b

        if len(seen) < min_wallets:
            continue

        amounts = [v["amount"] for v in seen.values()]
        min_amt, max_amt = min(amounts), max(amounts)
        if min_amt == 0 or (max_amt / min_amt) > ratio_max:
            continue

        total_bought = sum(amounts)
        pct = (total_bought / total_supply) * 100
        if pct < threshold_pct:
            continue

        clusters.append({
            "wallets": list(seen.values()),
            "total_bought": total_bought,
            "supply_pct": pct,
            "window_start": anchor["timestamp"],
            "window_end": anchor["timestamp"] + tw,
        })

    return clusters


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
        log.info(f"Alert sent for mint {mint}, cluster of {n} wallets ({pct:.2f}%)")
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
        "ℹ️ *Scanner Info*\n"
        "\n"
        "*Detection Thresholds*\n"
        f"  Supply threshold: `{s['supply_threshold_pct']}%`\n"
        f"  Time window: `{s['time_window_seconds'] // 60} min`\n"
        f"  Min coordinated wallets: `{s['min_coordinated_wallets']}`\n"
        f"  Max buy size ratio: `{s['buy_size_ratio_max']}x`\n"
        "\n"
        "*Wallet Classification*\n"
        f"  Max txs (fresh): `{s['max_wallet_tx_count']}`\n"
        f"  Dormant age: `{s['max_wallet_age_days']} days`\n"
        "\n"
        "*Token Filters*\n"
        f"  Min token age: `{TOKEN_MIN_AGE_SECONDS // 3600}h`\n"
        "\n"
        "*Operational*\n"
        f"  Poll interval: `{POLL_INTERVAL_SECONDS}s`\n"
        f"  Alert cooldown: `{ALERT_COOLDOWN_SECONDS // 3600}h`\n"
        f"  Tokens seen: `{len(known_tokens)}`\n"
        f"  Clusters alerted: `{len(alerted_clusters)}`\n"
        f"  Uptime: `{fmt_uptime()}`\n"
        "\n"
        "*Commands*\n"
        "/status /threshold /minwallets /window /dormantage\n"
        "/wallet /token /cluster /recent /stats"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    last_scan = (
        datetime.fromtimestamp(LAST_SCAN_TIME, tz=timezone.utc).strftime("%H:%M:%S UTC")
        if LAST_SCAN_TIME else "not yet"
    )
    msg = (
        "📡 *Scanner Status*\n"
        "\n"
        f"  Uptime: `{fmt_uptime()}`\n"
        f"  Last scan: `{last_scan}`\n"
        f"  Scan cycles: `{SCAN_CYCLES}`\n"
        f"  Tokens tracked: `{len(known_tokens)}`\n"
        f"  Tokens scanned (total): `{TOTAL_TOKENS_SCANNED}`\n"
        f"  Clusters found: `{TOTAL_CLUSTERS_FOUND}`\n"
        f"  Alerts sent: `{TOTAL_ALERTS_SENT}`\n"
        f"  Next scan in: ~`{POLL_INTERVAL_SECONDS}s`\n"
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
    await update.message.reply_text(
        f"✅ Supply threshold: `{old}%` → `{val}%`", parse_mode=ParseMode.MARKDOWN
    )


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
    await update.message.reply_text(
        f"✅ Min wallets: `{old}` → `{val}`", parse_mode=ParseMode.MARKDOWN
    )


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
    await update.message.reply_text(
        f"✅ Time window: `{old} min` → `{val} min`", parse_mode=ParseMode.MARKDOWN
    )


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
    await update.message.reply_text(
        f"✅ Dormant age threshold: `{old} days` → `{val} days`", parse_mode=ParseMode.MARKDOWN
    )


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

    trading = parse_trade_pnl(swaps, addr)

    open_mints = list(trading["open_positions"].keys())
    live_mints = [b["mint"] for b in balances[:10]]
    all_mints = list(set(open_mints + live_mints))
    prices = await get_jupiter_prices(all_mints) if all_mints else {}

    tx_count = info.get("tx_count", 0)
    age_days = info.get("age_days")
    first_seen = info.get("first_seen")
    last_seen = info.get("last_seen")
    suspicious = is_suspicious_wallet(info)
    label = wallet_label(info)

    age_str = f"{age_days:.0f}d" if age_days is not None else "unknown"
    first_str = (
        datetime.fromtimestamp(first_seen, tz=timezone.utc).strftime("%Y-%m-%d")
        if first_seen else "unknown"
    )
    last_str = (
        datetime.fromtimestamp(last_seen, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if last_seen else "unknown"
    )

    lines = [
        f"👛 *Wallet Profile*",
        f"[`{addr[:6]}…{addr[-4:]}`](https://solscan.io/account/{addr})",
        f"",
        f"*Identity*",
        f"  Classification: {label} {'⚠️' if suspicious else '✅'}",
        f"  Age: `{age_str}` | Txs: `{tx_count}`",
        f"  First tx: `{first_str}`",
        f"  Last tx: `{last_str}`",
    ]

    win_rate = trading["win_rate"]
    total_closed = trading["total_closed"]
    wins = trading["wins"]
    best = trading["best_trade"]
    worst = trading["worst_trade"]

    lines += ["", "*Trading Stats* (last 100 swaps)"]

    if total_closed == 0:
        lines.append("  No closed trades found in recent history")
    else:
        wr_str = f"{win_rate:.1f}%" if win_rate is not None else "n/a"
        lines.append(f"  Win rate: `{wr_str}` ({wins}W / {total_closed - wins}L of {total_closed} trades)")
        if best:
            sign = "+" if best["pnl_sol"] >= 0 else ""
            lines.append(
                f"  Best trade: `{sign}{best['pnl_sol']:.3f} SOL` "
                f"([`{best['mint'][:6]}…`](https://solscan.io/token/{best['mint']}))"
            )
        if worst and worst["mint"] != (best["mint"] if best else None):
            lines.append(
                f"  Worst trade: `{worst['pnl_sol']:.3f} SOL` "
                f"([`{worst['mint'][:6]}…`](https://solscan.io/token/{worst['mint']}))"
            )
        total_pnl = sum(t["pnl_sol"] for t in trading["trades"])
        sign = "+" if total_pnl >= 0 else ""
        lines.append(f"  Total realised PnL: `{sign}{total_pnl:.3f} SOL`")

    open_pos = trading["open_positions"]
    if open_pos:
        lines += ["", "*Open Positions* (from swap history)"]
        for mint, pos in list(open_pos.items())[:5]:
            price_usd = prices.get(mint)
            sol_in = pos["sol_invested"]
            sol_out = pos["sol_recovered"]
            token_bal = pos["token_balance"]
            unrealised_str = f" ≈ ${token_bal * price_usd / 1e6:.2f}" if price_usd else ""
            lines.append(
                f"  [`{mint[:6]}…`](https://solscan.io/token/{mint}) "
                f"— {sol_in:.3f} SOL in, {sol_out:.3f} SOL out{unrealised_str}"
            )

    if balances:
        lines += ["", "*Current Token Holdings*"]
        for i, b in enumerate(balances[:5]):
            mint = b["mint"]
            amount = b["amount"]
            price_usd = prices.get(mint)
            val_str = f" ≈ ${amount * price_usd:.2f}" if price_usd else ""
            lines.append(
                f"  [`{mint[:6]}…`](https://solscan.io/token/{mint}) "
                f"— {amount:,.0f} tokens{val_str}"
            )
        if len(balances) > 5:
            lines.append(f"  _…and {len(balances) - 5} more_")

    lines.append(f"\n[View on Solscan](https://solscan.io/account/{addr})")

    await update.message.reply_text(
        "\n".join(lines),
        parse_mode=ParseMode.MARKDOWN,
        disable_web_page_preview=True,
    )


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
        buys = extract_buys(txs, mint)
    except Exception as e:
        await update.message.reply_text(f"❌ Error fetching token data: {e}")
        return

    if not buys:
        await update.message.reply_text("No recent buy activity found for this token.")
        return

    unique_wallets = list({b["wallet"] for b in buys})
    suspicious_found = []

    for w in unique_wallets[:20]:
        try:
            info = await get_wallet_info(w)
            if is_suspicious_wallet(info):
                total_bought = sum(b["amount"] for b in buys if b["wallet"] == w)
                pct = (total_bought / supply * 100) if supply else 0
                suspicious_found.append({"info": info, "wallet": w, "pct": pct})
        except Exception:
            continue

    if not suspicious_found:
        await update.message.reply_text(
            f"✅ No suspicious wallets found in recent buyers for `{mint[:8]}…`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    lines = [
        f"🪙 *Suspicious holders of* `{mint[:8]}…`\n",
        f"[Pump.fun](https://pump.fun/{mint}) | [Solscan](https://solscan.io/token/{mint})\n",
        f"Found `{len(suspicious_found)}` suspicious wallet(s) among recent buyers:\n",
    ]
    for entry in suspicious_found:
        w = entry["wallet"]
        info = entry["info"]
        pct = entry["pct"]
        label = wallet_label(info)
        age = info.get("age_days")
        age_str = f"{age:.0f}d" if age is not None else "?"
        lines.append(
            f"{label} [`{w[:6]}…{w[-4:]}`](https://solscan.io/account/{w}) "
            f"— {info['tx_count']} txs, {age_str} old, holds ~{pct:.2f}%"
        )

    await update.message.reply_text(
        "\n".join(lines), parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True
    )


async def cmd_cluster(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    if not context.args:
        await update.message.reply_text("Usage: `/cluster <mint_address>`", parse_mode=ParseMode.MARKDOWN)
        return

    mint = context.args[0].strip()
    clusters = token_clusters.get(mint)

    if not clusters:
        await update.message.reply_text(
            f"No clusters detected for `{mint[:8]}…` yet.\n"
            f"Either the token hasn't triggered a detection or it hasn't been scanned.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    lines = [f"🔬 *Clusters for* `{mint[:8]}…`\n"]
    for i, c in enumerate(clusters, 1):
        n = len(c["wallets"])
        pct = c["supply_pct"]
        ws = datetime.fromtimestamp(c["window_start"], tz=timezone.utc).strftime("%H:%M:%S UTC")
        lines.append(f"*Cluster {i}* — {n} wallets, {pct:.2f}% supply, at {ws}")
        for entry in c["wallets"]:
            w = entry["wallet"]
            lines.append(f"  • [`{w[:6]}…{w[-4:]}`](https://solscan.io/account/{w})")
        lines.append("")

    await update.message.reply_text(
        "\n".join(lines), parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True
    )


async def cmd_recent(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    if not recent_alerts:
        await update.message.reply_text("No alerts fired yet this session.")
        return

    lines = ["📋 *Recent Alerts*\n"]
    for i, a in enumerate(recent_alerts, 1):
        ts = datetime.fromtimestamp(a["timestamp"], tz=timezone.utc).strftime("%m/%d %H:%M UTC")
        mint = a["mint"]
        lines.append(
            f"`{i}.` [{mint[:8]}…](https://pump.fun/{mint}) — "
            f"{a['n_wallets']} wallets, {a['pct']:.2f}% supply — {ts}"
        )

    await update.message.reply_text(
        "\n".join(lines), parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True
    )


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await track_user(update, context.application)
    hit_rate = (
        f"{(TOTAL_CLUSTERS_FOUND / TOTAL_TOKENS_SCANNED * 100):.1f}%"
        if TOTAL_TOKENS_SCANNED > 0 else "n/a"
    )
    alert_rate = (
        f"{(TOTAL_ALERTS_SENT / TOTAL_CLUSTERS_FOUND * 100):.1f}%"
        if TOTAL_CLUSTERS_FOUND > 0 else "n/a"
    )
    msg = (
        "📊 *Detection Stats*\n"
        "\n"
        f"  Scan cycles run: `{SCAN_CYCLES}`\n"
        f"  Tokens scanned: `{TOTAL_TOKENS_SCANNED}`\n"
        f"  Clusters found: `{TOTAL_CLUSTERS_FOUND}`\n"
        f"  Alerts sent: `{TOTAL_ALERTS_SENT}`\n"
        f"\n"
        f"  Cluster hit rate: `{hit_rate}` of tokens scanned\n"
        f"  Alert conversion: `{alert_rate}` of clusters alerted\n"
        f"  (Alerts < clusters when cluster is on cooldown)\n"
        f"\n"
        f"  Uptime: `{fmt_uptime()}`\n"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


async def cmd_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/users — owner only: see who has interacted with the bot."""
    await track_user(update, context.application)

    if not is_owner(update):
        return  # silently ignore non-owners

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
            count = u.get("command_count", 1)
            last_cmd = u.get("last_command", "?")
            lines.append(
                f"\n  `{u['username']}` (ID: `{uid}`)\n"
                f"  {count} attempt(s) | first: {first} | last: {last}\n"
                f"  Last command: `{last_cmd}`"
            )

    await update.message.reply_text(
        "\n".join(lines), parse_mode=ParseMode.MARKDOWN
    )


# ---------------------------------------------------------------------------
# Scan loop
# ---------------------------------------------------------------------------

async def scan_loop(app: Application):
    global LAST_SCAN_TIME, TOTAL_TOKENS_SCANNED, TOTAL_CLUSTERS_FOUND, SCAN_CYCLES

    while True:
        try:
            log.info("Starting scan cycle...")
            mints = await get_program_accounts()
            SCAN_CYCLES += 1
            log.info(f"Scanning {len(mints)} tokens")

            for mint in mints:
                try:
                    supply = await get_token_supply(mint)
                    if supply == 0:
                        continue

                    txs = await get_recent_token_txs(mint)
                    buys = extract_buys(txs, mint)
                    clusters = find_coordinated_clusters(buys, supply)

                    TOTAL_TOKENS_SCANNED += 1

                    if not clusters:
                        continue

                    TOTAL_CLUSTERS_FOUND += len(clusters)
                    log.info(f"Found {len(clusters)} cluster(s) for {mint}")

                    token_clusters[mint] = clusters

                    for cluster in clusters:
                        wallet_infos = {}
                        for entry in cluster["wallets"]:
                            w = entry["wallet"]
                            try:
                                wallet_infos[w] = await get_wallet_info(w)
                            except Exception as e:
                                log.warning(f"Wallet info failed for {w}: {e}")
                                wallet_infos[w] = {}

                        all_suspicious = all(
                            is_suspicious_wallet(wallet_infos.get(e["wallet"], {}))
                            for e in cluster["wallets"]
                        )
                        if not all_suspicious:
                            continue

                        await send_telegram_alert(app.bot, mint, cluster, wallet_infos)

                    await asyncio.sleep(0.5)

                except Exception as e:
                    log.error(f"Error scanning {mint}: {e}")

            LAST_SCAN_TIME = time.time()

        except Exception as e:
            log.error(f"Scan cycle error: {e}")

        log.info(f"Sleeping {POLL_INTERVAL_SECONDS}s...")
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    global BOT_START_TIME, _http_client

    log.info("🚀 Pump.fun Coordinated Wallet Scanner starting...")

    if not HELIUS_API_KEY or HELIUS_API_KEY == "YOUR_HELIUS_API_KEY":
        raise RuntimeError("HELIUS_API_KEY env var is not set")
    if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN":
        raise RuntimeError("TELEGRAM_BOT_TOKEN env var is not set")
    if not TELEGRAM_CHAT_ID or TELEGRAM_CHAT_ID == "YOUR_CHAT_ID":
        raise RuntimeError("TELEGRAM_CHAT_ID env var is not set")

    log.info(f"Helius key: {HELIUS_API_KEY[:6]}…")
    log.info(f"Telegram token: {TELEGRAM_BOT_TOKEN[:10]}…")
    log.info(f"Chat ID: {TELEGRAM_CHAT_ID}")

    BOT_START_TIME = time.time()
    load_state()
    load_users()
    _http_client = httpx.AsyncClient()

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("info",        cmd_info))
    app.add_handler(CommandHandler("status",      cmd_status))
    app.add_handler(CommandHandler("threshold",   cmd_threshold))
    app.add_handler(CommandHandler("minwallets",  cmd_minwallets))
    app.add_handler(CommandHandler("window",      cmd_window))
    app.add_handler(CommandHandler("dormantage",  cmd_dormantage))
    app.add_handler(CommandHandler("wallet",      cmd_wallet))
    app.add_handler(CommandHandler("token",       cmd_token))
    app.add_handler(CommandHandler("cluster",     cmd_cluster))
    app.add_handler(CommandHandler("recent",      cmd_recent))
    app.add_handler(CommandHandler("stats",       cmd_stats))
    app.add_handler(CommandHandler("users",       cmd_users))

    async with app:
        await app.start()
        await app.updater.start_polling(drop_pending_updates=True)

        try:
            await app.bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=(
                    "✅ *Scanner online.*\n"
                    "Watching pump.fun tokens older than 24h for coordinated accumulation.\n"
                    "\n"
                    "*Commands*\n"
                    "/info — thresholds and config\n"
                    "/status — uptime and scan stats\n"
                    "/stats — detection totals and hit rate\n"
                    "/recent — last 10 alerts\n"
                    "\n"
                    "/threshold N — set supply % trigger\n"
                    "/minwallets N — set min wallets in cluster\n"
                    "/window N — set time window (minutes)\n"
                    "/dormantage N — set dormant wallet age (days)\n"
                    "\n"
                    "/wallet \\<address\\> — profile a wallet\n"
                    "/token \\<mint\\> — scan suspicious holders\n"
                    "/cluster \\<mint\\> — show detected clusters\n"
                    "/users — see who has used the bot \\(owner only\\)"
                ),
                parse_mode=ParseMode.MARKDOWN,
            )
        except Exception as e:
            log.error(f"Startup message failed: {e}")

        try:
            await scan_loop(app)
        finally:
            await _http_client.aclose()
            await app.updater.stop()
            await app.stop()


if __name__ == "__main__":
    asyncio.run(main())
