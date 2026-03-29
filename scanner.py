"""
Pump.fun Coordinated Wallet Scanner
Detects coordinated accumulation by suspicious wallets on older pump.fun tokens.
"""

import asyncio
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone

import httpx
from telegram import Bot
from telegram.constants import ParseMode

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

# In-memory state
alerted_clusters: dict[str, float] = {}  # cluster_key -> last_alert_timestamp
known_tokens: dict[str, float] = {}       # mint -> first_seen_timestamp


# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

async def rpc_post(client: httpx.AsyncClient, method: str, params: list) -> dict:
    resp = await client.post(
        HELIUS_RPC,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data.get("result", {})


async def get_program_accounts(client: httpx.AsyncClient) -> list[str]:
    """Fetch all token mints created by pump.fun program via Helius enhanced API."""
    url = f"https://api.helius.xyz/v0/addresses/{PUMP_FUN_PROGRAM}/transactions?api-key={HELIUS_API_KEY}&limit=100&type=CREATE"
    resp = await client.get(url, timeout=30)
    resp.raise_for_status()
    txs = resp.json()
    mints = []
    now = time.time()
    for tx in txs:
        ts = tx.get("timestamp", 0)
        age = now - ts
        if age < TOKEN_MIN_AGE_SECONDS:
            continue
        for account in tx.get("accountData", []):
            mint = account.get("account")
            if mint and mint not in known_tokens:
                known_tokens[mint] = ts
                mints.append(mint)
            elif mint in known_tokens:
                mints.append(mint)
    return list(set(mints))


async def get_token_supply(client: httpx.AsyncClient, mint: str) -> int:
    """Get total token supply."""
    result = await rpc_post(client, "getTokenSupply", [mint])
    return int(result.get("value", {}).get("amount", 0))


async def get_recent_token_txs(client: httpx.AsyncClient, mint: str) -> list[dict]:
    """Fetch recent transactions for a token mint via Helius."""
    url = (
        f"https://api.helius.xyz/v0/addresses/{mint}/transactions"
        f"?api-key={HELIUS_API_KEY}&limit=50&type=SWAP"
    )
    resp = await client.get(url, timeout=20)
    resp.raise_for_status()
    return resp.json()


async def get_wallet_info(client: httpx.AsyncClient, wallet: str) -> dict:
    """Get wallet age and transaction count."""
    # Get transaction history count
    sigs_result = await rpc_post(
        client,
        "getSignaturesForAddress",
        [wallet, {"limit": 1000}],
    )
    tx_count = len(sigs_result) if isinstance(sigs_result, list) else 0

    # Get account creation (first tx) approximate age via account info
    account_result = await rpc_post(client, "getAccountInfo", [wallet, {"encoding": "base58"}])
    # Estimate wallet age from earliest signature if available
    age_days = None
    if isinstance(sigs_result, list) and sigs_result:
        oldest = sigs_result[-1]
        block_time = oldest.get("blockTime")
        if block_time:
            age_days = (time.time() - block_time) / 86400

    return {
        "address": wallet,
        "tx_count": tx_count,
        "age_days": age_days,
    }


def is_suspicious_wallet(wallet_info: dict) -> bool:
    """Return True if wallet looks dormant/fresh/low-activity."""
    tx_count = wallet_info.get("tx_count", 9999)
    age_days = wallet_info.get("age_days")

    # Brand new wallet (very few txs)
    if tx_count <= MAX_WALLET_TX_COUNT:
        return True

    # Dormant wallet (old but almost no activity)
    if age_days is not None and age_days > MAX_WALLET_AGE_DAYS and tx_count <= MAX_WALLET_TX_COUNT * 3:
        return True

    return False


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def extract_buys(txs: list[dict], mint: str) -> list[dict]:
    """Extract buy events (wallet bought the token) from parsed Helius transactions."""
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
    """
    Group buys into time windows and detect coordinated accumulation.
    Returns clusters that meet all thresholds.
    """
    if not buys or total_supply == 0:
        return []

    # Sort by time
    buys_sorted = sorted(buys, key=lambda x: x["timestamp"])
    now = time.time()
    clusters = []

    # Sliding window grouping
    for i, anchor in enumerate(buys_sorted):
        window = [
            b for b in buys_sorted[i:]
            if b["timestamp"] - anchor["timestamp"] <= TIME_WINDOW_SECONDS
        ]
        if len(window) < MIN_COORDINATED_WALLETS:
            continue

        # Deduplicate wallets in window
        seen = {}
        for b in window:
            w = b["wallet"]
            if w not in seen or b["amount"] > seen[w]["amount"]:
                seen[w] = b

        if len(seen) < MIN_COORDINATED_WALLETS:
            continue

        amounts = [v["amount"] for v in seen.values()]
        min_amt, max_amt = min(amounts), max(amounts)

        # Similar buy sizes check
        if min_amt == 0 or (max_amt / min_amt) > BUY_SIZE_RATIO_MAX:
            continue

        # Total supply check
        total_bought = sum(amounts)
        pct = (total_bought / total_supply) * 100
        if pct < SUPPLY_THRESHOLD_PCT:
            continue

        clusters.append({
            "wallets": list(seen.values()),
            "total_bought": total_bought,
            "supply_pct": pct,
            "window_start": anchor["timestamp"],
            "window_end": anchor["timestamp"] + TIME_WINDOW_SECONDS,
        })

    return clusters


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def cluster_key(mint: str, cluster: dict) -> str:
    wallets = sorted(w["wallet"] for w in cluster["wallets"])
    return f"{mint}:{':'.join(wallets)}"


async def send_telegram_alert(bot: Bot, mint: str, cluster: dict, wallet_infos: dict):
    now = time.time()
    key = cluster_key(mint, cluster)

    # Cooldown check
    if key in alerted_clusters and (now - alerted_clusters[key]) < ALERT_COOLDOWN_SECONDS:
        return
    alerted_clusters[key] = now

    pct = cluster["supply_pct"]
    n = len(cluster["wallets"])
    window_start = datetime.fromtimestamp(cluster["window_start"], tz=timezone.utc).strftime("%H:%M:%S UTC")

    lines = [
        "🚨 *Coordinated Accumulation Detected*",
        "",
        f"🪙 Token: `{mint}`",
        f"🔗 [View on Pump.fun](https://pump.fun/{mint})",
        f"",
        f"📊 *{n} wallets* bought *{pct:.2f}% of supply* within {TIME_WINDOW_SECONDS // 60} min window",
        f"⏰ Window started: {window_start}",
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

        label = "🆕 Fresh" if (info.get("tx_count", 9999) <= 5) else "💤 Dormant"
        lines.append(
            f"{label} [`{w[:6]}…{w[-4:]}`](https://solscan.io/account/{w}) "
            f"— {tx_count} txs, {age_str}, {individual_pct:.2f}% supply"
        )

    lines += [
        "",
        f"[Full token on Solscan](https://solscan.io/token/{mint})",
    ]

    msg = "\n".join(lines)
    try:
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=msg,
            parse_mode=ParseMode.MARKDOWN,
            disable_web_page_preview=True,
        )
        log.info(f"Alert sent for mint {mint}, cluster of {n} wallets ({pct:.2f}%)")
    except Exception as e:
        log.error(f"Telegram send failed: {e}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

async def scan_once(client: httpx.AsyncClient, bot: Bot):
    log.info("Starting scan cycle...")

    try:
        mints = await get_program_accounts(client)
    except Exception as e:
        log.error(f"Failed to fetch token list: {e}")
        return

    log.info(f"Scanning {len(mints)} tokens older than {TOKEN_MIN_AGE_SECONDS // 3600}h")

    for mint in mints:
        try:
            supply = await get_token_supply(client, mint)
            if supply == 0:
                continue

            txs = await get_recent_token_txs(client, mint)
            buys = extract_buys(txs, mint)
            clusters = find_coordinated_clusters(buys, supply)

            if not clusters:
                continue

            log.info(f"Found {len(clusters)} cluster(s) for {mint}, checking wallets...")

            for cluster in clusters:
                # Fetch wallet info for all wallets in cluster
                wallet_infos = {}
                for entry in cluster["wallets"]:
                    w = entry["wallet"]
                    try:
                        info = await get_wallet_info(client, w)
                        wallet_infos[w] = info
                    except Exception as e:
                        log.warning(f"Could not fetch wallet info for {w}: {e}")
                        wallet_infos[w] = {}

                # All wallets in cluster must be suspicious
                all_suspicious = all(
                    is_suspicious_wallet(wallet_infos.get(e["wallet"], {}))
                    for e in cluster["wallets"]
                )
                if not all_suspicious:
                    continue

                await send_telegram_alert(bot, mint, cluster, wallet_infos)

            # Small delay per token to respect rate limits
            await asyncio.sleep(0.5)

        except Exception as e:
            log.error(f"Error scanning mint {mint}: {e}")
            continue


async def main():
    log.info("🚀 Pump.fun Coordinated Wallet Scanner starting...")
    bot = Bot(token=TELEGRAM_BOT_TOKEN)

    # Send startup message
    try:
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text="✅ *Scanner online.* Watching for coordinated accumulation on pump.fun tokens older than 24h.",
            parse_mode=ParseMode.MARKDOWN,
        )
    except Exception as e:
        log.error(f"Could not send startup message: {e}. Check TELEGRAM_CHAT_ID and BOT_TOKEN.")

    async with httpx.AsyncClient() as client:
        while True:
            try:
                await scan_once(client, bot)
            except Exception as e:
                log.error(f"Unhandled error in scan cycle: {e}")
            log.info(f"Sleeping {POLL_INTERVAL_SECONDS}s until next cycle...")
            await asyncio.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
