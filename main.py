#!/usr/bin/env python3
"""Tech Deal Hunter: поиск потенциально выгодных товаров и Telegram-уведомления.

Источники подключаются явно через RSS_FEEDS, AVITO_SEARCH_URLS и TELEGRAM_CHANNELS
либо импортом CSV/JSON. Читаются только публичные страницы; защита площадок
не обходится: при CAPTCHA/ограничении запросов источник
останавливается и требует ручной проверки.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import re
import sqlite3
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "data" / "deals.sqlite3"
USER_AGENT = "TechDealHunter/1.0 (+personal price research; no CAPTCHA bypass)"
FREE_RE = re.compile(r"\b(?:бесплатно|отдам\s+даром|даром|самовывоз\s+бесплатно)\b", re.I)
PRICE_RE = re.compile(
    r"(?<!\w)(\d[\d\s\u00a0]{0,12})\s*(?:₽|руб(?:\.|лей|ля|ль)?)(?!\w)", re.I
)
LABEL_PRICE_RE = re.compile(r"(?:цена|стоимость|price)\s*[:—-]?\s*(\d[\d\s\u00a0]{0,12})", re.I)
COMPACT_CURRENCY_PRICE_RE = re.compile(
    r"(?<!\w)(\d{1,3}(?:[.,]\d{1,2})?)\s*(тыс(?:\.|яч(?:а|и)?)?|к|k)\s*(?:₽|руб(?:\.|лей|ля|ль)?|р\.?)(?!\w)",
    re.I,
)
COMPACT_LABEL_PRICE_RE = re.compile(
    r"(?:цена|стоимость|price|за|отдам\s+за)\s*[:—-]?\s*"
    r"(\d{1,3}(?:[.,]\d{1,2})?)\s*(тыс(?:\.|яч(?:а|и)?)?|к|k)\b",
    re.I,
)
BAD_RE = re.compile(
    r"на\s+запчаст|не\s+работает|не\s+включа|разбит|треснут|утоплен|после\s+воды|"
    r"заблокир|icloud|айклауд|аклауд|донор|дефект|неисправ",
    re.I,
)
SCAM_RE = re.compile(
    r"предоплат|перевод\s+до\s+отправк|внесите\s+(?:залог|предоплат)|"
    r"оплатите\s+по\s+ссылке|ссылка\s+для\s+оплаты|сотрудник\s+авито|"
    r"код\s+из\s+смс|безопасн(?:ая|ую)\s+сделк[ау]\s+по\s+ссылке",
    re.I,
)
STOP_WORDS = {
    "продам", "куплю", "срочно", "новый", "новая", "новое", "новые", "б/у", "бу",
    "идеальное", "состояние", "отличное", "рабочий", "рабочая", "оригинал",
    "доставка", "самовывоз", "торг", "обмен", "цена", "руб", "рублей", "₽", "не", "работает", "работал", "работала",
    "запчасти", "запчасть", "разбит", "разбитый", "неисправен", "неисправна", "дефект", "донор",
    "заблокирован", "заблокирована", "icloud", "айклауд", "утоплен", "утоплена",
    "отдам", "даром", "бесплатно", "подарю", "подарок", "забирайте",
    "nvidia", "geforce",
}


def load_dotenv(path: Path = BASE_DIR / ".env") -> None:
    """Load a simple .env file without third-party dependencies."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def env_list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [x.strip() for x in re.split(r"[;\n]", raw) if x.strip()]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_datetime(value: Any) -> datetime | None:
    """Parse common ISO-8601, RFC 2822/RSS, and Unix timestamps as UTC."""
    raw = str(value or "").strip()
    if not raw:
        return None
    if re.fullmatch(r"\d{10,13}", raw):
        try:
            timestamp = float(raw)
            if timestamp >= 1_000_000_000_000:
                timestamp /= 1000
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(raw)
        except (TypeError, ValueError, OverflowError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def listing_is_fresh(row: dict[str, Any] | sqlite3.Row, now: datetime | None = None) -> bool:
    """Use publish time when available, otherwise the last time the source showed it."""
    published = parse_datetime(row["published_at"])
    observed = parse_datetime(row["last_seen_at"])
    created = parse_datetime(row["created_at"])
    timestamp = published or observed or created
    if timestamp is None:
        return False
    current = now or datetime.now(timezone.utc)
    max_hours = max(1, safe_int_env("MAX_LISTING_AGE_HOURS", 72))
    age_hours = (current - timestamp).total_seconds() / 3600
    # Allow minor clock skew, but do not treat arbitrarily future-dated ads as fresh.
    return -6 <= age_hours <= max_hours


def observation_is_fresh(value: Any, now: datetime | None = None) -> bool:
    observed = parse_datetime(value)
    if observed is None:
        return False
    current = now or datetime.now(timezone.utc)
    max_days = max(1, safe_int_env("MAX_MARKET_DATA_AGE_DAYS", 30))
    age_hours = (current - observed).total_seconds() / 3600
    return -6 <= age_hours <= max_days * 24


def as_int(value: Any, default: int | None = None) -> int | None:
    if value is None or str(value).strip() == "":
        return default
    if isinstance(value, (int, float)):
        return int(value)
    digits = re.sub(r"[^\d]", "", str(value))
    return int(digits) if digits else default


def parse_price(text: str) -> int | None:
    text = html.unescape(text or "").replace("\u202f", " ")
    if FREE_RE.search(text):
        return 0
    match = PRICE_RE.search(text)
    if match:
        return as_int(match.group(1))
    compact = COMPACT_CURRENCY_PRICE_RE.search(text) or COMPACT_LABEL_PRICE_RE.search(text)
    if compact:
        amount = float(compact.group(1).replace(",", "."))
        unit = compact.group(2).lower()
        multiplier = 1000 if unit.startswith("тыс") or unit in {"к", "k"} else 1
        return int(round(amount * multiplier))
    match = LABEL_PRICE_RE.search(text)
    return as_int(match.group(1)) if match else None


def normalize_model(title: str) -> str:
    """Normalize common spelling variants without discarding meaningful model variants."""
    cleaned = html.unescape(title or "").lower().replace("ё", "е")
    cleaned = re.sub(r"https?://\S+|\b\d[\d\s]*\s*(?:₽|руб(?:лей|ля|ль)?)", " ", cleaned)
    # Compact model names are common in classifieds: iPhone13, RTX3060Ti, PS 5.
    cleaned = re.sub(r"\biphone(?=\d)", "iphone ", cleaned)
    cleaned = re.sub(
        r"\b(rtx|gtx|rx|arc)\s*(\d{3,5})\s*(ti|super|xtx|xt)?\b",
        lambda m: f"{m.group(1)} {m.group(2)} {m.group(3) or ''}",
        cleaned,
    )
    cleaned = re.sub(r"\b(?:sony\s+)?(?:play\s*station|ps)\s*([345])\b", r"ps\1", cleaned)
    cleaned = re.sub(r"\b(\d{2,4})\s*(?:gb|гб)\b", r"\1 gb", cleaned)
    cleaned = re.sub(
        r"\b(\d+(?:[.,]\d+)?)\s*(?:tb|тб)\b",
        lambda m: m.group(1).replace(",", ".") + " tb",
        cleaned,
    )
    cleaned = re.sub(r"\s+", " ", cleaned)
    cleaned = re.sub(r"[^\w.+-]+", " ", cleaned, flags=re.UNICODE)
    parts = [p for p in cleaned.split() if p not in STOP_WORDS and len(p) > 1]
    return " ".join(parts[:10])


def safe_int_env(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


class Database:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or os.getenv("DEAL_DB_PATH", str(DEFAULT_DB)))
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # The watcher and Telegram command loop may access the same file-backed DB.
        # WAL plus a longer busy timeout reduces transient "database is locked" errors.
        self.conn = sqlite3.connect(str(self.path), timeout=30)
        self.conn.execute("PRAGMA busy_timeout=30000")
        if str(self.path) != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS listings (
          id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, source TEXT NOT NULL,
          title TEXT NOT NULL, model_key TEXT NOT NULL, category TEXT DEFAULT '',
          city TEXT DEFAULT '', price INTEGER NOT NULL, description TEXT DEFAULT '',
          image_url TEXT DEFAULT '', published_at TEXT DEFAULT '', market_price INTEGER,
          market_samples INTEGER NOT NULL DEFAULT 0, delivery_cost INTEGER NOT NULL DEFAULT 0,
          repair_cost INTEGER NOT NULL DEFAULT 0, commission_pct REAL NOT NULL DEFAULT 0,
          discount_pct REAL, expected_profit INTEGER, risk_score INTEGER NOT NULL DEFAULT 0,
          risk_notes TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'new',
          notified INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS market_comps (
          id INTEGER PRIMARY KEY AUTOINCREMENT, model_key TEXT NOT NULL,
          title TEXT NOT NULL, price INTEGER NOT NULL, city TEXT DEFAULT '',
          source TEXT DEFAULT '', observed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_market_model ON market_comps(model_key);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_market_dedupe ON market_comps(model_key,title,price,city,source);
        CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status, notified);
        CREATE TABLE IF NOT EXISTS source_status (
          url TEXT PRIMARY KEY, source_type TEXT NOT NULL,
          last_checked_at TEXT NOT NULL, last_success_at TEXT NOT NULL DEFAULT '',
          last_items INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT ''
        );
        """)
        # Upgrade databases created by earlier versions without deleting existing data.
        listing_columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(listings)")}
        if "last_seen_at" not in listing_columns:
            self.conn.execute("ALTER TABLE listings ADD COLUMN last_seen_at TEXT NOT NULL DEFAULT ''")
        self.conn.execute("UPDATE listings SET last_seen_at=created_at WHERE last_seen_at=''")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def record_source_check(
        self, url: str, source_type: str, item_count: int = 0, error: str = ""
    ) -> None:
        """Persist latest source result without erasing last successful data on errors."""
        checked = now_iso()
        if error:
            self.conn.execute(
                """INSERT INTO source_status(url, source_type, last_checked_at, last_error)
                   VALUES(?,?,?,?)
                   ON CONFLICT(url) DO UPDATE SET
                     source_type=excluded.source_type,
                     last_checked_at=excluded.last_checked_at,
                     last_error=excluded.last_error""",
                (url, source_type, checked, error[:500]),
            )
        else:
            self.conn.execute(
                """INSERT INTO source_status(
                     url, source_type, last_checked_at, last_success_at, last_items, last_error
                   ) VALUES(?,?,?,?,?, '')
                   ON CONFLICT(url) DO UPDATE SET
                     source_type=excluded.source_type,
                     last_checked_at=excluded.last_checked_at,
                     last_success_at=excluded.last_success_at,
                     last_items=excluded.last_items,
                     last_error=''""",
                (url, source_type, checked, checked, max(0, int(item_count))),
            )
        self.conn.commit()

    def source_status(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM source_status ORDER BY source_type, url"
        ).fetchall()
        return [dict(row) for row in rows]

    def add_market(self, row: dict[str, Any]) -> bool:
        title = str(row.get("title") or row.get("model") or "").strip()
        model_key = str(row.get("model_key") or normalize_model(title)).strip()
        price = as_int(row.get("price"))
        if not title or not model_key or price is None or price < 0:
            return False
        self.conn.execute(
            "INSERT OR IGNORE INTO market_comps(model_key,title,price,city,source,observed_at) VALUES(?,?,?,?,?,?)",
            (model_key, title, price, str(row.get("city") or ""), str(row.get("source") or "manual"), now_iso()),
        )
        self.conn.commit()
        # Recalculate saved offers if comparisons arrive after them.
        self.refresh_model(model_key)
        return True

    def market_stats(self, model_key: str, exclude_url: str = "") -> tuple[int | None, int]:
        """Estimate the market price from automatically collected listings plus optional imported comps.

        At least three comparable observations are required. The current offer is excluded,
        so a cheap listing cannot pull its own reference price down.
        """
        if not model_key:
            return None, 0
        comp_rows = self.conn.execute(
            "SELECT price, observed_at FROM market_comps WHERE model_key=? AND price>0 ORDER BY observed_at DESC LIMIT 200",
            (model_key,),
        ).fetchall()
        listing_rows = self.conn.execute(
            "SELECT url, price, published_at, last_seen_at, created_at FROM listings "
            "WHERE model_key=? AND price>0 AND url<>? ORDER BY created_at DESC LIMIT 200",
            (model_key, exclude_url),
        ).fetchall()
        # Old price snapshots and offers no longer seen at the source must not skew the market.
        values = [
            int(r["price"]) for r in comp_rows
            if observation_is_fresh(r["observed_at"])
        ] + [
            int(r["price"]) for r in listing_rows
            if listing_is_fresh(r)
        ]
        if len(values) < 3:
            return None, len(values)
        median = statistics.median(values)
        # Remove extreme outliers such as suspiciously cheap broken devices or obvious price errors.
        clean = [p for p in values if median * 0.5 <= p <= median * 1.8]
        if len(clean) < 3:
            return None, len(values)
        return int(round(statistics.median(clean))), len(clean)

    def refresh_model(self, model_key: str) -> None:
        """Re-evaluate saved offers after new comparable listings arrive."""
        if not model_key:
            return
        rows = self.conn.execute("SELECT * FROM listings WHERE model_key=?", (model_key,)).fetchall()
        min_discount = float(os.getenv("MIN_DISCOUNT_PERCENT", "25"))
        min_profit = safe_int_env("MIN_PROFIT_RUB", 1500)
        max_risk = safe_int_env("MAX_RISK_SCORE", 40)
        for item in rows:
            row = dict(item)
            market_price, samples = self.market_stats(model_key, exclude_url=row["url"])
            discount = max(0.0, (market_price - row["price"]) / market_price * 100) if market_price else None
            profit = int(round(market_price * (1 - row["commission_pct"] / 100) - row["price"] - row["delivery_cost"] - row["repair_cost"])) if market_price else None
            if not listing_is_fresh(row):
                status = "stale"
            elif market_price is None or samples < 3:
                status = "needs_market"
            elif row["risk_score"] >= 60:
                status = "risky"
            elif discount is not None and discount >= min_discount and profit is not None and profit >= min_profit and row["risk_score"] <= max_risk:
                status = "candidate"
            else:
                status = "not_enough_profit"
            self.conn.execute(
                "UPDATE listings SET market_price=?, market_samples=?, discount_pct=?, expected_profit=?, status=? WHERE url=?",
                (market_price, samples, discount, profit, status, row["url"]),
            )
        self.conn.commit()

    def upsert_listing(self, raw: dict[str, Any], city_default: str = "") -> tuple[bool, dict[str, Any]]:
        url = str(raw.get("url") or raw.get("link") or "").strip()
        title = html.unescape(str(raw.get("title") or raw.get("name") or "")).strip()
        price = as_int(raw.get("price"))
        if not url or not title or price is None or price < 0:
            return False, {"error": "Для объявления обязательны url, title и price"}
        model_key = str(raw.get("model_key") or normalize_model(title)).strip()
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        market_price, market_samples = self.market_stats(model_key, exclude_url=url)
        manual_market = as_int(raw.get("market_price"))
        manual_samples = as_int(raw.get("market_samples"), 0) or 0
        if manual_market is not None and manual_samples >= 3:
            market_price, market_samples = manual_market, manual_samples
        delivery = as_int(raw.get("delivery_cost"), 0) or 0
        repair = as_int(raw.get("repair_cost"), 0) or 0
        try:
            commission = float(raw.get("commission_pct") or os.getenv("DEFAULT_COMMISSION_PCT", "0"))
        except (TypeError, ValueError):
            commission = 0.0
        commission = max(0.0, min(commission, 90.0))
        discount = None
        profit = None
        if market_price and market_samples >= 3:
            discount = max(0.0, (market_price - price) / market_price * 100)
            profit = int(round(market_price * (1 - commission / 100) - price - delivery - repair))
        text = f"{title} {raw.get('description') or ''}"
        notes = []
        risk = 0
        if BAD_RE.search(text):
            risk += 60
            notes.append("в названии/описании есть признаки неисправности")
        if SCAM_RE.search(text):
            risk += 55
            notes.append("подозрительное требование оплаты или ссылка")
        if market_price is not None and price == 0:
            risk += 20
            notes.append("объявление бесплатное: проверьте условия передачи и продавца")
        elif market_price and price > 0 and price < market_price * 0.45:
            risk += 25
            notes.append("аномально низкая цена: возможен дефект или обман")
        if not raw.get("image_url") and not raw.get("image"):
            risk += 5
            notes.append("фото не найдено в данных источника")
        risk = min(risk, 100)
        min_discount = float(os.getenv("MIN_DISCOUNT_PERCENT", "25"))
        min_profit = safe_int_env("MIN_PROFIT_RUB", 1500)
        max_risk = safe_int_env("MAX_RISK_SCORE", 40)
        if market_price is None or market_samples < 3:
            status = "needs_market"
        elif risk >= 60:
            status = "risky"
        elif discount is not None and discount >= min_discount and profit is not None and profit >= min_profit and risk <= max_risk:
            status = "candidate"
        else:
            status = "not_enough_profit"
        values = (
            key, url, str(raw.get("source") or "import"), title, model_key,
            str(raw.get("category") or ""), str(raw.get("city") or city_default),
            price, str(raw.get("description") or ""), str(raw.get("image_url") or raw.get("image") or ""),
            str(raw.get("published_at") or raw.get("published") or ""), market_price,
            market_samples, delivery, repair, commission, discount, profit, risk,
            "; ".join(notes), status, now_iso(),
        )
        exists = self.conn.execute("SELECT 1 FROM listings WHERE url=?", (url,)).fetchone() is not None
        if exists:
            self.conn.execute("""UPDATE listings SET source=?,title=?,model_key=?,category=?,city=?,price=?,
              description=?,image_url=?,published_at=?,market_price=?,market_samples=?,delivery_cost=?,
              repair_cost=?,commission_pct=?,discount_pct=?,expected_profit=?,risk_score=?,risk_notes=?,
              status=? WHERE url=?""", values[2:21] + (url,))
        else:
            self.conn.execute("""INSERT INTO listings
              (id,url,source,title,model_key,category,city,price,description,image_url,published_at,
               market_price,market_samples,delivery_cost,repair_cost,commission_pct,discount_pct,
               expected_profit,risk_score,risk_notes,status,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", values)
        self.conn.commit()
        # Remember the latest time the source showed this URL; migration preserves prior records.
        self.conn.execute("UPDATE listings SET last_seen_at=? WHERE url=?", (now_iso(), url))
        self.conn.commit()
        # New observations automatically become comparable market data for other offers.
        self.refresh_model(model_key)
        row = dict(self.conn.execute("SELECT * FROM listings WHERE url=?", (url,)).fetchone())
        return not exists, row

    def mark_stale_listings(self) -> int:
        rows = self.conn.execute(
            "SELECT url, published_at, last_seen_at, created_at, status FROM listings WHERE status<>'stale'"
        ).fetchall()
        stale = [row["url"] for row in rows if not listing_is_fresh(row)]
        if stale:
            self.conn.executemany(
                "UPDATE listings SET status='stale' WHERE url=?",
                [(url,) for url in stale],
            )
            self.conn.commit()
        return len(stale)

    def deals(self, limit: int = 10, candidates_only: bool = True) -> list[dict[str, Any]]:
        self.mark_stale_listings()
        where = "WHERE status='candidate'" if candidates_only else ""
        rows = self.conn.execute(
            f"SELECT * FROM listings {where} ORDER BY COALESCE(expected_profit,-1) DESC, created_at DESC LIMIT ?",
            (max(1, min(limit, 100)),),
        ).fetchall()
        return [dict(r) for r in rows]

    def pending_alerts(self) -> list[dict[str, Any]]:
        self.mark_stale_listings()
        rows = self.conn.execute(
            "SELECT * FROM listings WHERE status='candidate' AND notified=0 ORDER BY created_at"
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_notified(self, url: str) -> None:
        self.conn.execute("UPDATE listings SET notified=1 WHERE url=?", (url,))
        self.conn.commit()

    def stats(self) -> dict[str, int]:
        self.mark_stale_listings()
        row = self.conn.execute("""SELECT COUNT(*) total,
          SUM(CASE WHEN status='candidate' THEN 1 ELSE 0 END) candidates,
          SUM(CASE WHEN status='needs_market' THEN 1 ELSE 0 END) needs_market,
          SUM(CASE WHEN status='risky' THEN 1 ELSE 0 END) risky,
          SUM(CASE WHEN status='stale' THEN 1 ELSE 0 END) stale FROM listings""").fetchone()
        return {k: int(row[k] or 0) for k in row.keys()}


class AvitoHTMLParser(HTMLParser):
    """Extract only visible public listing cards; no private endpoints or challenge handling."""
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.cards: list[dict[str, Any]] = []
        self.card: dict[str, Any] | None = None
        self.depth = 0
        self.capture: str | None = None
        self.capture_tag: str | None = None
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        a = dict(attrs)
        marker = a.get("data-marker", "")
        if self.card is None and marker == "item":
            self.card = {"source": "avito", "url": "", "title": "", "price": None, "description": "", "image_url": ""}
            self.depth = 1
            return
        if self.card is None:
            return
        if tag not in self.VOID:
            self.depth += 1
        if marker in ("item-title", "item-price", "item-description"):
            self.capture = {"item-title": "title", "item-price": "price_text", "item-description": "description"}[marker]
            self.capture_tag = tag
            self.parts = []
            if marker == "item-title" and a.get("href"):
                self.card["url"] = urllib.parse.urljoin(self.base_url, a["href"])
        if tag == "img" and not self.card.get("image_url"):
            self.card["image_url"] = a.get("src") or a.get("data-src") or ""

    def handle_data(self, data):
        if self.card is not None and self.capture:
            self.parts.append(data)

    def handle_endtag(self, tag: str):
        if self.card is None:
            return
        if self.capture and tag == self.capture_tag:
            value = " ".join(" ".join(self.parts).split())
            if self.capture == "price_text":
                self.card["price"] = parse_price(value)
            else:
                self.card[self.capture] = value
            self.capture = self.capture_tag = None
            self.parts = []
        if tag not in self.VOID:
            self.depth -= 1
        if self.depth <= 0:
            if self.card.get("title") and self.card.get("url") and self.card.get("price") is not None:
                self.cards.append(self.card)
            self.card = None
            self.depth = 0



class TelegramPublicChannelParser(HTMLParser):
    """Read public t.me/s channel previews only; no account or private-channel access."""
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.cards: list[dict[str, Any]] = []
        self.card: dict[str, Any] | None = None
        self.depth = 0
        self.capture_tag: str | None = None
        self.capture_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        a = dict(attrs)
        classes = set((a.get("class") or "").split())
        if self.card is None:
            post = (a.get("data-post") or "").strip("/")
            if tag == "div" and "tgme_widget_message" in classes and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}/\d+", post):
                self.card = {
                    "url": "https://t.me/" + post,
                    "published_at": "",
                    "description": "",
                }
                self.depth = 1
            return

        if tag not in self.VOID:
            self.depth += 1

        if tag == "time" and a.get("datetime") and not self.card["published_at"]:
            self.card["published_at"] = a["datetime"]

        if self.capture_tag:
            if tag not in self.VOID:
                self.capture_depth += 1
            if tag == "br":
                self.parts.append("\n")
        elif "tgme_widget_message_text" in classes:
            self.capture_tag = tag
            self.capture_depth = 1
            self.parts = []

    def handle_data(self, data):
        if self.card is not None and self.capture_tag:
            self.parts.append(data)

    def handle_endtag(self, tag: str):
        if self.card is None:
            return

        if self.capture_tag and tag not in self.VOID:
            self.capture_depth -= 1
            if self.capture_depth <= 0:
                body = "".join(self.parts).replace("\xa0", " ")
                self.card["description"] = "\n".join(
                    line.strip() for line in body.splitlines() if line.strip()
                )
                self.capture_tag = None
                self.capture_depth = 0
                self.parts = []

        if tag not in self.VOID:
            self.depth -= 1

        if self.depth <= 0:
            body = self.card.get("description", "")
            if body and self.card.get("url"):
                lines = [line.strip() for line in body.splitlines() if line.strip()]
                title = next(
                    (line for line in lines if not line.startswith(("http://", "https://"))
                     and re.search(r"[A-Za-zА-Яа-я0-9]", line)),
                    lines[0] if lines else "",
                )
                title = re.sub(
                    r"\s*(?:[|—–-]\s*)?(?:цена|стоимость|за|отдам\s+за)\s*[:—-]?\s*"
                    r"\d{1,3}(?:[.,]\d{1,2})?\s*(?:тыс(?:\.|яч(?:а|и)?)?|к|k)"
                    r"(?:\s*(?:₽|руб(?:\.|лей|ля|ль)?))?.*$",
                    "",
                    title,
                    flags=re.I,
                ).strip(" —–-:|")
                price = parse_price(body)
                if title and price is not None:
                    self.cards.append({
                        "url": self.card["url"],
                        "title": title[:180],
                        "price": price,
                        "description": body[:3000],
                        "published_at": self.card.get("published_at", ""),
                        "source": "telegram_channel",
                    })
            self.card = None
            self.depth = 0
            self.capture_tag = None
            self.capture_depth = 0
            self.parts = []


def fetch_url(url: str, timeout: int = 20) -> tuple[str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/rss+xml,application/atom+xml,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            body = response.read(3_000_000)
            charset = response.headers.get_content_charset() or "utf-8"
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429, 439):
            raise RuntimeError(f"Источник ограничил доступ (HTTP {exc.code}); автоматическая проверка остановлена. Проверьте разрешённый способ доступа.") from exc
        raise RuntimeError(f"HTTP {exc.code} при чтении {url}") from exc
    text = body.decode(charset, errors="replace")
    if any(token in text.lower() for token in ("captcha", "проверка безопасности", "докажите, что вы не робот", "geetest")):
        raise RuntimeError("Источник показал CAPTCHA/проверку безопасности; автоматический сбор остановлен.")
    return text, response.headers.get("Content-Type", "")


def safe_source_label(url: str) -> str:
    """Show a source location without query parameters that might contain credentials."""
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    return f"{parsed.hostname or 'unknown'}{path}"


def fetch_rss(url: str, city: str) -> list[dict[str, Any]]:
    xml, _ = fetch_url(url)
    root = ET.fromstring(xml)
    found = []
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1].lower()
        if tag not in ("item", "entry"):
            continue
        data: dict[str, str] = {}
        for child in list(node):
            key = child.tag.rsplit("}", 1)[-1].lower()
            if key == "link" and child.attrib.get("href"):
                data[key] = child.attrib["href"]
            else:
                data[key] = "".join(child.itertext()).strip()
        title = data.get("title", "")
        description = data.get("description") or data.get("summary") or data.get("content") or ""
        price = parse_price(f"{title} {description}")
        link = data.get("link", "")
        if price is None or not link or not title:
            continue
        found.append({
            "url": urllib.parse.urljoin(url, link), "title": title, "price": price,
            "description": re.sub("<[^>]+>", " ", html.unescape(description)),
            "category": data.get("category", ""), "published_at": data.get("pubdate") or data.get("published") or data.get("updated") or "",
            "city": city, "source": "rss",
        })
    return found


def fetch_avito(url: str, city: str) -> list[dict[str, Any]]:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or not (host == "avito.ru" or host.endswith(".avito.ru")):
        raise ValueError(f"Разрешены только ссылки на публичный поиск avito.ru: {url}")
    # Some Avito search URLs can expose an RSS response via format=rss.
    # Prefer the structured feed when explicitly requested; never bypass access controls.
    query = urllib.parse.parse_qs(parsed.query)
    if any(value.lower() == "rss" for value in query.get("format", [])):
        return fetch_rss(url, city)
    text, _ = fetch_url(url)
    parser = AvitoHTMLParser(url)
    parser.feed(text)
    out = []
    for row in parser.cards:
        row["city"] = city
        row["published_at"] = ""
        out.append(row)
    if not out:
        raise RuntimeError("Не удалось извлечь карточки из публичной HTML-страницы. Не включайте обход защиты: используйте разрешённый экспорт CSV/JSON.")
    return out



def telegram_channel_public_url(value: str) -> str:
    """Normalize a public Telegram channel name/link into its public preview URL."""
    raw = (value or "").strip()
    if raw.startswith("@"):
        username = raw[1:]
    elif "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        host = (parsed.hostname or "").lower()
        if host not in {"t.me", "www.t.me", "telegram.me", "www.telegram.me"}:
            raise ValueError("Разрешены только публичные ссылки t.me или telegram.me")
        parts = [part for part in parsed.path.split("/") if part]
        if parts and parts[0].lower() == "s":
            parts = parts[1:]
        if not parts:
            raise ValueError("В ссылке не указано имя Telegram-канала")
        username = parts[0]
    else:
        username = raw

    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", username):
        raise ValueError("Имя публичного Telegram-канала должно содержать 5–32 латинских символа, цифры или _")
    return f"https://t.me/s/{username}"


def fetch_telegram_channel(channel: str, city: str) -> list[dict[str, Any]]:
    """Fetch price-bearing posts from Telegram's public web preview."""
    preview_url = telegram_channel_public_url(channel)
    page, _ = fetch_url(preview_url)
    parser = TelegramPublicChannelParser()
    parser.feed(page)
    if not parser.cards:
        raise RuntimeError(
            "В публичном просмотре Telegram не найдены посты с распознаваемой ценой. "
            "Канал может быть недоступен для веб-просмотра или использовать другой формат публикаций."
        )
    for row in parser.cards:
        row["city"] = city
    return parser.cards


def load_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    if path.suffix.lower() == ".json":
        content = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(content, dict):
            content = content.get("items") or content.get("listings") or [content]
        if not isinstance(content, list):
            raise ValueError("JSON должен быть массивом объектов или содержать items/listings")
        return [x for x in content if isinstance(x, dict)]
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f))
    raise ValueError("Поддерживаются только .csv и .json")


def format_deal(row: dict[str, Any]) -> str:
    price = "БЕСПЛАТНО" if row["price"] == 0 else f'{row["price"]:,}'.replace(",", " ") + " ₽"
    market = f'{row["market_price"]:,}'.replace(",", " ") + " ₽" if row.get("market_price") else "недостаточно аналогов"
    profit = f'{row["expected_profit"]:,}'.replace(",", " ") + " ₽" if row.get("expected_profit") is not None else "не рассчитана"
    discount = f'{row["discount_pct"]:.0f}%' if row.get("discount_pct") is not None else "—"
    notes = row.get("risk_notes") or "явных рисковых фраз не найдено"
    return (
        f'🔎 {row["title"]}\n'
        f'Цена: {price} · Рыночная медиана: {market}\n'
        f'Скидка: {discount} · Оценка прибыли: {profit}\n'
        f'Риск: {row.get("risk_score", 0)}/100 — {notes}\n'
        f'Источник: {row.get("source", "—")} · {row.get("city", "")}\n'
        f'⚠️ Предварительная оценка. Наличие, состояние и право собственности у продавца не подтверждены.\n'
        f'{row["url"]}'
    )[:3900]


def telegram_call(method: str, payload: dict[str, Any]) -> dict[str, Any]:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("Укажите TELEGRAM_BOT_TOKEN в .env")
    url = f"https://api.telegram.org/bot{token}/{method}"
    encoded = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(url, data=encoded, headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=35) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Telegram API HTTP {exc.code}") from exc
    if not result.get("ok"):
        raise RuntimeError("Telegram API: " + str(result.get("description", "unknown error")))
    return result


def send_telegram(text: str) -> bool:
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not chat_id:
        print("Telegram: TELEGRAM_CHAT_ID не задан; уведомление показано только в консоли.", file=sys.stderr)
        return False
    telegram_call("sendMessage", {"chat_id": chat_id, "text": text, "disable_web_page_preview": "true"})
    return True


def ingest_sources(db: Database, quiet: bool = False) -> int:
    city = os.getenv("SEARCH_CITY", "Новосибирск")
    items: list[dict[str, Any]] = []
    failures = 0
    rss_urls = env_list("RSS_FEEDS")
    avito_urls = env_list("AVITO_SEARCH_URLS")
    telegram_channels = env_list("TELEGRAM_CHANNELS")
    for url in rss_urls:
        try:
            batch = fetch_rss(url, city)
            items.extend(batch)
            db.record_source_check(url, "RSS/Atom", len(batch))
            if not quiet:
                print(f"RSS: {len(batch)} объявлений — {safe_source_label(url)}")
        except Exception as e:
            failures += 1
            db.record_source_check(url, "RSS/Atom", error=str(e))
            print(f"RSS ERROR {safe_source_label(url)}: {e}", file=sys.stderr)
    for url in avito_urls:
        try:
            batch = fetch_avito(url, city)
            items.extend(batch)
            db.record_source_check(url, "Avito", len(batch))
            if not quiet:
                print(f"Avito: {len(batch)} объявлений — {safe_source_label(url)}")
        except Exception as e:
            failures += 1
            db.record_source_check(url, "Avito", error=str(e))
            print(f"AVITO ERROR {safe_source_label(url)}: {e}", file=sys.stderr)
    for channel in telegram_channels:
        try:
            preview_url = telegram_channel_public_url(channel)
            batch = fetch_telegram_channel(channel, city)
            items.extend(batch)
            db.record_source_check(preview_url, "Telegram", len(batch))
            if not quiet:
                print(f"Telegram: {len(batch)} публикаций с ценой — {safe_source_label(preview_url)}")
        except Exception as e:
            failures += 1
            try:
                status_url = telegram_channel_public_url(channel)
            except ValueError:
                status_url = str(channel)
            db.record_source_check(status_url, "Telegram", error=str(e))
            print(f"TELEGRAM SOURCE ERROR {safe_source_label(status_url)}: {e}", file=sys.stderr)

    if not rss_urls and not avito_urls and not telegram_channels and not quiet:
        print("Источники не настроены: добавьте RSS_FEEDS, AVITO_SEARCH_URLS или TELEGRAM_CHANNELS в .env.", file=sys.stderr)
    added = 0
    for item in items:
        item.setdefault("source", "feed")
        is_new, _row = db.upsert_listing(item, city)
        added += int(is_new)

    # New comparisons can promote previously stored listings to candidate status.
    # Drain the alert queue after the whole batch so those promotions are not missed.
    for row in db.pending_alerts():
        message = format_deal(row)
        try:
            if send_telegram(message):
                db.mark_notified(row["url"])
        except Exception as e:
            print(f"Telegram ERROR: {e}", file=sys.stderr)
        if not quiet:
            print("\n" + message + "\n")
    if not quiet:
        stats = db.stats()
        print(f"Сканирование завершено: новых {added}, всего {stats['total']}, находок {stats['candidates']}, нужен рынок {stats['needs_market']}, рискованных {stats['risky']}. Ошибок источников: {failures}.")
    return added


def import_listings(db: Database, path: Path) -> int:
    count = 0
    for row in load_rows(path):
        row.setdefault("source", "import")
        _, saved = db.upsert_listing(row, os.getenv("SEARCH_CITY", "Новосибирск"))
        count += 1
        print(f'{saved["status"]:18} {saved["title"][:75]}')
    return count


def import_market(db: Database, path: Path) -> int:
    count = 0
    for row in load_rows(path):
        if db.add_market(row):
            count += 1
    print(f"Загружено рыночных аналогов: {count}. Для оценки одной модели нужно минимум 3 цены с model_key.")
    return count


def run_telegram_poll(db: Database) -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("Укажите TELEGRAM_BOT_TOKEN в .env")
    offset = 0
    print("Telegram polling запущен. Остановка: Ctrl+C")
    while True:
        try:
            result = telegram_call("getUpdates", {"offset": offset, "timeout": 20, "allowed_updates": json.dumps(["message"])})
            for update in result.get("result", []):
                offset = max(offset, int(update["update_id"]) + 1)
                msg = update.get("message", {})
                chat_id = msg.get("chat", {}).get("id")
                text = (msg.get("text") or "").strip()
                if not chat_id or not text.startswith("/"):
                    continue
                command = text.split()[0].split("@")[0].lower()
                allowed = os.getenv("TELEGRAM_CHAT_ID", "").strip()
                if allowed and str(chat_id) != allowed:
                    telegram_call("sendMessage", {"chat_id": chat_id, "text": "Бот настроен для другого чата."})
                    continue
                if command in ("/start", "/help"):
                    answer = "Tech Deal Hunter готов.\n/id — показать ID чата\n/deals — лучшие находки\n/stats — статистика\n/sources — состояние подключённых источников\n/scan — проверить подключённые источники\n\nРыночную цену бот оценивает автоматически по собранным аналогам; нужно минимум 3 сопоставимых предложения. Источники: RSS/Atom, публичный поиск Avito и публичные Telegram-каналы из TELEGRAM_CHANNELS."
                elif command == "/id":
                    answer = f"ID этого чата: {chat_id}\nДобавьте его в TELEGRAM_CHAT_ID файла .env и перезапустите бота."
                elif command == "/stats":
                    answer = "Статистика:\n" + "\n".join(f"{k}: {v}" for k, v in db.stats().items())
                elif command == "/deals":
                    deals = db.deals(5)
                    answer = "\n\n".join(format_deal(d) for d in deals) if deals else "Пока нет находок, прошедших все фильтры."
                elif command == "/sources":
                    rss = env_list("RSS_FEEDS")
                    avito = env_list("AVITO_SEARCH_URLS")
                    telegram_channels = env_list("TELEGRAM_CHANNELS")
                    configured = [(url, "RSS/Atom") for url in rss] + [(url, "Avito") for url in avito]
                    invalid_channels = []
                    for channel in telegram_channels:
                        try:
                            configured.append((telegram_channel_public_url(channel), "Telegram"))
                        except ValueError:
                            invalid_channels.append(channel)
                    checks = {item["url"]: item for item in db.source_status()}
                    stats = db.stats()
                    lines = [
                        "Источники поиска",
                        f"Настроено: RSS/Atom — {len(rss)}, Avito — {len(avito)}, Telegram — {len(telegram_channels)}",
                        f"Объявлений в базе: {stats['total']}",
                    ]
                    if not configured and not invalid_channels:
                        lines.append("⛔ Источники не настроены. Заполните RSS_FEEDS, AVITO_SEARCH_URLS или TELEGRAM_CHANNELS в .env.")
                    for channel in invalid_channels[:5]:
                        lines.append(f"⛔ Неверная ссылка на публичный Telegram-канал: {channel}")
                    else:
                        lines.append("")
                        for url, source_type in configured[:12]:
                            item = checks.get(url)
                            label = safe_source_label(url)
                            if item is None:
                                state = "⏳ ещё не проверен"
                                last = "нет данных"
                                detail = "отправьте /scan"
                            elif item["last_error"]:
                                state = "⚠️ ошибка"
                                last = item["last_checked_at"] or "нет данных"
                                detail = item["last_error"]
                            elif item["last_success_at"]:
                                state = "✅ доступен"
                                last = item["last_checked_at"] or "нет данных"
                                detail = f"получено карточек: {item['last_items']}"
                            else:
                                state = "⏳ ещё не проверен"
                                last = item["last_checked_at"] or "нет данных"
                                detail = "результат пока отсутствует"
                            lines.append(f"{state} {source_type}: {label}")
                            lines.append(f"Проверка: {last} · {detail[:180]}")
                        if len(configured) > 12:
                            lines.append(f"Показаны первые 12 из {len(configured)} источников.")
                    answer = "\n".join(lines)
                elif command == "/scan":
                    answer = "Запускаю проверку источников…"
                    telegram_call("sendMessage", {"chat_id": chat_id, "text": answer})
                    added = ingest_sources(db, quiet=False)
                    stats = db.stats()
                    configured_urls = set(env_list("RSS_FEEDS") + env_list("AVITO_SEARCH_URLS"))
                    for channel in env_list("TELEGRAM_CHANNELS"):
                        try:
                            configured_urls.add(telegram_channel_public_url(channel))
                        except ValueError:
                            pass
                    checks = [item for item in db.source_status() if item["url"] in configured_urls]
                    failed = sum(1 for item in checks if item["last_error"])
                    answer = (
                        "Проверка завершена.\n"
                        f"Настроено источников: {len(configured_urls)}\n"
                        f"Проверено источников: {len(checks)}\n"
                        f"Источники с ошибками: {failed}\n"
                        f"Новых объявлений: {added}\n"
                        f"Выгодных находок в базе: {stats['candidates']}\n"
                        "Команды: /deals — находки, /sources — состояние источников."
                    )
                else:
                    answer = "Неизвестная команда. Используйте /help."
                telegram_call("sendMessage", {"chat_id": chat_id, "text": answer[:3900], "disable_web_page_preview": "true"})
        except KeyboardInterrupt:
            print("\nОстановлено.")
            return
        except Exception as e:
            print(f"Telegram polling error: {e}", file=sys.stderr)
            time.sleep(5)


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Поиск недооценённых товаров и уведомления Telegram")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scan", help="один проход по RSS и публичным страницам Avito")
    watch = sub.add_parser("watch", help="повторять сканирование")
    watch.add_argument("--interval", type=int, default=safe_int_env("POLL_INTERVAL_SECONDS", 300))
    imp = sub.add_parser("import-listings", help="импорт объявлений из CSV/JSON")
    imp.add_argument("file", type=Path)
    market = sub.add_parser("import-market", help="импорт сравнимых цен из CSV/JSON")
    market.add_argument("file", type=Path)
    deals = sub.add_parser("deals", help="показать подходящие сделки")
    deals.add_argument("--all", action="store_true", help="показать все записи, включая непрошедшие фильтры")
    deals.add_argument("--limit", type=int, default=20)
    sub.add_parser("telegram", help="запустить приём команд Telegram")
    args = parser.parse_args()
    db = Database()
    try:
        if args.command == "scan":
            ingest_sources(db)
        elif args.command == "watch":
            interval = max(60, args.interval)
            while True:
                ingest_sources(db)
                time.sleep(interval)
        elif args.command == "import-listings":
            print(f"Импортировано записей: {import_listings(db, args.file)}")
        elif args.command == "import-market":
            print(f"Импортировано аналогов: {import_market(db, args.file)}")
        elif args.command == "deals":
            rows = db.deals(args.limit, candidates_only=not args.all)
            for row in rows:
                print(format_deal(row) + "\n")
            if not rows:
                print("Нет записей для отображения.")
        elif args.command == "telegram":
            run_telegram_poll(db)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
