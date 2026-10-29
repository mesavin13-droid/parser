import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

from main import Database, fetch_avito, format_deal, ingest_sources, normalize_model, parse_datetime, parse_price, safe_source_label


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.old_env = {k: os.environ.get(k) for k in (
            "MIN_DISCOUNT_PERCENT", "MIN_PROFIT_RUB", "MAX_RISK_SCORE", "DEFAULT_COMMISSION_PCT",
            "MAX_LISTING_AGE_HOURS", "MAX_MARKET_DATA_AGE_DAYS"
        )}
        os.environ["MIN_DISCOUNT_PERCENT"] = "25"
        os.environ["MIN_PROFIT_RUB"] = "1500"
        os.environ["MAX_RISK_SCORE"] = "40"
        os.environ["DEFAULT_COMMISSION_PCT"] = "0"
        os.environ["MAX_LISTING_AGE_HOURS"] = "72"
        os.environ["MAX_MARKET_DATA_AGE_DAYS"] = "30"
        self.db = Database(":memory:")

    def tearDown(self):
        self.db.close()
        for k, v in self.old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_source_status_preserves_last_success_after_failure(self):
        url = "https://example.org/feed.xml?token=must-not-be-shown"
        self.db.record_source_check(url, "RSS/Atom", item_count=7)
        first = self.db.source_status()[0]
        self.assertEqual(first["last_items"], 7)
        self.assertTrue(first["last_success_at"])
        self.assertEqual(first["last_error"], "")

        self.db.record_source_check(url, "RSS/Atom", error="HTTP 403")
        second = self.db.source_status()[0]
        self.assertEqual(second["last_items"], 7)
        self.assertEqual(second["last_success_at"], first["last_success_at"])
        self.assertEqual(second["last_error"], "HTTP 403")
        self.assertNotIn("must-not-be-shown", safe_source_label(url))
        self.assertEqual(safe_source_label(url), "example.org/feed.xml")

    def test_scan_records_source_success_and_failure(self):
        feed_url = "https://example.org/feed.xml"
        avito_url = "https://www.avito.ru/novosibirsk/telefony"
        feed_items = [{
            "url": "https://example.org/item/1",
            "title": "iPhone 13 128 GB",
            "price": 20000,
            "image_url": "https://example.org/image.jpg",
            "source": "rss",
        }]
        with patch.dict(os.environ, {
            "RSS_FEEDS": feed_url,
            "AVITO_SEARCH_URLS": avito_url,
        }):
            with patch("main.fetch_rss", return_value=feed_items), \
                 patch("main.fetch_avito", side_effect=RuntimeError("HTTP 403")), \
                 patch("main.send_telegram", return_value=False):
                added = ingest_sources(self.db, quiet=True)

        self.assertEqual(added, 1)
        checks = {item["url"]: item for item in self.db.source_status()}
        self.assertEqual(checks[feed_url]["last_items"], 1)
        self.assertTrue(checks[feed_url]["last_success_at"])
        self.assertEqual(checks[feed_url]["last_error"], "")
        self.assertIn("HTTP 403", checks[avito_url]["last_error"])

    def test_file_database_uses_wal_for_multiple_workers(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Database(Path(folder) / "deals.sqlite3")
            try:
                mode = db.conn.execute("PRAGMA journal_mode").fetchone()[0].lower()
                self.assertEqual(mode, "wal")
            finally:
                db.close()

    def test_parse_price(self):
        self.assertEqual(parse_price("Цена 25 900 ₽"), 25900)
        self.assertEqual(parse_price("Отдам даром"), 0)
        self.assertIsNone(parse_price("обычный товар"))

    def test_normalize_model(self):
        self.assertEqual(normalize_model("Продам iPhone 13 128 GB, срочно"), "iphone 13 128 gb")

    def test_normalize_model_compact_names_and_free_listing_phrases(self):
        expected = "iphone 13 128 gb"
        self.assertEqual(normalize_model("Продам iPhone13 128GB, срочно"), expected)
        self.assertEqual(normalize_model("Отдам даром iPhone 13 128 GB"), expected)
        self.assertEqual(normalize_model("iPhone 13 128 GB бесплатно"), expected)
        self.assertEqual(normalize_model("NVIDIA GeForce RTX3060Ti"), "rtx 3060 ti")
        self.assertEqual(normalize_model("PlayStation5 Slim"), "ps5 slim")
        self.assertEqual(normalize_model("Sony PS 5 Slim"), "ps5 slim")

    def test_market_median_and_candidate(self):
        for price in (10000, 11000, 12000):
            self.db.add_market({"title": "iPhone 13 128 GB", "price": price, "city": "Новосибирск"})
        new, row = self.db.upsert_listing({
            "url": "https://example.org/item/1",
            "title": "iPhone 13 128 GB",
            "price": 5000,
            "city": "Новосибирск",
            "image_url": "https://example.org/image.jpg",
        })
        self.assertTrue(new)
        self.assertEqual(row["market_price"], 11000)
        self.assertEqual(row["status"], "candidate")
        self.assertEqual(row["expected_profit"], 6000)

    def test_market_price_is_learned_from_collected_listings(self):
        offers = [
            ("https://example.org/market/1", 10000),
            ("https://example.org/market/2", 11000),
            ("https://example.org/market/3", 12000),
            ("https://example.org/deal/cheap", 5000),
        ]
        for url, price in offers:
            _, row = self.db.upsert_listing({
                "url": url,
                "title": "Sony PlayStation 5 Slim",
                "price": price,
                "city": "Новосибирск",
                "image_url": "https://example.org/image.jpg",
            })
        # The bot derives the reference price from other collected offers; no manual market import.
        self.assertEqual(row["market_price"], 11000)
        self.assertEqual(row["market_samples"], 3)
        self.assertEqual(row["status"], "candidate")
        self.assertEqual(row["expected_profit"], 6000)

    def test_late_market_comps_refresh_existing_offer(self):
        _, row = self.db.upsert_listing({
            "url": "https://example.org/item/late-comps",
            "title": "iPhone 13 128 GB",
            "price": 5000,
            "image_url": "https://example.org/image.jpg",
        })
        self.assertEqual(row["status"], "needs_market")
        for price in (10000, 11000, 12000):
            self.db.add_market({"title": "iPhone 13 128 GB", "price": price})
        refreshed = self.db.conn.execute(
            "SELECT * FROM listings WHERE url=?",
            ("https://example.org/item/late-comps",),
        ).fetchone()
        self.assertEqual(refreshed["market_price"], 11000)
        self.assertEqual(refreshed["status"], "candidate")

    def test_avito_rss_url_uses_rss_parser(self):
        url = "https://www.avito.ru/novosibirsk/telefony?format=rss"
        expected = [{"title": "iPhone", "price": 1000, "url": url}]
        with patch("main.fetch_rss", return_value=expected) as parser:
            self.assertEqual(fetch_avito(url, "Новосибирск"), expected)
            parser.assert_called_once_with(url, "Новосибирск")

    def test_avito_rejects_lookalike_domain(self):
        with self.assertRaises(ValueError):
            fetch_avito("https://notavito.ru/novosibirsk/telefony", "Новосибирск")

    def test_parse_datetime_supports_iso_rss_and_unix(self):
        self.assertEqual(
            parse_datetime("2026-10-29T12:00:00Z"),
            datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(
            parse_datetime("Thu, 29 Oct 2026 12:00:00 GMT"),
            datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(
            parse_datetime("1793275200"),
            datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc),
        )

    def test_free_high_value_offer_gets_verification_warning(self):
        for price in (10000, 11000, 12000):
            self.db.add_market({"title": "iPhone 13 128 GB", "price": price})
        _, row = self.db.upsert_listing({
            "url": "https://example.org/item/free-phone",
            "title": "iPhone 13 128 GB отдам даром",
            "model_key": "iphone 13 128 gb",
            "price": 0,
            "image_url": "https://example.org/image.jpg",
        })
        self.assertEqual(row["status"], "candidate")
        self.assertEqual(row["risk_score"], 20)
        self.assertIn("бесплатное", row["risk_notes"])
        self.assertIn("Цена: БЕСПЛАТНО", format_deal(row))

    def test_stale_listing_is_excluded_from_alerts_and_deals(self):
        for price in (10000, 11000, 12000):
            self.db.add_market({"title": "iPhone 13 128 GB", "price": price})
        old_date = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        _, row = self.db.upsert_listing({
            "url": "https://example.org/item/stale",
            "title": "iPhone 13 128 GB",
            "price": 5000,
            "published_at": old_date,
            "image_url": "https://example.org/image.jpg",
        })
        self.assertEqual(row["status"], "stale")
        self.assertEqual(self.db.pending_alerts(), [])
        self.assertEqual(self.db.deals(), [])
        self.assertEqual(self.db.stats()["stale"], 1)

    def test_old_market_snapshots_are_not_used(self):
        for price in (10000, 11000, 12000):
            self.db.add_market({"title": "iPhone 13 128 GB", "price": price})
        old_date = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        self.db.conn.execute(
            "UPDATE market_comps SET observed_at=? WHERE price=12000",
            (old_date,),
        )
        self.db.conn.commit()
        market_price, samples = self.db.market_stats("iphone 13 128 gb")
        self.assertIsNone(market_price)
        self.assertEqual(samples, 2)

    def test_insufficient_market_comps_not_alerted(self):
        _, row = self.db.upsert_listing({
            "url": "https://example.org/item/2",
            "title": "RTX 3060",
            "price": 5000,
        })
        self.assertEqual(row["status"], "needs_market")
        self.assertEqual(len(self.db.pending_alerts()), 0)

    def test_defect_flagged_risky(self):
        for price in (10000, 11000, 12000):
            self.db.add_market({"title": "RTX 3060", "price": price})
        _, row = self.db.upsert_listing({
            "url": "https://example.org/item/3",
            "title": "RTX 3060 не работает",
            "price": 5000,
        })
        self.assertEqual(row["status"], "risky")


if __name__ == "__main__":
    unittest.main()
