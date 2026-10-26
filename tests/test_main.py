import os
import unittest

from main import Database, normalize_model, parse_price


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.old_env = {k: os.environ.get(k) for k in (
            "MIN_DISCOUNT_PERCENT", "MIN_PROFIT_RUB", "MAX_RISK_SCORE", "DEFAULT_COMMISSION_PCT"
        )}
        os.environ["MIN_DISCOUNT_PERCENT"] = "25"
        os.environ["MIN_PROFIT_RUB"] = "1500"
        os.environ["MAX_RISK_SCORE"] = "40"
        os.environ["DEFAULT_COMMISSION_PCT"] = "0"
        self.db = Database(":memory:")

    def tearDown(self):
        self.db.close()
        for k, v in self.old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_parse_price(self):
        self.assertEqual(parse_price("Цена 25 900 ₽"), 25900)
        self.assertEqual(parse_price("Отдам даром"), 0)
        self.assertIsNone(parse_price("обычный товар"))

    def test_normalize_model(self):
        self.assertEqual(normalize_model("Продам iPhone 13 128 GB, срочно"), "iphone 13 128 gb")

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
