-- Global fuel prices (Estonia national average) — shown as an info badge.
-- Single-row table (id is always 1). Not per-user: the average is the same for
-- everyone. The daily cron fills it from globalpetrolprices.com; an admin can
-- override it manually (source='manual'), in which case the cron leaves it alone
-- until the override is cleared back to 'auto'.
CREATE TABLE IF NOT EXISTS fuel_prices (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  petrol_95  REAL,                              -- €/liter, national average 95
  diesel     REAL,                              -- €/liter, national average diesel
  price_date TEXT,                              -- date the price is "as of" (YYYY-MM-DD)
  source     TEXT NOT NULL DEFAULT 'auto',      -- 'auto' | 'manual'
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed the single row (empty until the first cron run or admin override).
INSERT OR IGNORE INTO fuel_prices (id, petrol_95, diesel, price_date, source)
VALUES (1, NULL, NULL, NULL, 'auto');
