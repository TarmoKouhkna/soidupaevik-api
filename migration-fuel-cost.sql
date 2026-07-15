-- Fuel cost estimate on the month card.
-- Per-vehicle fuel type + consumption, and a per-report snapshot of the fuel
-- price at save time so each report's estimate stays stable.
ALTER TABLE vehicles ADD COLUMN fuel_type TEXT;          -- '95' | 'diesel'
ALTER TABLE vehicles ADD COLUMN fuel_consumption REAL;   -- liters / 100 km
ALTER TABLE reports  ADD COLUMN fuel_price REAL;         -- €/liter captured when the report was saved
