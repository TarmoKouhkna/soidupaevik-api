-- Detailse sõidurežiimi migratsioon
-- Käivita: wrangler d1 execute soidupaevik-db --remote --file=migration-detail.sql

ALTER TABLE reports ADD COLUMN mode TEXT NOT NULL DEFAULT 'simple';

ALTER TABLE trips ADD COLUMN route      TEXT;
ALTER TABLE trips ADD COLUMN km         INTEGER;
ALTER TABLE trips ADD COLUMN plate      TEXT;
ALTER TABLE trips ADD COLUMN odom_start INTEGER;
ALTER TABLE trips ADD COLUMN odom_end   INTEGER;
ALTER TABLE trips ADD COLUMN trip_type  TEXT NOT NULL DEFAULT 'T';
ALTER TABLE trips ADD COLUMN notes      TEXT;
