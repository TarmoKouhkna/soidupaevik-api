-- ============================================================
-- Migratsioon: esmaklassiline sõiduki-entiteet (Option B)
-- ============================================================
-- Lisab `vehicles` tabeli, seob olemasolevad aruanded sõidukitega
-- (eraldatud eri reg. märkide järgi) ja muudab reports unikaalsuse
-- (user_id, year, month) -> (user_id, year, month, vehicle_id), et sama
-- kuu mahuks mitu autot (keset kuud autovahetus = kaks aruannet).
--
-- Käivita ÜKS KORD:
--   wrangler d1 execute soidupaevik-db --local  --file=migration-vehicles.sql   (test)
--   wrangler d1 execute soidupaevik-db --remote --file=migration-vehicles.sql   (toodang)
--
-- ENNE TOODANGUT: varukoopia!
--   wrangler d1 export soidupaevik-db --remote --output backup.sql
--
-- Re-run kaitse: samm "ALTER TABLE reports ADD COLUMN vehicle_id" annab vea,
-- kui migratsioon on juba tehtud, nii et kogemata teist korda jooksutamine katkeb.
-- ============================================================

-- 1. Sõidukite tabel ------------------------------------------------
CREATE TABLE IF NOT EXISTS vehicles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  plate TEXT NOT NULL,
  label TEXT,
  is_default INTEGER NOT NULL DEFAULT 0,
  archived INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vehicles_user ON vehicles(user_id);

-- 2. Üks sõiduk iga erineva reg. märgi kohta (normaliseeritud TRIM+UPPER) --
INSERT INTO vehicles (user_id, plate, is_default, created_at)
SELECT user_id, TRIM(UPPER(plate)), 0, datetime('now')
FROM reports
WHERE plate IS NOT NULL AND TRIM(plate) <> ''
GROUP BY user_id, TRIM(UPPER(plate));

-- 3. Lisa ka seadetes olev praegune reg. märk, kui seda veel pole -------
INSERT INTO vehicles (user_id, plate, is_default, created_at)
SELECT s.user_id, TRIM(UPPER(s.value)), 0, datetime('now')
FROM settings s
WHERE s.key = 'plate' AND s.value IS NOT NULL AND TRIM(s.value) <> ''
  AND NOT EXISTS (
    SELECT 1 FROM vehicles v
    WHERE v.user_id = s.user_id AND TRIM(UPPER(v.plate)) = TRIM(UPPER(s.value))
  );

-- 4. Tagavarasõiduk kasutajatele, kel on aruandeid aga ükski plaat polnud --
INSERT INTO vehicles (user_id, plate, is_default, created_at)
SELECT DISTINCT user_id, '(määramata)', 0, datetime('now')
FROM reports
WHERE user_id NOT IN (SELECT user_id FROM vehicles);

-- 5. Määra igale kasutajale täpselt üks vaikesõiduk --------------------
--   5a. eelista seadetes olevale märgile vastavat sõidukit
UPDATE vehicles SET is_default = 1
WHERE id IN (
  SELECT MIN(v.id) FROM vehicles v
  JOIN settings s ON s.user_id = v.user_id AND s.key = 'plate'
    AND TRIM(UPPER(s.value)) = TRIM(UPPER(v.plate))
  GROUP BY v.user_id
);
--   5b. muidu uusima aruande sõiduk
UPDATE vehicles SET is_default = 1
WHERE id IN (
  SELECT MIN(v.id) FROM vehicles v
  JOIN reports r ON r.user_id = v.user_id AND TRIM(UPPER(r.plate)) = TRIM(UPPER(v.plate))
  WHERE v.user_id NOT IN (SELECT user_id FROM vehicles WHERE is_default = 1)
    AND r.updated_at = (SELECT MAX(r2.updated_at) FROM reports r2 WHERE r2.user_id = v.user_id)
  GROUP BY v.user_id
);
--   5c. ülejäänutele (nt ainult seadete-sõidukiga) esimene sõiduk
UPDATE vehicles SET is_default = 1
WHERE id IN (
  SELECT MIN(id) FROM vehicles
  WHERE user_id NOT IN (SELECT user_id FROM vehicles WHERE is_default = 1)
  GROUP BY user_id
);

-- 6. Lisa reports.vehicle_id veerg ------------------------------------
ALTER TABLE reports ADD COLUMN vehicle_id INTEGER;

-- 7. Seo aruanded sõidukitega -----------------------------------------
--   7a. plaadi järgi
UPDATE reports SET vehicle_id = (
  SELECT v.id FROM vehicles v
  WHERE v.user_id = reports.user_id AND TRIM(UPPER(v.plate)) = TRIM(UPPER(reports.plate))
  LIMIT 1
)
WHERE plate IS NOT NULL AND TRIM(plate) <> '';
--   7b. plaadita aruanded -> vaikesõiduk
UPDATE reports SET vehicle_id = (
  SELECT v.id FROM vehicles v WHERE v.user_id = reports.user_id AND v.is_default = 1 LIMIT 1
)
WHERE vehicle_id IS NULL;

-- 8. reports ümberehitus uue UNIQUE(user_id, year, month, vehicle_id)-ga --
--   `trips` read varundatakse, sest reports DROP võib FK ON DELETE CASCADE
--   tõttu trips-read kustutada — taastame need pärast. (D1 FK-käitumisest sõltumatu.)
CREATE TABLE trips_backup AS SELECT * FROM trips;

CREATE TABLE reports_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  vehicle_id INTEGER,
  year INTEGER NOT NULL,
  month INTEGER NOT NULL,
  employee_name TEXT,
  plate TEXT,
  employer TEXT,
  prev_speedo INTEGER,
  end_speedo INTEGER,
  trip_distance INTEGER DEFAULT 100,
  route TEXT,
  purpose TEXT,
  mode TEXT NOT NULL DEFAULT 'simple',
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_id, year, month, vehicle_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE SET NULL
);

INSERT INTO reports_new
  (id, user_id, vehicle_id, year, month, employee_name, plate, employer,
   prev_speedo, end_speedo, trip_distance, route, purpose, mode, updated_at)
SELECT
   id, user_id, vehicle_id, year, month, employee_name, plate, employer,
   prev_speedo, end_speedo, trip_distance, route, purpose, mode, updated_at
FROM reports;

DROP TABLE reports;
ALTER TABLE reports_new RENAME TO reports;

-- Taasta trips-read (kui cascade need kustutas, on tabel tühi; muidu identne) --
DELETE FROM trips;
INSERT INTO trips SELECT * FROM trips_backup;
DROP TABLE trips_backup;

-- 9. Taasta indeks ----------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id, year DESC, month DESC);

-- ============================================================
-- Kontroll pärast migratsiooni (käivita käsitsi, ära jäta faili):
--   SELECT COUNT(*) FROM vehicles;
--   SELECT COUNT(*) FROM reports WHERE vehicle_id IS NULL;   -- peaks 0
--   SELECT user_id, COUNT(*) FROM vehicles WHERE is_default=1 GROUP BY user_id HAVING COUNT(*)<>1;  -- tühi
--   SELECT (SELECT COUNT(*) FROM trips) AS trips_now;        -- == enne migratsiooni
-- ============================================================
