-- the 'feature_level' column as not null with a default value
UPDATE users SET feature_level = 'released' WHERE feature_level IS NULL;
ALTER TABLE users ALTER COLUMN feature_level SET NOT NULL;
ALTER TABLE users ALTER COLUMN feature_level SET default 'released';