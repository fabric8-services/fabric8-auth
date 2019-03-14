-- add a new column since we want to preserve the old one for, while the
-- whole rollout is in progress and in case we need to rollback later.
ALTER TABLE users ADD COLUMN banned boolean not null default false;
-- update all existing records
UPDATE users set banned = deprovisioned;