-- Support for multiple clusters
-- The default value can't be set at a data model level since the default cluster varies with environment.

ALTER TABLE users ADD COLUMN cluster TEXT;
