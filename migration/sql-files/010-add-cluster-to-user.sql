ALTER TABLE users ADD COLUMN cluster TEXT;
UPDATE users SET cluster = '{{ index . 0}}'  WHERE cluster is null or cluster = '';
ALTER TABLE users ALTER COLUMN cluster set NOT NULL ,ADD CHECK (cluster <> '');
