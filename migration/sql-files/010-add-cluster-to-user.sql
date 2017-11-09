ALTER TABLE users ADD COLUMN cluster TEXT;
UPDATE users SET cluster = '{{.}}'  WHERE cluster is null or cluster = '';