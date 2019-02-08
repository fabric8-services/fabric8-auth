-- add an 'active' column (default true) in the 'user' table
ALTER TABLE users ADD COLUMN active boolean DEFAULT true;