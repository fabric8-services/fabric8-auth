-- make sure there's always a value in the 'last_active' column
ALTER TABLE identities ALTER COLUMN last_active set default now();

-- set the default value in the 'last_active' column to the date of the deployment on production
update identities set last_active = '2019-03-04:00:00:00' where last_active is null; 