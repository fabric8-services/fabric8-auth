drop index idx_identities_username;
drop index idx_user_email;
drop index idx_user_full_name;

CREATE EXTENSION pg_trgm;
create index ix_users_email_gin on users using gin (lower(email) gin_trgm_ops);
create index ix_users_full_name_gin on users using gin (lower(full_name) gin_trgm_ops);
create index ix_identities_username_gin on identities using gin (username gin_trgm_ops);
