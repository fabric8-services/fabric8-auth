DROP TABLE token_resource;

CREATE TABLE privilege_cache (
  privilege_cache_id uuid NOT NULL PRIMARY KEY,
  identity_id uuid NOT NULL FOREIGN KEY REFERENCES identities (id),
  resource_id uuid NOT NULL FOREIGN KEY REFERENCES resource (resource_id),
  scopes varchar,
  stale boolean,
  expiry_time timestamp with time zone,
  created_at timestamp with time zone NOT NULL,
  updated_at timestamp with time zone,
  deleted_at timestamp with time zone
);

CREATE TABLE token_privilege (
  token_id uuid NOT NULL PRIMARY KEY,
  privilege_cache_id NOT NULL PRIMARY KEY
);