CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- identity

CREATE TABLE identities (
    id uuid primary key DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    username text,
    provider_type text,
    profile_url text,
    registration_completed boolean NOT NULL DEFAULT FALSE,
    user_id uuid
);

-- user

CREATE TABLE users (
    id uuid primary key DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    email text,
    full_name text,
    image_url text,
    bio text,
    url text,
    context_information jsonb,
    company text
);

CREATE UNIQUE INDEX uix_users_email ON users USING btree (email);

-- index to query identity by profile_url, which must be unique 
CREATE UNIQUE INDEX uix_identity_profileurl ON identities USING btree (profile_url) WHERE deleted_at IS NULL;

-- index to query identity by user_id
CREATE INDEX uix_identity_userid ON identities USING btree (user_id);

-- Add a foreign key constraint to identities
ALTER TABLE identities add constraint identities_user_id_users_id_fk foreign key (user_id) REFERENCES users (id);

CREATE INDEX idx_user_full_name ON users (lower(full_name));
CREATE INDEX idx_user_email ON users (lower(email));
CREATE INDEX idx_identities_username ON identities (username);