
-- token storage

CREATE TABLE external_providers (
    id uuid primary key DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    type text,
    url text
);

CREATE TABLE external_provider_tokens (
    id uuid primary key DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    external_provider_id uuid  REFERENCES external_providers (id),
    identity_id uuid REFERENCES identities(id),
    token text,
    scope text
);
