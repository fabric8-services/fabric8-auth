
-- token storage

CREATE TABLE external_provider_tokens (
    id uuid primary key DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    provider_type text,
    identity_id uuid,
    version integer DEFAULT 0 NOT NULL
);

