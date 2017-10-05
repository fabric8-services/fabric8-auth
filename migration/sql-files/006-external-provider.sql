
-- token storage

CREATE TABLE external_provider_tokens (
    id uuid primary key DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    provider_id text not null,
    identity_id uuid REFERENCES identities(id),
    token text not null,
    scope text
);

CREATE INDEX idx_provider_id ON external_provider_tokens (lower(provider_id));
CREATE INDEX idx_external_provider_identity_id ON external_provider_tokens (identity_id);