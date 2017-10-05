
-- token storage

CREATE TABLE external_provider_tokens (
    id uuid primary key DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    external_provider_type text not null,
    identity_id uuid REFERENCES identities(id),
    token text not null,
    scope text
);

CREATE INDEX idx_external_provider_type ON external_provider_tokens (lower(external_provider_type));
CREATE INDEX idx_external_provider_identity_id ON external_provider_tokens (identity_id);