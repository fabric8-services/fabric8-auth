-- drop existing index
DROP INDEX idx_provider_id;
-- recreate case sensitive index idx_provider_id
CREATE INDEX idx_provider_id ON external_provider_tokens (provider_id);