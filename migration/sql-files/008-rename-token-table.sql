-- rename table.
ALTER TABLE "external_provider_tokens" RENAME TO "external_tokens";

-- indexes should be fine. Hence not re-creating them.