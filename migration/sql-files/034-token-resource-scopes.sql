ALTER TABLE token_resource ADD scopes VARCHAR;
ALTER TABLE token_resource ADD status INTEGER;
ALTER TABLE token_resource ADD CONSTRAINT token_resource_pkey PRIMARY KEY (token_id, resource_id);