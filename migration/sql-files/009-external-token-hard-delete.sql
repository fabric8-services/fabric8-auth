-- External tokens should be hard deletable
ALTER TABLE external_tokens
  DROP deleted_at;
