DROP TABLE rpt_token;

CREATE TABLE token (
  token_id uuid NOT NULL PRIMARY KEY,
  identity_id uuid NOT NULL FOREIGN KEY REFERENCES identities (id),
  status integer NOT NULL,
  token_type char(3) NOT NULL,
  expiry_time timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL,
  updated_at timestamp with time zone,
  deleted_at timestamp with time zone  
);
