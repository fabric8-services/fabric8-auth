ALTER TABLE resource DROP CONSTRAINT resource_parent_resource_id_fkey;
ALTER TABLE identity_role DROP CONSTRAINT identity_role_resource_id_fkey;

ALTER TABLE resource ALTER COLUMN resource_id TYPE varchar(256);
ALTER TABLE resource ALTER COLUMN parent_resource_id TYPE varchar(256);
ALTER TABLE resource ALTER COLUMN name TYPE varchar(256);
ALTER TABLE resource DROP COLUMN owner_id;

ALTER TABLE resource ADD CONSTRAINT resource_parent_resource_id_fkey FOREIGN KEY (parent_resource_id) REFERENCES resource (resource_id);

ALTER TABLE resource ADD COLUMN creator_id uuid REFERENCES Identities (id);

ALTER TABLE identity_role ALTER COLUMN resource_id TYPE varchar(256);
ALTER TABLE identity_role ADD CONSTRAINT identity_role_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES resource (resource_id);

ALTER TABLE identities ADD COLUMN identity_resource_id varchar(256);
ALTER TABLE identities ADD CONSTRAINT identities_identity_resource_id_fkey FOREIGN KEY (identity_resource_id) REFERENCES resource (resource_id);

ALTER TABLE role ALTER COLUMN name TYPE varchar(256);

CREATE TABLE membership (
  member_of uuid NOT NULL references identities (id),
  member_id uuid NOT NULL references identities (id),
  PRIMARY KEY (member_of, member_id)
);

CREATE TABLE rpt_token (
  token_id uuid primary key,
  expiry_time timestamp with time zone NOT NULL,
  identity_id uuid NOT NULL REFERENCES identities (id),
  status integer NOT NULL
);
  
CREATE TABLE token_resource (
  token_id uuid NOT NULL references rpt_token (token_id),
  resource_id varchar NOT NULL references resource (resource_id),
  last_accessed timestamp with time zone
);