create table invitation (
  invitation_id uuid primary key DEFAULT uuid_generate_v4(),
  invite_to uuid NOT NULL references identities (id),
  user_id uuid NOT NULL references identities (id),
  member boolean NOT NULL,
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  deleted_at timestamp with time zone
);

create table invitation_role (
  invitation_id uuid NOT NULL references invitation (invitation_id),
  role_id uuid NOT NULL references role (role_id),
  PRIMARY KEY (invitation_id, role_id)
);

create table role_mapping (
  role_mapping_id uuid primary key DEFAULT uuid_generate_v4(),
  resource_id varchar NOT NULL references resource (resource_id),
  from_role_id uuid NOT NULL references role (role_id),
  to_role_id uuid NOT NULL references role (role_id),
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  deleted_at timestamp with time zone
);

create table default_role_mapping (
  default_role_mapping_id uuid primary key DEFAULT uuid_generate_v4(),
  resource_type_id uuid NOT NULL references resource_type (resource_type_id),
  from_role_id uuid NOT NULL references role (role_id),
  to_role_id uuid NOT NULL references role (role_id),
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  deleted_at timestamp with time zone
);

INSERT INTO resource_type (name) VALUES ('identity/team');
INSERT INTO resource_type (name) VALUES ('identity/group');