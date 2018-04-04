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

INSERT INTO resource_type_scope (resource_type_scope_id, resource_type_id, name) SELECT '87c2a3b2-6b7c-4d67-be4d-c73d5f51864b', resource_type_id, 'invite_user' FROM resource_type WHERE name = 'identity/organization';
INSERT INTO role_scope (scope_id, role_id) SELECT '87c2a3b2-6b7c-4d67-be4d-c73d5f51864b', r.role_id FROM role r, resource_type rt WHERE r.resource_type_id = rt.resource_type_id AND r.name = 'owner' AND rt.name = 'identity/organization';