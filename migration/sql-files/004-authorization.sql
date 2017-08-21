-- Create resource type table
CREATE TABLE resource_type (
    resource_type_id uuid primary key DEFAULT uuid_generate_v4(),
    name text NOT NULL,
    description text NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone
);

CREATE INDEX resource_type_resource_type_id_idx ON resource_type USING BTREE (resource_type_id); 

CREATE TABLE resource_type_scope (
    resource_type_scope_id uuid primary key DEFAULT uuid_generate_v4(),
    resource_type_id uuid NOT NULL,
    name text NOT NULL,
    description text NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone
);

CREATE TABLE role (
    role_id uuid primary key DEFAULT uuid_generate_v4(),
    resource_type_id uuid NOT NULL references resource_type(resource_type_id),
    name text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone
);

CREATE TABLE role_scope (
    scope_id uuid references resource_type_scope(resource_type_scope_id),
    role_id uuid references role(role_id),
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    PRIMARY KEY(scope_id, role_id)
);

CREATE TABLE resource (
    resource_id uuid primary key DEFAULT uuid_generate_v4(),
    parent_resource_id uuid NULL references resource(resource_id),
    owner_id uuid NOT NULL references identities(id),
    resource_type_id uuid NOT NULL references resource_type(resource_type_id),
    name text NULL,
    description text NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone
);

CREATE TABLE identity_role (
    identity_role_id serial primary key,
    identity_id uuid NOT NULL references identities(id),
    resource_id uuid NOT NULL references resource(resource_id),
    role_id uuid NOT NULL references role(role_id),
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone
);

CREATE TABLE identity_relationship (
    parent_identity_id uuid references identities(id),
    child_identity_id uuid references identities(id),
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    PRIMARY KEY(parent_identity_id, child_identity_id)
);