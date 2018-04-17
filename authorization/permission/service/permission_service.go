package service

import (
	"context"

	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
)

type PermissionService interface {
	HasScope(ctx context.Context, identityID uuid.UUID, resourceID string, scopeName string) (bool, error)
}

// GormPermissionModelService is the implementation of the interface for
// PermissionService. IMPORTANT NOTE: Transaction control is not provided by this service
type PermissionServiceImpl struct {
	PermissionService
	db *gorm.DB
}

// NewPermissionModelService creates a new service.
func NewPermissionService(db *gorm.DB) PermissionService {
	return &PermissionServiceImpl{
		db: db,
	}
}

// HasScope does a permission check for a user, to determine whether they have a particular scope for the
// specified resource.  It does this by executing a rather complex query against the database, which checks whether the
// user, or any of the identity groups (i.e. teams, organizations, security groups) that it is a member of has been
// assigned a role that grants the specified scope.  It takes into account resource hierarchies, checking the roles of
// parent and other ancestor resources, and also takes into account role mappings, which allow roles assigned for a
// certain type of resource in the resource ancestry to map to a role for a different resource type lower in the
// resource hierarchy.
func (s *PermissionServiceImpl) HasScope(ctx context.Context, identityID uuid.UUID, resourceID string, scopeName string) (bool, error) {

	rows, err := s.db.Unscoped().Raw(`SELECT
  count(1) roles
FROM
  identity_role ir
WHERE
  ir.identity_id in (
  SELECT
    id
  FROM
    identities i
  WHERE
    id = ? /* IDENTITY_ID */
    OR id in (
    WITH RECURSIVE m AS (
      SELECT 
        member_of 
      FROM 
        membership 
      WHERE 
        member_id = ? /* IDENTITY_ID */
      UNION SELECT 
        p.member_of 
      FROM 
        membership p INNER JOIN m ON m.member_of = p.member_id
    ) 
    SELECT member_of FROM m
    )
  )
  AND ir.resource_id IN (
  WITH RECURSIVE m AS (
  SELECT
    resource_id, parent_resource_id
  FROM
    resource
  WHERE
    resource_id = ? /* RESOURCE_ID */
  UNION SELECT
    p.resource_id, p.parent_resource_id
  FROM
    resource p INNER JOIN m ON m.parent_resource_id = p.resource_id
  )
  SELECT
    m.resource_id
  FROM
    m
  )
  AND (ir.role_id IN (
    SELECT
      r.role_id
    FROM
      resource res,
      role r,
      role_scope rs,
      resource_type_scope rts
    WHERE
      res.resource_id = ? /* RESOURCE_ID */
      AND res.resource_type_id = r.resource_type_id
      AND r.role_id = rs.role_id
      AND rs.scope_id = rts.resource_type_scope_id
      AND rts.name = ? /* SCOPE */
  ) OR ir.role_id IN (
    SELECT DISTINCT
      rl.role_id
    FROM
      (
    WITH RECURSIVE prm AS (
    SELECT
      rm.from_role_id,
      rm.to_role_id
    FROM
      role_mapping rm,
      role r,
      role_scope rs,
      resource_type_scope rts
    WHERE
      rm.to_role_id = r.role_id
      AND r.role_id = rs.role_id
      AND rs.scope_id = rts.resource_type_scope_id
      AND rts.name = ? /* SCOPE */
      AND rm.resource_id IN (WITH RECURSIVE m AS ( /* only resources that are in the ancestor hierarchy */
      SELECT
        resource_id, parent_resource_id
      FROM
        resource
      WHERE
        resource_id = ? /* RESOURCE_ID */
      UNION SELECT
        p.resource_id, p.parent_resource_id
      FROM
        resource p INNER JOIN m ON m.parent_resource_id = p.resource_id
      )
      SELECT
        m.resource_id
      FROM
        m)
    UNION SELECT
     trm.from_role_id,
     trm.to_role_id
    FROM
      role_mapping trm INNER JOIN prm ON prm.from_role_id = trm.to_role_id
    WHERE
      trm.resource_id IN (WITH RECURSIVE m AS ( /* only resources that are in this role mapping's ancestor hierarchy */
      SELECT
        resource_id, parent_resource_id
      FROM
        resource
      WHERE 
        resource_id = trm.resource_id
      UNION SELECT
        p.resource_id, p.parent_resource_id
      FROM
        resource p INNER JOIN m ON m.parent_resource_id = p.resource_id
      )
      SELECT 
        m.resource_id
      FROM
        m)
      )
    SELECT 
      prm.from_role_id,
      prm.to_role_id
    FROM
      prm) AS mappings
    CROSS JOIN LATERAL (
      VALUES (from_role_id), (to_role_id)
      ) AS rl (role_id))
  );`,
		identityID, identityID, resourceID, resourceID, scopeName, scopeName, resourceID).Rows()

	if err != nil {
		return false, err
	}

	rolesFound := false
	defer rows.Close()
	for rows.Next() {
		var roles int
		rows.Scan(&roles)
		if roles > 0 {
			rolesFound = true
			break
		}
	}
	return rolesFound, nil
}
