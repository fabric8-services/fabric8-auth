package model

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/authorization/repository"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

type PermissionModelService interface {
	HasScope(ctx context.Context, identityID uuid.UUID, resourceID string, scope string) (bool, error)
}

// GormPermissionModelService is the implementation of the interface for
// PermissionService. IMPORTANT NOTE: Transaction control is not provided by this service
type GormPermissionModelService struct {
	db   *gorm.DB
	repo repository.Repositories
}

// NewPermissionModelService creates a new service.
func NewPermissionModelService(db *gorm.DB, repo repository.Repositories) PermissionModelService {
	return &GormPermissionModelService{
		db:   db,
		repo: repo,
	}
}

// Creates a new organization.  The specified identityID is the user creating the organization, while the name parameter
// specifies the organization name.  The organization's identity ID is returned.
func (s *GormPermissionModelService) HasScope(ctx context.Context, identityID uuid.UUID, resourceID string, scope string) (bool, error) {

	// query for organizations in which the user is a member
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
  AND ir.role_id IN (
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
      resource_type_scope s
    WHERE
      rm.to_role_id = r.role_id
      AND r.resource_type_id = s.resource_type_id
      AND s.scope = ? /* SCOPE */
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
      trm.resource_id in (with recursive m as ( /* only resources that are in this role mapping's ancestor hierarchy */
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
      ) AS rl (role_id)
  );`,
		identityID, identityID, resourceID, scope, resourceID).Rows()
	defer rows.Close()

	if err != nil {
		return false, err
	}

	return rows.Next(), nil
}
