package model

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"time"
)

// RoleManagementModelService defines the service contract for managing role assignments
type RoleManagementModelService interface {
	ListByResource(ctx context.Context, resourceID string) ([]identityrole.IdentityRole, error)
	ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]identityrole.IdentityRole, error)
}

// NewRoleManagementModelService creates a new service to manage role assignments
func NewRoleManagementModelService(db *gorm.DB, repo repository.Repositories) *GormRoleManagementModelService {
	return &GormRoleManagementModelService{
		db:         db,
		repository: repo,
	}
}

// GormRoleManagementModelService implements the RoleManagementModelService to manage role assignments
type GormRoleManagementModelService struct {
	db         *gorm.DB
	repository repository.Repositories
}

// ListByResourceAndRoleName lists role assignments of a specific resource.
func (r *GormRoleManagementModelService) ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]identityrole.IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "list"}, time.Now())
	var identityRoles []identityrole.IdentityRole

	r.db = r.db.Debug()
	db := r.db.Raw(`WITH RECURSIVE q AS ( 
		SELECT 
		  resource_id, parent_resource_id 
		FROM 
		  resource 
		WHERE 
		  resource_id = ?
		UNION ALL
		SELECT 
		  p.resource_id, p.parent_resource_id
		FROM 
		  resource p
		JOIN q ON 
		  q.parent_resource_id = p.resource_id)
	  SELECT 
		q.parent_resource_id,q.resource_id, ir.identity_role_id, ir.identity_id, r.role_id, r.name 
	  FROM 
		identity_role ir, q, role r
	  WHERE 
		ir.resource_id = q.resource_id 
		and ir.role_id = r.role_id
		and r.name = ?`, resourceID, roleName)

	rows, err := db.Rows()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resourceID,
			"err":         err,
		}, "error running custom sql to get identity roles")
		return identityRoles, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resourceID,
			"err":         err,
		}, "error getting columns")
		return identityRoles, errors.NewInternalError(ctx, err)
	}

	columnValues := make([]interface{}, len(columns))

	for rows.Next() {
		var parentResourceID *string
		var returnedResourceID string
		var identityRoleID string
		var identityID string
		var roleID string
		var roleName string

		columnValues[0] = &parentResourceID
		columnValues[1] = &returnedResourceID
		columnValues[2] = &identityRoleID
		columnValues[3] = &identityID
		columnValues[4] = &roleID
		columnValues[5] = &roleName

		if err = rows.Scan(columnValues...); err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": resourceID,
				"err":         err,
			}, "error getting rows")
			return identityRoles, errors.NewInternalError(ctx, err)
		}

		identityRoleIDAsUUID, err := uuid.FromString(identityRoleID)
		if err != nil {
			return identityRoles, errors.NewInternalError(ctx, err)
		}

		identityIDAsUUID, err := uuid.FromString(identityID)
		if err != nil {
			return identityRoles, errors.NewInternalError(ctx, err)
		}

		roleIDAsUUID, err := uuid.FromString(roleID)
		if err != nil {
			return identityRoles, errors.NewInternalError(ctx, err)
		}

		ir := identityrole.IdentityRole{
			IdentityRoleID: identityRoleIDAsUUID,
			Identity: account.Identity{
				ID: identityIDAsUUID,
			},
			Resource: resource.Resource{
				ResourceID:       resourceID,
				ParentResourceID: parentResourceID,
			},
			Role: role.Role{
				RoleID: roleIDAsUUID,
				Name:   roleName,
			},
		}
		if parentResourceID != nil {
			ir.Resource.ParentResourceID = parentResourceID
		}
		identityRoles = append(identityRoles, ir)
	}
	return identityRoles, nil
}

// ListByResource lists role assignments of a specific resource.
func (r *GormRoleManagementModelService) ListByResource(ctx context.Context, resourceID string) ([]identityrole.IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "list"}, time.Now())
	var identityRoles []identityrole.IdentityRole

	r.db = r.db.Debug()
	db := r.db.Raw(`WITH RECURSIVE q AS ( 
		SELECT 
		  resource_id, parent_resource_id 
		FROM 
		  resource 
		WHERE 
		  resource_id = ?
		UNION ALL
		SELECT 
		  p.resource_id, p.parent_resource_id
		FROM 
		  resource p
		JOIN q ON 
		  q.parent_resource_id = p.resource_id)
	  SELECT 
		q.parent_resource_id,q.resource_id, ir.identity_role_id, ir.identity_id, r.role_id, r.name 
	  FROM 
		identity_role ir, q, role r
	  WHERE 
		ir.resource_id = q.resource_id 
		and ir.role_id = r.role_id`, resourceID)

	rows, err := db.Rows()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resourceID,
			"err":         err,
		}, "error running custom sql to get identity roles")
		return identityRoles, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resourceID,
			"err":         err,
		}, "error getting columns")
		return identityRoles, errors.NewInternalError(ctx, err)
	}

	columnValues := make([]interface{}, len(columns))

	for rows.Next() {
		var parentResourceID *string
		var returnedResourceID string
		var identityRoleID string
		var identityID string
		var roleID string
		var roleName string

		columnValues[0] = &parentResourceID
		columnValues[1] = &returnedResourceID
		columnValues[2] = &identityRoleID
		columnValues[3] = &identityID
		columnValues[4] = &roleID
		columnValues[5] = &roleName

		if err = rows.Scan(columnValues...); err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_id": resourceID,
				"err":         err,
			}, "error getting rows")
			return identityRoles, errors.NewInternalError(ctx, err)
		}

		identityRoleIDAsUUID, err := uuid.FromString(identityRoleID)
		if err != nil {
			return identityRoles, errors.NewInternalError(ctx, err)
		}

		identityIDAsUUID, err := uuid.FromString(identityID)
		if err != nil {
			return identityRoles, errors.NewInternalError(ctx, err)
		}

		roleIDAsUUID, err := uuid.FromString(roleID)
		if err != nil {
			return identityRoles, errors.NewInternalError(ctx, err)
		}

		ir := identityrole.IdentityRole{
			IdentityRoleID: identityRoleIDAsUUID,
			Identity: account.Identity{
				ID: identityIDAsUUID,
			},
			Resource: resource.Resource{
				ResourceID:       resourceID,
				ParentResourceID: parentResourceID,
			},
			Role: role.Role{
				RoleID: roleIDAsUUID,
				Name:   roleName,
			},
		}
		if parentResourceID != nil {
			ir.Resource.ParentResourceID = parentResourceID
		}
		identityRoles = append(identityRoles, ir)
	}
	return identityRoles, nil
}
