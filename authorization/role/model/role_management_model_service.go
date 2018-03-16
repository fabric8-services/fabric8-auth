package model

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"strings"
	"time"
)

// RoleManagementModelService defines the service contract for managing role assignments
type RoleManagementModelService interface {
	ListByResource(ctx context.Context, resourceID string) ([]identityrole.IdentityRole, error)
	ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleScope, error)
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
			Role: rolerepo.Role{
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
			Role: rolerepo.Role{
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

// ListAvailableRolesByResourceType lists role assignments of a specific resource.
func (r *GormRoleManagementModelService) ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleScope, error) {
	defer goa.MeasureSince([]string{"goa", "db", "role", "listAvailableRoles"}, time.Now())
	var roleScopes []role.RoleScope

	r.db = r.db.Debug()
	db := r.db.Raw(`SELECT r.role_id,
		r.name role_name,
		array_to_string(array_agg(rts.NAME), ',') scopes
		FROM   resource_type_scope rts, 
			   role_scope rs, 
			   resource_type rt, 
			   role r 
		WHERE  rs.scope_id = rts.resource_type_scope_id 
			   AND rs.role_id = r.role_id 
			   AND rt.resource_type_id = r.resource_type_id 
			   AND rt.NAME = ?
		group by r.role_id, r.name`, resourceType)

	rows, err := db.Rows()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resourceType": resourceType,
			"err":          err,
		}, "error running custom sql to get available roles")
		return roleScopes, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	columnValues := make([]interface{}, len(columns))

	var ignore interface{}
	for index := range columnValues {
		columnValues[index] = &ignore
	}

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_type": resourceType,
			"err":           err,
		}, "error getting columns")
		return roleScopes, errors.NewInternalError(ctx, err)
	}

	for rows.Next() {
		var roleName string
		var scopeNames string
		var roleID string

		columnValues[0] = &roleID
		columnValues[1] = &roleName
		columnValues[2] = &scopeNames

		if err = rows.Scan(columnValues...); err != nil {
			log.Error(ctx, map[string]interface{}{
				"resource_type": resourceType,
				"err":           err,
			}, "error getting rows")
			return roleScopes, errors.NewInternalError(ctx, err)
		}
		scopesList := strings.Split(scopeNames, ",")
		roleScope := role.RoleScope{
			RoleName:     roleName,
			RoleID:       roleID,
			Scopes:       scopesList,
			ResourceType: resourceType,
		}
		roleScopes = append(roleScopes, roleScope)
	}
	return roleScopes, err
}
