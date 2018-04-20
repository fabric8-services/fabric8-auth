package model

import (
	"context"
	"strings"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
)

// RoleManagementModelService defines the service contract for managing role assignments
type RoleManagementModelService interface {
	ListAssignmentsByIdentityAndResource(ctx context.Context, resourceID string, identity uuid.UUID) ([]rolerepo.IdentityRole, error)
	ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleScope, error)
	Assign(ctx context.Context, identityID uuid.UUID, resourceID string, roleName string) error
	ListByResource(ctx context.Context, resourceID string) ([]rolerepo.IdentityRole, error)
	ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]rolerepo.IdentityRole, error)
}

// NewRoleManagementModelService creates a new service to manage role assignments
func NewRoleManagementModelService(db *gorm.DB) *GormRoleManagementModelService {
	return &GormRoleManagementModelService{
		db: db,
	}
}

// GormRoleManagementModelService implements the RoleManagementModelService to manage role assignments
type GormRoleManagementModelService struct {
	db *gorm.DB
}

// ListAssignmentsByIdentityAndResource lists all the roles that have been assigned to a specific identity ( users or organizations or teams or groups ) for a specific resource
func (r *GormRoleManagementModelService) ListAssignmentsByIdentityAndResource(ctx context.Context, resourceID string, identityID uuid.UUID) ([]rolerepo.IdentityRole, error) {
	repo := rolerepo.NewIdentityRoleRepository(r.db)
	return repo.ListByIdentityAndResource(ctx, resourceID, identityID)
}

// AssignMultiple assigns a user identity with a role, for a specific resource
func (r *GormRoleManagementModelService) AssignMultiple(ctx context.Context, identityIDs []uuid.UUID, resourceID string, roleName string) error {
	for _, identityID := range identityIDs {
		err := r.Assign(ctx, identityID, resourceID, roleName)
		if err != nil {
			return err
		}

	}
	return nil
}

// Assign assigns an identity ( users or organizations or teams or groups ) with a role, for a specific resource
func (r *GormRoleManagementModelService) Assign(ctx context.Context, identityID uuid.UUID, resourceID string, roleName string) error {

	resourceRepository := resource.NewResourceRepository(r.db)
	rt, err := resourceRepository.Load(ctx, resourceID)
	if err != nil {
		return err
	}

	roleRepository := rolerepo.NewRoleRepository(r.db)
	roleRef, err := roleRepository.Lookup(ctx, roleName, rt.ResourceType.Name)
	if err != nil {
		return err
	}

	ir := rolerepo.IdentityRole{
		ResourceID: resourceID,
		IdentityID: identityID,
		RoleID:     roleRef.RoleID,
	}

	identityRepository := rolerepo.NewIdentityRoleRepository(r.db)
	return identityRepository.Create(ctx, &ir)
}

// ListByResourceAndRoleName lists role assignments of a specific resource.
func (r *GormRoleManagementModelService) ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]rolerepo.IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "list"}, time.Now())
	var identityRoles []rolerepo.IdentityRole

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

		ir := rolerepo.IdentityRole{
			IdentityRoleID: identityRoleIDAsUUID,
			Identity: account.Identity{
				ID: identityIDAsUUID,
			},
			IdentityID: identityIDAsUUID,
			Resource: resource.Resource{
				ResourceID:       resourceID,
				ParentResourceID: parentResourceID,
			},
			ResourceID: resourceID,
			Role: rolerepo.Role{
				RoleID: roleIDAsUUID,
				Name:   roleName,
			},
			RoleID: roleIDAsUUID,
		}
		if parentResourceID != nil {
			ir.Resource.ParentResourceID = parentResourceID
		}
		identityRoles = append(identityRoles, ir)
	}
	return identityRoles, nil
}

// ListByResource lists role assignments of a specific resource.
func (r *GormRoleManagementModelService) ListByResource(ctx context.Context, resourceID string) ([]rolerepo.IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "list"}, time.Now())
	var identityRoles []rolerepo.IdentityRole

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

		ir := rolerepo.IdentityRole{
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

	db := r.db.Raw(`SELECT r.role_id,
		r.name role_name,
		array_to_string(array_agg(rts.NAME), ',') scopes
		FROM   
		  role r LEFT OUTER JOIN role_scope rs ON r.role_id = rs.role_id
		  LEFT OUTER JOIN resource_type_scope rts ON rs.scope_id = rts.resource_type_scope_id,
			resource_type rt
		WHERE  
			rt.resource_type_id = r.resource_type_id 
			AND rt.NAME = ?
		GROUP BY 
		  r.role_id, 
		  r.name`, resourceType)

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
		var scopesList []string
		if scopeNames != "" {
			scopesList = strings.Split(scopeNames, ",")
		}
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
