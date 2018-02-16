package assignment

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization/repositories"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"time"
)

// RoleAssignmentModelService defines the service contract for managing role assignments
type RoleAssignmentModelService interface {
	ListByResource(ctx context.Context, resourceID string) ([]role.IdentityRole, error)
}

// NewRoleAssignmentModelService creates a new service to manage role assignments
func NewRoleAssignmentModelService(db *gorm.DB, repo repositories.Repositories) *GormRoleAssignmentModelService {
	return &GormRoleAssignmentModelService{
		db:           db,
		repositories: repo,
	}
}

// GormRoleAssignmentModelService implements the RoleAssignmentModelService to manage role assignments
type GormRoleAssignmentModelService struct {
	db           *gorm.DB
	repositories repositories.Repositories
}

// ListByResource lists role assignments of a specific resource.
func (r *GormRoleAssignmentModelService) ListByResource(ctx context.Context, resourceID string) ([]role.IdentityRole, error) {
	defer goa.MeasureSince([]string{"goa", "db", "identity_role", "list"}, time.Now())
	var identityRoles []role.IdentityRole

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
	columnValues := make([]interface{}, len(columns))

	var ignore interface{}
	for index := range columnValues {
		columnValues[index] = &ignore
	}

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource_id": resourceID,
			"err":         err,
		}, "error getting columns")
		return identityRoles, errors.NewInternalError(ctx, err)
	}

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

		ir := role.IdentityRole{
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
