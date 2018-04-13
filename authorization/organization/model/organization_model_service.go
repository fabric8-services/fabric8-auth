package model

import (
	"context"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization"
	organization "github.com/fabric8-services/fabric8-auth/authorization/organization"

	"github.com/fabric8-services/fabric8-auth/authorization/repository"

	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
)

type OrganizationModelService interface {
	CreateOrganization(ctx context.Context, identityID uuid.UUID, organizationName string) (*uuid.UUID, error)
	ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]organization.IdentityOrganization, error)
}

// GormOrganizationModelService is the implementation of the interface for
// OrganizationService. IMPORTANT NOTE: Transaction control is not provided by this service
type GormOrganizationModelService struct {
	db   *gorm.DB
	repo repository.Repositories
}

// NewOrganizationModelService creates a new service.
func NewOrganizationModelService(db *gorm.DB, repo repository.Repositories) OrganizationModelService {
	return &GormOrganizationModelService{
		db:   db,
		repo: repo,
	}
}

// Creates a new organization.  The specified identityID is the user creating the organization, while the name parameter
// specifies the organization name.  The organization's identity ID is returned.
func (s *GormOrganizationModelService) CreateOrganization(ctx context.Context, identityID uuid.UUID, organizationName string) (*uuid.UUID, error) {
	var organizationId uuid.UUID

	// Lookup the identity for the current user
	userIdentity, err := s.repo.Identities().Load(ctx, identityID)
	if err != nil {
		return nil, errors.NewUnauthorizedError(fmt.Sprintf("auth token contains id %s of unknown Identity\n", identityID))
	}

	// Lookup the organization resource type
	resourceType, err := s.repo.ResourceTypeRepository().Lookup(ctx, authorization.IdentityResourceTypeOrganization)
	if err != nil {
		return nil, err
	}

	// Create the organization resource
	res := &resource.Resource{
		Name:           organizationName,
		ResourceType:   *resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
	}

	err = s.repo.ResourceRepository().Create(ctx, res)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}

	// Create the organization identity
	orgIdentity := &account.Identity{
		IdentityResourceID: &res.ResourceID,
	}

	err = s.repo.Identities().Create(ctx, orgIdentity)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}

	organizationId = orgIdentity.ID

	// Lookup the identity/organization owner role
	ownerRole, err := s.repo.RoleRepository().Lookup(ctx, organization.OrganizationOwnerRole, authorization.IdentityResourceTypeOrganization)

	if err != nil {
		return nil, errors.NewInternalErrorFromString(ctx, "Error looking up owner role for 'identity/organization' resource type")
	}

	// Assign the owner role for the new organization to the current user
	identityRole := &identityrole.IdentityRole{
		IdentityID: userIdentity.ID,
		ResourceID: res.ResourceID,
		RoleID:     ownerRole.RoleID,
	}

	err = s.repo.IdentityRoleRepository().Create(ctx, identityRole)
	if err != nil {
		return nil, err
	}

	log.Debug(ctx, map[string]interface{}{
		"organization_id": organizationId.String(),
	}, "organization created")

	return &organizationId, nil
}

// Returns an array of all organizations in which the specified user is a member or is assigned a role
func (s *GormOrganizationModelService) ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]organization.IdentityOrganization, error) {

	db := s.db.Model(&account.Identity{})

	findOrganization := func(orgs []organization.IdentityOrganization, id uuid.UUID) int {
		for i, org := range orgs {
			if org.OrganizationID == id {
				return i
			}
		}
		return -1
	}

	results := []organization.IdentityOrganization{}

	// query for organizations in which the user is a member
	rows, err := db.Unscoped().Raw(`SELECT 
      oi.ID,
      r.name
    FROM 
      resource r, 
      identities oi, 
      resource_type rt
		WHERE 
      oi.identity_resource_id = r.resource_id 
      and r.resource_type_id = rt.resource_type_id
		  and rt.name = ? 
      and oi.deleted_at IS NULL
      and r.deleted_at IS NULL
      and rt.deleted_at IS NULL
      and (oi.ID = ? 
      OR oi.ID in (
        WITH RECURSIVE m AS (
		      SELECT 
            member_of 
          FROM 
            membership 
          WHERE 
            member_id = ? 
          UNION SELECT 
            p.member_of 
          FROM 
            membership p INNER JOIN m ON m.member_of = p.member_id
        ) 
        select member_of from m
      ))`,
		authorization.IdentityResourceTypeOrganization, identityID, identityID).Rows()

	if err != nil {
		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		var id string
		var name string
		rows.Scan(&id, &name)
		organizationId, err := uuid.FromString(id)
		if err != nil {
			return nil, err
		}

		idx := findOrganization(results, organizationId)
		if idx == -1 {
			results = append(results, organization.IdentityOrganization{
				OrganizationID: organizationId,
				Name:           name,
				Member:         true,
				Roles:          []string{},
			})
		} else {
			results[idx].Member = true
		}
	}

	// query for organizations for which the user has a role, or the user is a member of a team or group that has a role
	rows, err = db.Unscoped().Raw(`SELECT 
      i.id, 
      r.name,
      role.name
    FROM 
      identity_role ir, 
      resource r, 
      identities i,
      resource_type rt, role
		WHERE 
      ir.resource_id = r.resource_id
      and ir.resource_id = i.identity_resource_id
      and ir.role_id = role.role_id 
      and r.resource_type_id = rt.resource_type_id 
		  and rt.name = ? 
      and ir.deleted_at IS NULL
      and r.deleted_at IS NULL
      and rt.deleted_at IS NULL
      and role.deleted_at IS NULL
      and (ir.identity_id = ? 
      OR ir.identity_id in (
        WITH RECURSIVE m AS ( 
		      SELECT 
            member_id, 
            member_of 
          FROM 
            membership 
          WHERE 
            member_id = ? 
		      UNION SELECT 
            p.member_id, 
            p.member_of 
          FROM 
            membership p INNER JOIN m ON m.member_of = p.member_id
        )
		    select member_id from m
      ))`,
		authorization.IdentityResourceTypeOrganization, identityID, identityID).Rows()

	if err != nil {
		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		var id string
		var name string
		var roleName string
		rows.Scan(&id, &name, &roleName)
		organizationId, err := uuid.FromString(id)
		if err != nil {
			return nil, err
		}

		idx := findOrganization(results, organizationId)
		if idx == -1 {
			results = append(results, organization.IdentityOrganization{
				OrganizationID: organizationId,
				Name:           name,
				Member:         false,
				Roles:          []string{roleName},
			})
		} else {
			found := false
			// Check if the role is already in the entry
			for _, r := range results[idx].Roles {
				if r == roleName {
					found = true
					break
				}
			}

			if !found {
				results[idx].Roles = append(results[idx].Roles, roleName)
			}

		}
	}

	return results, nil
}
