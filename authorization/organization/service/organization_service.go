package service

import (
	"context"
	"fmt"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"

	"database/sql"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/satori/go.uuid"
)

// organizationServiceImpl is the default implementation of OrganizationService.
type organizationServiceImpl struct {
	base.BaseService
}

// NewOrganizationService creates a new service.
func NewOrganizationService(context *service.ServiceContext) service.OrganizationService {
	return &organizationServiceImpl{base.NewBaseService(context)}
}

// Creates a new organization.  The specified identityID is the user creating the organization, while the name parameter
// specifies the organization name.  The organization's identity ID is returned.
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (s *organizationServiceImpl) CreateOrganization(ctx context.Context, identityID uuid.UUID, organizationName string) (*uuid.UUID, error) {
	var organizationId uuid.UUID

	err := s.Transactional(func() error {
		// Lookup the identity for the current user
		userIdentity, err := s.Repositories().Identities().Load(ctx, identityID)
		if err != nil {
			return errors.NewUnauthorizedError(fmt.Sprintf("auth token contains id %s of unknown Identity\n", identityID))
		}

		// Lookup the organization resource type
		resourceType, err := s.Repositories().ResourceTypeRepository().Lookup(ctx, authorization.IdentityResourceTypeOrganization)
		if err != nil {
			return err
		}

		// Create the organization resource
		res := &resource.Resource{
			Name:           organizationName,
			ResourceType:   *resourceType,
			ResourceTypeID: resourceType.ResourceTypeID,
		}

		err = s.Repositories().ResourceRepository().Create(ctx, res)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		// Create the organization identity
		orgIdentity := &account.Identity{
			IdentityResourceID: sql.NullString{res.ResourceID, true},
		}

		err = s.Repositories().Identities().Create(ctx, orgIdentity)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		organizationId = orgIdentity.ID

		// Lookup the identity/organization owner role
		ownerRole, err := s.Repositories().RoleRepository().Lookup(ctx, authorization.OwnerRole, authorization.IdentityResourceTypeOrganization)

		if err != nil {
			return errors.NewInternalErrorFromString(ctx, "Error looking up owner role for 'identity/organization' resource type")
		}

		// Assign the owner role for the new organization to the current user
		identityRole := &role.IdentityRole{
			IdentityID: userIdentity.ID,
			ResourceID: res.ResourceID,
			RoleID:     ownerRole.RoleID,
		}

		err = s.Repositories().IdentityRoleRepository().Create(ctx, identityRole)
		if err != nil {
			return err
		}

		log.Debug(ctx, map[string]interface{}{
			"organization_id": organizationId.String(),
		}, "organization created")

		return err
	})

	if err != nil {
		return nil, err
	}

	return &organizationId, nil
}

// Returns an array of all organizations in which the specified identity is a member or is assigned a role
func (s *organizationServiceImpl) ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]authorization.IdentityAssociation, error) {
	resourceType := authorization.IdentityResourceTypeOrganization

	// first find the identity's memberships
	memberships, err := s.Repositories().Identities().FindIdentityMemberships(ctx, identityID, &resourceType)

	if err != nil {
		return nil, err
	}

	// then find the identity's roles
	roles, err := s.Repositories().IdentityRoleRepository().FindIdentityRolesForIdentity(ctx, identityID, &resourceType)

	if err != nil {
		return nil, err
	}

	return authorization.MergeAssociations(memberships, roles), nil
}
