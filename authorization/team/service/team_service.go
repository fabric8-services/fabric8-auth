package service

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/fabric8-services/fabric8-auth/authorization"
	permissionservice "github.com/fabric8-services/fabric8-auth/authorization/permission/service"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/satori/go.uuid"
)

type TeamService interface {
	CreateTeam(ctx context.Context, identityID uuid.UUID, spaceID string, teamName string) (*uuid.UUID, error)
	ListTeamsInSpace(ctx context.Context, identityID uuid.UUID, spaceID string) ([]account.Identity, error)
	ListTeamsForIdentity(ctx context.Context, identityID uuid.UUID) ([]authorization.IdentityAssociation, error)
}

// TeamServiceImpl is the default implementation of TeamService. It is a private struct and should only be instantiated
// via the NewTeamService() function.
type teamServiceImpl struct {
	repo repository.Repositories
	tm   transaction.TransactionManager
}

// NewTeamService creates a new service.
func NewTeamService(repo repository.Repositories, tm transaction.TransactionManager) TeamService {
	return &teamServiceImpl{repo: repo, tm: tm}
}

// Creates a new team.  The specified identityID is the user creating the team, and the spaceID is the identifier for the
// space resource in which the team will be created.  The name parameter specifies the team name.  The team's identity ID is returned.
// IMPORTANT: This is a transactional method, which manages its own transaction/s internally
func (s *teamServiceImpl) CreateTeam(ctx context.Context, identityID uuid.UUID, spaceID string, teamName string) (*uuid.UUID, error) {
	var teamID uuid.UUID

	err := transaction.Transactional(s.tm, func(tr transaction.TransactionalResources) error {
		// Validate the identity for the current user
		_, err := tr.Identities().Load(ctx, identityID)
		if err != nil {
			return errors.NewUnauthorizedError(fmt.Sprintf("unknown Identity ID %s", identityID))
		}

		// Validate the space resource
		space, err := tr.ResourceRepository().Load(ctx, spaceID)
		if err != nil {
			return errors.NewBadParameterErrorFromString("spaceID", spaceID, "invalid space ID specified")
		}

		// Confirm that the resource is a space
		if space.ResourceType.Name != authorization.ResourceTypeSpace {
			return errors.NewBadParameterErrorFromString("spaceID", spaceID, "space ID specified is not a space resource")
		}

		// Create the permission service
		permService := permissionservice.NewPermissionService(tr)

		// Confirm that the user has the 'manage' scope for the space
		scope, err := permService.HasScope(ctx, identityID, spaceID, authorization.ManageTeamsInSpaceScope)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		if !scope {
			return errors.NewForbiddenError(fmt.Sprintf("user requires %s scope for the space to be able to create new teams", authorization.ManageTeamsInSpaceScope))
		}

		// Lookup the team resource type
		resourceType, err := tr.ResourceTypeRepository().Lookup(ctx, authorization.IdentityResourceTypeTeam)
		if err != nil {
			return err
		}

		// Create the team resource
		res := &resource.Resource{
			Name:             teamName,
			ResourceType:     *resourceType,
			ResourceTypeID:   resourceType.ResourceTypeID,
			ParentResourceID: &spaceID,
		}

		err = tr.ResourceRepository().Create(ctx, res)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		// Create the team identity
		teamIdentity := &account.Identity{
			IdentityResourceID: sql.NullString{res.ResourceID, true},
		}

		err = tr.Identities().Create(ctx, teamIdentity)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}

		teamID = teamIdentity.ID

		log.Debug(ctx, map[string]interface{}{
			"team_id": teamID.String(),
		}, "team created")

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &teamID, nil
}

// Returns an array of all team identities within a space
func (s *teamServiceImpl) ListTeamsInSpace(ctx context.Context, identityID uuid.UUID, spaceID string) ([]account.Identity, error) {
	// Confirm that the specified spaceID is valid
	space, err := s.repo.ResourceRepository().Load(ctx, spaceID)
	if err != nil {
		return nil, err
	}

	// Confirm that the resource is actually a space
	if space.ResourceType.Name != authorization.ResourceTypeSpace {
		return nil, errors.NewBadParameterErrorFromString("spaceID", spaceID, "invalid space ID specified - resource is not a space")
	}

	// Lookup the team resource type
	resourceType, err := s.repo.ResourceTypeRepository().Lookup(ctx, authorization.IdentityResourceTypeTeam)
	if err != nil {
		return nil, err
	}

	// Find team identities that have the space as their parent
	identities, err := s.repo.Identities().FindIdentitiesByResourceTypeWithParentResource(ctx, resourceType.ResourceTypeID, spaceID)
	if err != nil {
		return nil, err
	}

	return identities, nil
}

// Returns an array of all teams in which the specified identity is a member or is assigned a role
func (s *teamServiceImpl) ListTeamsForIdentity(ctx context.Context, identityID uuid.UUID) ([]authorization.IdentityAssociation, error) {
	resourceType := authorization.IdentityResourceTypeTeam

	// first find the identity's memberships
	memberships, err := s.repo.Identities().FindIdentityMemberships(ctx, identityID, &resourceType)

	if err != nil {
		return nil, err
	}

	// then find the identity's roles
	roles, err := s.repo.IdentityRoleRepository().FindIdentityRolesForIdentity(ctx, identityID, &resourceType)

	if err != nil {
		return nil, err
	}

	return authorization.MergeAssociations(memberships, roles), nil
}
