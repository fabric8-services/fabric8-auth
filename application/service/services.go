package service

import (
	"context"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"

	"github.com/satori/go.uuid"
)

/*
Steps for adding a new Service:
1. Add a new service interface to application/service/service.go
2. Create an implementation of the service interface
3. Add a new method to service.Service interface in application/service/service.go for accessing the service interface
   defined in step 1
4. Add a new method to application/service/factory/service_factory.go which implements the service access method
   from step #3 and uses the service constructor from step 2
5. Add a new method to gormapplication/application.go which implements the service access method from step #3
   and use the factory method from the step #4
*/

type InvitationService interface {
	Issue(ctx context.Context, issuingUserId uuid.UUID, inviteTo string, invitations []invitation.Invitation) error
}

type OrganizationService interface {
	CreateOrganization(ctx context.Context, creatorIdentityID uuid.UUID, organizationName string) (*uuid.UUID, error)
	ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]authorization.IdentityAssociation, error)
}

type PermissionService interface {
	HasScope(ctx context.Context, identityID uuid.UUID, resourceID string, scopeName string) (bool, error)
	RequireScope(ctx context.Context, identityID uuid.UUID, resourceID string, scopeName string) error
}

type ResourceService interface {
	Delete(ctx context.Context, resourceID string) error
	Read(ctx context.Context, resourceID string) (*app.Resource, error)
	Register(ctx context.Context, resourceTypeName string, resourceID, parentResourceID *string) (*resource.Resource, error)
}

type RoleManagementService interface {
	ListByResource(ctx context.Context, resourceID string) ([]rolerepo.IdentityRole, error)
	ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleDescriptor, error)
	ListByResourceAndRoleName(ctx context.Context, resourceID string, roleName string) ([]rolerepo.IdentityRole, error)
	Assign(ctx context.Context, assignedBy uuid.UUID, roleAssignments map[string][]uuid.UUID, resourceID string, appendToExistingRoles bool) error
	ForceAssign(ctx context.Context, assignedTo uuid.UUID, roleName string, res resource.Resource) error
	DeleteRoleAssignments(ctx context.Context, byIdentity uuid.UUID, forIdentities []uuid.UUID, resourceID string) error
}

type TeamService interface {
	CreateTeam(ctx context.Context, identityID uuid.UUID, spaceID string, teamName string) (*uuid.UUID, error)
	ListTeamsInSpace(ctx context.Context, identityID uuid.UUID, spaceID string) ([]account.Identity, error)
	ListTeamsForIdentity(ctx context.Context, identityID uuid.UUID) ([]authorization.IdentityAssociation, error)
}

type SpaceService interface {
	CreateSpace(ctx context.Context, spaceCreatorIdentityID uuid.UUID, spaceID string) error
	DeleteSpace(ctx context.Context, byIdentityID uuid.UUID, spaceID string) error
}

//Services creates instances of service layer objects
type Services interface {
	InvitationService() InvitationService
	OrganizationService() OrganizationService
	ResourceService() ResourceService
	PermissionService() PermissionService
	RoleManagementService() RoleManagementService
	TeamService() TeamService
	SpaceService() SpaceService
}
