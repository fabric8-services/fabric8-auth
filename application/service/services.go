package service

import (
	"context"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	permission "github.com/fabric8-services/fabric8-auth/authorization/permission/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/notification"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/fabric8-services/fabric8-auth/wit"
	"github.com/satori/go.uuid"
)

/*
Steps for adding a new Service:
1. Add a new service interface to application/service/services.go
2. Create an implementation of the service interface
3. Add a new method to service.Services interface in application/service/services.go for accessing the service interface
   defined in step 1
4. Add a new method to application/service/factory/service_factory.go which implements the service access method
   from step #3 and uses the service constructor from step 2
5. Add a new method to gormapplication/application.go which implements the service access method from step #3
   and use the factory method from the step #4
*/

type InvitationService interface {
	// Issue creates a new invitation for a user.
	Issue(ctx context.Context, issuingUserID uuid.UUID, inviteTo string, invitations []invitation.Invitation) error
	// Rescind revokes an invitation for a user.
	Rescind(ctx context.Context, rescindingUserID, invitationID uuid.UUID) error
	// Accept processes the invitation acceptance action from the user, converting the invitation into real memberships/roles
	Accept(ctx context.Context, token uuid.UUID) (string, string, error)
}

type OrganizationService interface {
	CreateOrganization(ctx context.Context, creatorIdentityID uuid.UUID, organizationName string) (*uuid.UUID, error)
	ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]authorization.IdentityAssociation, error)
}

type PermissionService interface {
	HasScope(ctx context.Context, identityID uuid.UUID, resourceID string, scopeName string) (bool, error)
	RequireScope(ctx context.Context, identityID uuid.UUID, resourceID string, scopeName string) error
}

type PrivilegeCacheService interface {
	CachedPrivileges(ctx context.Context, identityID uuid.UUID, resourceID string) (*permission.PrivilegeCache, error)
}

type ResourceService interface {
	Delete(ctx context.Context, resourceID string) error
	Read(ctx context.Context, resourceID string) (*app.Resource, error)
	CheckExists(ctx context.Context, resourceID string) error
	Register(ctx context.Context, resourceTypeName string, resourceID, parentResourceID *string) (*resource.Resource, error)
	FindWithRoleByResourceTypeAndIdentity(ctx context.Context, resourceType string, identityID uuid.UUID) ([]string, error)
}

type RoleManagementService interface {
	ListByResource(ctx context.Context, currentIdentity uuid.UUID, resourceID string) ([]rolerepo.IdentityRole, error)
	ListAvailableRolesByResourceType(ctx context.Context, resourceType string) ([]role.RoleDescriptor, error)
	ListByResourceAndRoleName(ctx context.Context, currentIdentity uuid.UUID, resourceID string, roleName string) ([]rolerepo.IdentityRole, error)
	Assign(ctx context.Context, assignedBy uuid.UUID, roleAssignments map[string][]uuid.UUID, resourceID string, appendToExistingRoles bool) error
	ForceAssign(ctx context.Context, assignedTo uuid.UUID, roleName string, res resource.Resource) error
	RevokeResourceRoles(ctx context.Context, currentIdentity uuid.UUID, identities []uuid.UUID, resourceID string) error
}

type TeamService interface {
	CreateTeam(ctx context.Context, identityID uuid.UUID, spaceID string, teamName string) (*uuid.UUID, error)
	ListTeamsInSpace(ctx context.Context, identityID uuid.UUID, spaceID string) ([]account.Identity, error)
	ListTeamsForIdentity(ctx context.Context, identityID uuid.UUID) ([]authorization.IdentityAssociation, error)
}

type TokenService interface {
	Audit(ctx context.Context, identity *account.Identity, tokenString string, resourceID string) (*string, error)
}

type SpaceService interface {
	CreateSpace(ctx context.Context, spaceCreatorIdentityID uuid.UUID, spaceID string) error
	DeleteSpace(ctx context.Context, byIdentityID uuid.UUID, spaceID string) error
}

type UserService interface {
	DeprovisionUser(ctx context.Context, username string) (*account.Identity, error)
	UserInfo(ctx context.Context, identityID uuid.UUID) (*account.User, *account.Identity, error)
}

type NotificationService interface {
	SendMessageAsync(ctx context.Context, msg notification.Message, options ...rest.HTTPClientOption) (chan error, error)
	SendMessagesAsync(ctx context.Context, messages []notification.Message, options ...rest.HTTPClientOption) (chan error, error)
}

type WITService interface {
	UpdateUser(ctx context.Context, updatePayload *app.UpdateUsersPayload, identityID string) error
	CreateUser(ctx context.Context, identity *account.Identity, identityID string) error
	GetSpace(ctx context.Context, spaceID string) (space *wit.Space, e error)
}

type ClusterService interface {
	Clusters(ctx context.Context, options ...rest.HTTPClientOption) ([]cluster.Cluster, error)
	ClusterByURL(ctx context.Context, url string, options ...rest.HTTPClientOption) (*cluster.Cluster, error)
}

//Services creates instances of service layer objects
type Services interface {
	InvitationService() InvitationService
	NotificationService() NotificationService
	OrganizationService() OrganizationService
	PermissionService() PermissionService
	PrivilegeCacheService() PrivilegeCacheService
	ResourceService() ResourceService
	RoleManagementService() RoleManagementService
	SpaceService() SpaceService
	TeamService() TeamService
	TokenService() TokenService
	UserService() UserService
	WITService() WITService
	ClusterService() ClusterService
}
