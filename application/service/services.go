package service

import (
	"context"
	"net/url"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/app"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"github.com/fabric8-services/fabric8-auth/authentication/subscription"
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/invitation"
	permission "github.com/fabric8-services/fabric8-auth/authorization/permission/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	tokenrepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/notification"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/wit"
	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

const (
	FACTORY_TYPE_CLUSTER_CACHE       = "factory.type.cluster.cache"
	FACTORY_TYPE_LINKING_PROVIDER    = "factory.type.linking.provider"
	FACTORY_TYPE_IDENTITY_PROVIDER   = "factory.type.identity.provider"
	FACTORY_TYPE_SUBSCRIPTION_LOADER = "factory.type.subscription.loader"
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

type AuthenticationProviderService interface {
	AuthorizeCallback(ctx context.Context, state string, code string) (*string, error)
	CreateOrUpdateIdentityAndUser(ctx context.Context, referrerURL *url.URL,
		providerToken *oauth2.Token) (*string, *oauth2.Token, error)
	UpdateIdentityUsingUserInfoEndPoint(ctx context.Context, accessToken string) (*account.Identity, error)
	ExchangeAuthorizationCodeForUserToken(ctx context.Context, code string, clientID string, redirectURL *url.URL) (*string, *app.OauthToken, error)
	ExchangeCodeWithProvider(ctx context.Context, code string, redirectURL string) (*oauth2.Token, error)
	GenerateAuthCodeURL(ctx context.Context, redirect *string, apiClient *string,
		state *string, scopes []string, responseMode *string, referrer string, callbackURL string) (*string, error)
	LoginCallback(ctx context.Context, state string, code string, redirectURL string) (*string, error)
	LoadReferrerAndResponseMode(ctx context.Context, state string) (string, *string, error)
	SaveReferrer(ctx context.Context, state string, referrer string,
		responseMode *string, validReferrerURL string) error
}

type ClusterService interface {
	Clusters(ctx context.Context, options ...rest.HTTPClientOption) ([]cluster.Cluster, error)
	ClusterByURL(ctx context.Context, url string, options ...rest.HTTPClientOption) (*cluster.Cluster, error)
	Status(ctx context.Context, options ...rest.HTTPClientOption) (bool, error)
	UnlinkIdentityFromCluster(ctx context.Context, identityID uuid.UUID, clusterURL string, options ...rest.HTTPClientOption) error
	LinkIdentityToCluster(ctx context.Context, identityID uuid.UUID, clusterURL string, options ...rest.HTTPClientOption) error
	Stop()
}

type InvitationService interface {
	// Issue creates a new invitation for a user.
	Issue(ctx context.Context, issuingUserID uuid.UUID, inviteTo string, invitations []invitation.Invitation) error
	// Rescind revokes an invitation for a user.
	Rescind(ctx context.Context, rescindingUserID, invitationID uuid.UUID) error
	// Accept processes the invitation acceptance action from the user, converting the invitation into real memberships/roles
	Accept(ctx context.Context, token uuid.UUID) (string, string, error)
}

// LinkService provides the ability to link 3rd party oauth accounts, such as Github and Openshift
type LinkService interface {
	ProviderLocation(ctx context.Context, req *goa.RequestData, identityID string, forResource string, redirectURL string) (string, error)
	Callback(ctx context.Context, req *goa.RequestData, state string, code string) (string, error)
}

type LogoutService interface {
	Logout(ctx context.Context, redirectURL string) (string, error)
}

type NotificationService interface {
	SendMessageAsync(ctx context.Context, msg notification.Message, options ...rest.HTTPClientOption) (chan error, error)
	SendMessagesAsync(ctx context.Context, messages []notification.Message, options ...rest.HTTPClientOption) (chan error, error)
}

type OrganizationService interface {
	CreateOrganization(ctx context.Context, creatorIdentityID uuid.UUID, organizationName string) (*uuid.UUID, error)
	ListOrganizations(ctx context.Context, identityID uuid.UUID) ([]authorization.IdentityAssociation, error)
}

type OSOSubscriptionService interface {
	LoadOSOSubscriptionStatus(ctx context.Context, token oauth2.Token) (string, error)
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
	Register(ctx context.Context, resourceTypeName string, resourceID, parentResourceID *string, identity *uuid.UUID) (*resource.Resource, error)
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

type SpaceService interface {
	CreateSpace(ctx context.Context, spaceCreatorIdentityID uuid.UUID, spaceID string) error
	DeleteSpace(ctx context.Context, byIdentityID uuid.UUID, spaceID string) error
}

type TeamService interface {
	CreateTeam(ctx context.Context, identityID uuid.UUID, spaceID string, teamName string) (*uuid.UUID, error)
	ListTeamsInSpace(ctx context.Context, identityID uuid.UUID, spaceID string) ([]account.Identity, error)
	ListTeamsForIdentity(ctx context.Context, identityID uuid.UUID) ([]authorization.IdentityAssociation, error)
}

type TokenService interface {
	Audit(ctx context.Context, identity *account.Identity, tokenString string, resourceID string) (*string, error)
	CleanupExpiredTokens(ctx context.Context) error
	DeleteExternalToken(ctx context.Context, currentIdentity uuid.UUID, authURL string, forResource string) error
	ExchangeRefreshToken(ctx context.Context, refreshToken string, rptToken string) (*manager.TokenSet, error)
	RegisterToken(ctx context.Context, identityID uuid.UUID, tokenString string, tokenType string, privileges []tokenrepo.TokenPrivilege) (*tokenrepo.Token, error)
	RetrieveExternalToken(ctx context.Context, forResource string, req *goa.RequestData, forcePull *bool) (*app.ExternalToken, *string, error)
	SetStatusForAllIdentityTokens(ctx context.Context, identityID uuid.UUID, status int) error
	ValidateToken(ctx context.Context, tkn *jwt.Token) error
}

type UserProfileService interface {
	Get(ctx context.Context, accessToken string, profileURL string) (*provider.OAuthUserProfileResponse, error)
}

type UserService interface {
	NotifyIdentitiesBeforeDeactivation(ctx context.Context) ([]account.Identity, error)
	ListIdentitiesToDeactivate(ctx context.Context) ([]account.Identity, error)
	DeactivateUser(ctx context.Context, username string) (*account.Identity, error)
	BanUser(ctx context.Context, username string) (*account.Identity, error)
	UserInfo(ctx context.Context, identityID uuid.UUID) (*account.User, *account.Identity, error)
	LoadContextIdentityAndUser(ctx context.Context) (*account.Identity, error)
	LoadContextIdentityIfNotBanned(ctx context.Context) (*account.Identity, error)
	ContextIdentityIfExists(ctx context.Context) (uuid.UUID, error)
	IdentityByUsernameAndEmail(ctx context.Context, username, email string) (*account.Identity, error)
	ResetBan(ctx context.Context, user account.User) error
	HardDeleteUser(ctx context.Context, identity account.Identity) error
}

// TenantService represents the Tenant service
type TenantService interface {
	Init(ctx context.Context) error
	Delete(ctx context.Context, identityID uuid.UUID) error
}

type WITService interface {
	UpdateUser(ctx context.Context, updatePayload *app.UpdateUsersPayload, identityID string) error
	CreateUser(ctx context.Context, identity *account.Identity, identityID string) error
	DeleteUser(ctx context.Context, identityID string) error
	GetSpace(ctx context.Context, spaceID string) (space *wit.Space, e error)
}

//Services creates instances of service layer objects
type Services interface {
	AuthenticationProviderService() AuthenticationProviderService
	ClusterService() ClusterService
	InvitationService() InvitationService
	LinkService() LinkService
	LogoutService() LogoutService
	NotificationService() NotificationService
	OrganizationService() OrganizationService
	OSOSubscriptionService() OSOSubscriptionService
	PermissionService() PermissionService
	PrivilegeCacheService() PrivilegeCacheService
	ResourceService() ResourceService
	RoleManagementService() RoleManagementService
	SpaceService() SpaceService
	TeamService() TeamService
	TokenService() TokenService
	UserProfileService() UserProfileService
	UserService() UserService
	TenantService() TenantService
	WITService() WITService
}

//----------------------------------------------------------------------------------------------------------------------
//
// Factories are a special type of service only accessible from other services, that can be replaced during testing,
// in order to produce mock / dummy factories
//
//----------------------------------------------------------------------------------------------------------------------

type ClusterCacheFactory interface {
	NewClusterCache(ctx context.Context, options ...rest.HTTPClientOption) cluster.ClusterCache
}

type IdentityProviderFactory interface {
	NewIdentityProvider(ctx context.Context, config provider.IdentityProviderConfiguration) provider.IdentityProvider
}

type LinkingProviderFactory interface {
	NewLinkingProvider(ctx context.Context, identityID uuid.UUID, authURL string, forResource string) (provider.LinkingProvider, error)
}

type SubscriptionLoaderFactory interface {
	NewSubscriptionLoader(ctx context.Context) subscription.SubscriptionLoader
}

// Factories is the interface responsible for creating instances of factory objects
type Factories interface {
	ClusterCacheFactory() ClusterCacheFactory
	IdentityProviderFactory() IdentityProviderFactory
	LinkingProviderFactory() LinkingProviderFactory
	SubscriptionLoaderFactory() SubscriptionLoaderFactory
}
