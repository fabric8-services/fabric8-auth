package application

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/auth"
	invitationservice "github.com/fabric8-services/fabric8-auth/authorization/invitation/model"
	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	organizationservice "github.com/fabric8-services/fabric8-auth/authorization/organization/model"
	permissionservice "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	scope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/space"
	"github.com/fabric8-services/fabric8-auth/token/provider"
)

//An Application stands for a particular implementation of the business logic of our application
type Application interface {
	Identities() account.IdentityRepository
	SpaceResources() space.ResourceRepository
	Users() account.UserRepository
	OauthStates() auth.OauthStateReferenceRepository
	ExternalTokens() provider.ExternalTokenRepository
	VerificationCodes() account.VerificationCodeRepository
	InvitationRepository() invitation.InvitationRepository
	InvitationModelService() invitationservice.InvitationModelService
	PermissionModelService() permissionservice.PermissionService
	ResourceRepository() resource.ResourceRepository
	ResourceTypeRepository() resourcetype.ResourceTypeRepository
	ResourceTypeScopeRepository() scope.ResourceTypeScopeRepository
	IdentityRoleRepository() role.IdentityRoleRepository
	RoleRepository() role.RoleRepository
	OrganizationModelService() organizationservice.OrganizationModelService
}

// A Transaction abstracts a database transaction. The repositories created for the transaction object make changes inside the the transaction
type Transaction interface {
	Application
	Commit() error
	Rollback() error
}

// A DB stands for a particular database (or a mock/fake thereof). It also includes "Application" for creating transactionless repositories
type DB interface {
	Application
	BeginTransaction() (Transaction, error)
}
