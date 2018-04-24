package repository

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/auth"
	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	scope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/space"
	"github.com/fabric8-services/fabric8-auth/token/provider"
)

//Repositories stands for a particular implementation of the business logic of our application
type Repositories interface {
	Identities() account.IdentityRepository
	SpaceResources() space.ResourceRepository
	Users() account.UserRepository
	OauthStates() auth.OauthStateReferenceRepository
	ExternalTokens() provider.ExternalTokenRepository
	VerificationCodes() account.VerificationCodeRepository
	InvitationRepository() invitation.InvitationRepository
	ResourceRepository() resource.ResourceRepository
	ResourceTypeRepository() resourcetype.ResourceTypeRepository
	ResourceTypeScopeRepository() scope.ResourceTypeScopeRepository
	IdentityRoleRepository() role.IdentityRoleRepository
	RoleRepository() role.RoleRepository
}
