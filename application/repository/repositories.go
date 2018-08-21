package repository

import (
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/auth"
	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	permission "github.com/fabric8-services/fabric8-auth/authorization/permission/repository"
	token "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/token/provider"
)

//Repositories stands for a particular implementation of the business logic of our application
type Repositories interface {
	Identities() account.IdentityRepository
	Users() account.UserRepository
	OauthStates() auth.OauthStateReferenceRepository
	ExternalTokens() provider.ExternalTokenRepository
	VerificationCodes() account.VerificationCodeRepository
	InvitationRepository() invitation.InvitationRepository
	ResourceRepository() resource.ResourceRepository
	ResourceTypeRepository() resourcetype.ResourceTypeRepository
	ResourceTypeScopeRepository() resourcetype.ResourceTypeScopeRepository
	IdentityRoleRepository() role.IdentityRoleRepository
	RoleRepository() role.RoleRepository
	DefaultRoleMappingRepository() role.DefaultRoleMappingRepository
	RoleMappingRepository() role.RoleMappingRepository
	TokenRepository() token.TokenRepository
	PrivilegeCacheRepository() permission.PrivilegeCacheRepository
}
