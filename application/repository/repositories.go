package repository

import (
	"github.com/fabric8-services/fabric8-auth/auth"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	permission "github.com/fabric8-services/fabric8-auth/authorization/permission/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	token "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
)

//Repositories stands for a particular implementation of the business logic of our application
type Repositories interface {
	Identities() account.IdentityRepository
	Users() account.UserRepository
	OauthStates() auth.OauthStateReferenceRepository
	ExternalTokens() token.ExternalTokenRepository
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
