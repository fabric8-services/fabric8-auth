package repository

import (
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	provider "github.com/fabric8-services/fabric8-auth/authentication/provider/repository"
	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	permission "github.com/fabric8-services/fabric8-auth/authorization/permission/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	token "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	worker "github.com/fabric8-services/fabric8-auth/worker/repository"
)

//Repositories is used to access the low-level domain model of our application
type Repositories interface {
	Identities() account.IdentityRepository
	Users() account.UserRepository
	OauthStates() provider.OauthStateReferenceRepository
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
	WorkerLockRepository() worker.LockRepository
}
