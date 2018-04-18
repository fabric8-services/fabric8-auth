package repository

import (
	"github.com/fabric8-services/fabric8-auth/account"
	invitation "github.com/fabric8-services/fabric8-auth/authorization/invitation/repository"
	permissionservice "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
)

// This lets us avoid an import cycle, which Go doesn't allow
type Repositories interface {
	Identities() account.IdentityRepository
	InvitationRepository() invitation.InvitationRepository
	ResourceRepository() resource.ResourceRepository
	ResourceTypeRepository() resourcetype.ResourceTypeRepository
	RoleRepository() role.RoleRepository
	IdentityRoleRepository() role.IdentityRoleRepository
	Users() account.UserRepository
	PermissionModelService() permissionservice.PermissionService
}
