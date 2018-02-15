package repositories

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
)

// This lets us avoid an import cycle, which Go doesn't allow
type Repositories interface {
	Identities() account.IdentityRepository
	ResourceRepository() resource.ResourceRepository
	ResourceTypeRepository() resource.ResourceTypeRepository
	RoleRepository() role.RoleRepository
	IdentityRoleRepository() role.IdentityRoleRepository
}
