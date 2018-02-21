package repository

import (
	"github.com/fabric8-services/fabric8-auth/account"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
)

// This lets us avoid an import cycle, which Go doesn't allow
type Repositories interface {
	Identities() account.IdentityRepository
	ResourceRepository() resource.ResourceRepository
	ResourceTypeRepository() resourcetype.ResourceTypeRepository
	RoleRepository() role.RoleRepository
	IdentityRoleRepository() identityrole.IdentityRoleRepository
}
