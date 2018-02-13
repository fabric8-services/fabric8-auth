package authorization_test

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
)

type TestRepositories struct {
	identityRepository     account.IdentityRepository
	resourceRepository     resource.ResourceRepository
	resourceTypeRepository resource.ResourceTypeRepository
	roleRepository         role.RoleRepository
	identityRoleRepository role.IdentityRoleRepository
}

func (m TestRepositories) Identities() account.IdentityRepository {
	return m.identityRepository
}

func (m TestRepositories) ResourceRepository() resource.ResourceRepository {
	return m.resourceRepository
}

func (m TestRepositories) ResourceTypeRepository() resource.ResourceTypeRepository {
	return m.resourceTypeRepository
}

func (m TestRepositories) RoleRepository() role.RoleRepository {
	return m.roleRepository
}

func (m TestRepositories) IdentityRoleRepository() role.IdentityRoleRepository {
	return m.identityRoleRepository
}
