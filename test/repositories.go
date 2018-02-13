package test

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
)

type TestRepositories struct {
	FIdentityRepository     account.IdentityRepository
	FResourceRepository     resource.ResourceRepository
	FResourceTypeRepository resource.ResourceTypeRepository
	FRoleRepository         role.RoleRepository
	FIdentityRoleRepository role.IdentityRoleRepository
}

func (m TestRepositories) Identities() account.IdentityRepository {
	return m.FIdentityRepository
}

func (m TestRepositories) ResourceRepository() resource.ResourceRepository {
	return m.FResourceRepository
}

func (m TestRepositories) ResourceTypeRepository() resource.ResourceTypeRepository {
	return m.FResourceTypeRepository
}

func (m TestRepositories) RoleRepository() role.RoleRepository {
	return m.FRoleRepository
}

func (m TestRepositories) IdentityRoleRepository() role.IdentityRoleRepository {
	return m.FIdentityRoleRepository
}
