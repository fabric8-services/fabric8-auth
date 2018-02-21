package test

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/account"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
)

func CreateTestIdentityRole(ctx context.Context, db *gorm.DB, resourceRef resource.Resource, roleRef role.Role) (*identityrole.IdentityRole, error) {

	assignedIdentity := &account.Identity{
		ID:           uuid.NewV4(),
		Username:     uuid.NewV4().String(),
		ProviderType: account.KeycloakIDP,
	}
	identityRepository := account.NewIdentityRepository(db)

	err := identityRepository.Create(ctx, assignedIdentity)
	if err != nil {
		return nil, err
	}

	identityRoleRef := identityrole.IdentityRole{
		IdentityRoleID: uuid.NewV4(),
		Identity:       *assignedIdentity,
		IdentityID:     assignedIdentity.ID,
		Resource:       resourceRef,
		ResourceID:     resourceRef.ResourceID,
		Role:           roleRef,
		RoleID:         roleRef.RoleID,
	}

	identityRolesRepository := identityrole.NewIdentityRoleRepository(db)
	err = identityRolesRepository.Create(ctx, &identityRoleRef)
	if err != nil {
		return nil, err
	}
	return &identityRoleRef, err
}

func CreateTestRole(ctx context.Context, db *gorm.DB, resourceType resourcetype.ResourceType, name string) (*role.Role, error) {
	roleRef := role.Role{
		ResourceType:   resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
		Name:           name,
	}
	roleRepository := role.NewRoleRepository(db)
	err := roleRepository.Create(ctx, &roleRef)
	return &roleRef, err
}

func CreateTestResource(ctx context.Context, db *gorm.DB, resourceType resourcetype.ResourceType, name string, parentResourceID *string) (*resource.Resource, error) {
	resourceRef := resource.Resource{
		ResourceType:     resourceType,
		ResourceTypeID:   resourceType.ResourceTypeID,
		Name:             name,
		ResourceID:       uuid.NewV4().String(),
		ParentResourceID: parentResourceID,
	}
	roleRepository := resource.NewResourceRepository(db)
	err := roleRepository.Create(ctx, &resourceRef)
	return &resourceRef, err
}

func CreateTestResourceWithDefaultType(ctx context.Context, db *gorm.DB, name string) (*resource.Resource, error) {

	resourceTypeRepo := resourcetype.NewResourceTypeRepository(db)
	resourceType, err := resourceTypeRepo.Lookup(ctx, "openshift.io/resource/area")

	if err != nil {
		return nil, err
	}
	resourceRef := resource.Resource{
		ResourceType:   *resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
		Name:           name,
		ResourceID:     uuid.NewV4().String(),
	}
	roleRepository := resource.NewResourceRepository(db)
	err = roleRepository.Create(ctx, &resourceRef)
	return &resourceRef, err
}

func CreateTestRoleWithDefaultType(ctx context.Context, db *gorm.DB, name string) (*role.Role, error) {
	resourceTypeRepo := resourcetype.NewResourceTypeRepository(db)
	resourceType, err := resourceTypeRepo.Lookup(ctx, "openshift.io/resource/area")

	if err != nil {
		return nil, err
	}
	roleRef := role.Role{
		ResourceType:   *resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
		Name:           name,
	}
	roleRepository := role.NewRoleRepository(db)
	err = roleRepository.Create(ctx, &roleRef)
	return &roleRef, err
}

func CreateRandomIdentityRole(ctx context.Context, db *gorm.DB) (*identityrole.IdentityRole, error) {
	resourceTypeRepo := resourcetype.NewResourceTypeRepository(db)
	resourceType, err := resourceTypeRepo.Lookup(ctx, "openshift.io/resource/area")

	if err != nil {
		return nil, err
	}

	testResource, err := CreateTestResource(ctx, db, *resourceType, uuid.NewV4().String(), nil)
	if err != nil {
		return nil, err
	}

	testRole, err := CreateTestRole(ctx, db, *resourceType, uuid.NewV4().String())
	if err != nil {
		return nil, err
	}

	testIdentityRole, err := CreateTestIdentityRole(ctx, db, *testResource, *testRole)
	if err != nil {
		return nil, err
	}

	return testIdentityRole, nil
}
