package test

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/authorization/role"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
)

func CreateTestIdentityRole(ctx context.Context, db *gorm.DB, resourceRef resource.Resource, roleRef role.Role) (*role.IdentityRole, error) {

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

	identityRoleRef := role.IdentityRole{
		IdentityRoleID: uuid.NewV4(),
		Identity:       *assignedIdentity,
		IdentityID:     assignedIdentity.ID,
		Resource:       resourceRef,
		ResourceID:     resourceRef.ResourceID,
		Role:           roleRef,
		RoleID:         roleRef.RoleID,
	}

	identityRolesRepository := role.NewIdentityRoleRepository(db)
	err = identityRolesRepository.Create(ctx, &identityRoleRef)
	if err != nil {
		return nil, err
	}
	return &identityRoleRef, err
}

func CreateTestRole(ctx context.Context, db *gorm.DB, resourceType resource.ResourceType, name string) (*role.Role, error) {
	roleRef := role.Role{
		ResourceType:   resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
		Name:           name,
	}
	roleRepository := role.NewRoleRepository(db)
	err := roleRepository.Create(ctx, &roleRef)
	return &roleRef, err
}

func CreateTestResource(ctx context.Context, db *gorm.DB, resourceType resource.ResourceType, name string) (*resource.Resource, error) {
	resourceRef := resource.Resource{
		ResourceType:   resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
		Name:           name,
		ResourceID:     uuid.NewV4().String(),
	}
	roleRepository := resource.NewResourceRepository(db)
	err := roleRepository.Create(ctx, &resourceRef)
	return &resourceRef, err
}

func CreateInheritedTestResource(ctx context.Context, db *gorm.DB, resourceType resource.ResourceType, name string, parentResource resource.Resource) (*resource.Resource, error) {
	resourceRef := resource.Resource{
		ResourceType:     resourceType,
		ResourceTypeID:   resourceType.ResourceTypeID,
		Name:             name,
		ResourceID:       uuid.NewV4().String(),
		ParentResourceID: &parentResource.ResourceID,
	}
	roleRepository := resource.NewResourceRepository(db)
	err := roleRepository.Create(ctx, &resourceRef)
	return &resourceRef, err
}
