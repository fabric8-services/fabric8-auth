package test

import (
	"context"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/application"
	organizationservice "github.com/fabric8-services/fabric8-auth/authorization/organization/service"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"

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

func CreateTestIdentityRoleForIdentity(ctx context.Context, db *gorm.DB, identity account.Identity, resourceRef resource.Resource, roleRef role.Role) (*role.IdentityRole, error) {
	identityRoleRef := role.IdentityRole{
		IdentityRoleID: uuid.NewV4(),
		Identity:       identity,
		IdentityID:     identity.ID,
		Resource:       resourceRef,
		ResourceID:     resourceRef.ResourceID,
		Role:           roleRef,
		RoleID:         roleRef.RoleID,
	}

	identityRoleRepository := role.NewIdentityRoleRepository(db)
	err := identityRoleRepository.Create(ctx, &identityRoleRef)
	if err != nil {
		return nil, err
	}
	return &identityRoleRef, err
}

func CreateTestOrganization(ctx context.Context, db *gorm.DB, app application.Application, creatorIdentityID uuid.UUID, name string) (account.Identity, error) {

	orgService := organizationservice.NewOrganizationService(app, app)

	var organization *account.Identity

	orgID, err := orgService.CreateOrganization(ctx, creatorIdentityID, name)
	if err != nil {
		return *organization, err
	}

	repo := account.NewIdentityRepository(db)

	organization, err = repo.Load(ctx, *orgID)
	if err != nil {
		return *organization, err
	}

	return *organization, nil
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
	resourceRepository := resource.NewResourceRepository(db)
	err := resourceRepository.Create(ctx, &resourceRef)
	return &resourceRef, err
}

func CreateTestResourceType(ctx context.Context, db *gorm.DB, name string) (*resourcetype.ResourceType, error) {
	resourcetypeRepoRef := resourcetype.NewResourceTypeRepository(db)
	resourceTypeRef := resourcetype.ResourceType{
		Name: name,
	}
	err := resourcetypeRepoRef.Create(ctx, &resourceTypeRef)
	if err != nil {
		return nil, err
	}
	return &resourceTypeRef, err
}

func CreateTestRoleMapping(ctx context.Context, db *gorm.DB, app application.Application, resourceID string, fromRoleID uuid.UUID, toRoleID uuid.UUID) error {
	roleMappingRepoRef := role.NewRoleMappingRepository(db)

	err := roleMappingRepoRef.Create(ctx, &role.RoleMapping{
		ResourceID: resourceID,
		FromRoleID: fromRoleID,
		ToRoleID:   toRoleID,
	})
	return err
}

func CreateTestScopeWithDefaultType(ctx context.Context, db *gorm.DB, name string) (*resourcetype.ResourceTypeScope, error) {
	resourceTypeRepo := resourcetype.NewResourceTypeRepository(db)
	resourceType, err := resourceTypeRepo.Lookup(ctx, "openshift.io/resource/area")

	if err != nil {
		return nil, err
	}

	rts := resourcetype.ResourceTypeScope{
		ResourceTypeScopeID: uuid.NewV4(),
		ResourceTypeID:      resourceType.ResourceTypeID,
		Name:                uuid.NewV4().String(),
	}

	resourceTypeScopeRepo := resourcetype.NewResourceTypeScopeRepository(db)
	err = resourceTypeScopeRepo.Create(ctx, &rts)
	if err != nil {
		return nil, err
	}
	return &rts, nil
}

func CreateTestScope(ctx context.Context, db *gorm.DB, resourceType resourcetype.ResourceType, name string) (*resourcetype.ResourceTypeScope, error) {

	rts := resourcetype.ResourceTypeScope{
		ResourceTypeScopeID: uuid.NewV4(),
		ResourceTypeID:      resourceType.ResourceTypeID,
		Name:                name,
	}

	resourceTypeScopeRepo := resourcetype.NewResourceTypeScopeRepository(db)
	err := resourceTypeScopeRepo.Create(ctx, &rts)
	if err != nil {
		return nil, err
	}
	return &rts, nil
}

func CreateTestRoleScope(ctx context.Context, db *gorm.DB, s resourcetype.ResourceTypeScope, r role.Role) (*role.RoleScope, error) {
	roleScopeRepo := role.NewRoleScopeRepository(db)

	rs := role.RoleScope{
		//ResourceTypeScope:   s,
		ResourceTypeScopeID: s.ResourceTypeScopeID,
		//Role:                r,
		RoleID: r.RoleID,
	}

	err := roleScopeRepo.Create(ctx, &rs)
	if err != nil {
		return nil, err
	}

	// adding the references help in comparing later on.
	rs.ResourceTypeScope = s
	rs.Role = r
	return &rs, nil
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

func CreateTestRoleWithSpecifiedType(ctx context.Context, db *gorm.DB, name string, resourceTypeName string) (*role.Role, error) {
	resourceTypeRepo := resourcetype.NewResourceTypeRepository(db)
	resourceType, err := resourceTypeRepo.Lookup(ctx, resourceTypeName)

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

func CreateRandomIdentityRole(ctx context.Context, db *gorm.DB) (*role.IdentityRole, error) {
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
