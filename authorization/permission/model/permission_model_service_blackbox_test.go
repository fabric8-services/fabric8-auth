package model_test

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/application"
	organizationModel "github.com/fabric8-services/fabric8-auth/authorization/organization/model"
	organizationService "github.com/fabric8-services/fabric8-auth/authorization/organization/service"
	permissionModelService "github.com/fabric8-services/fabric8-auth/authorization/permission/model"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	"testing"

	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	resourcetypescope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
	roleRepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"

	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	testScopeName = "test_permission_scope"
)

type permissionModelServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	identityRepo          account.IdentityRepository
	identityRoleRepo      identityrole.IdentityRoleRepository
	resourceRepo          resource.ResourceRepository
	resourceTypeRepo      resourcetype.ResourceTypeRepository
	resourceTypeScopeRepo resourcetypescope.ResourceTypeScopeRepository
	roleRepo              roleRepo.RoleRepository
	orgModelService       organizationModel.OrganizationModelService
	permissionService     permissionModelService.PermissionModelService
	testRole              roleRepo.Role
}

func TestRunPermissionModelServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &permissionModelServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *permissionModelServiceBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()

	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.identityRoleRepo = identityrole.NewIdentityRoleRepository(s.DB)
	s.resourceRepo = resource.NewResourceRepository(s.DB)
	s.resourceTypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
	s.resourceTypeScopeRepo = resourcetypescope.NewResourceTypeScopeRepository(s.DB)
	s.roleRepo = roleRepo.NewRoleRepository(s.DB)
	s.orgModelService = organizationModel.NewOrganizationModelService(s.DB, s.Application)
	s.permissionService = permissionModelService.NewPermissionModelService(s.DB, s.Application)

	// Lookup our default resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, "openshift.io/resource/area")
	require.Nil(s.T(), err, "Could not lookup resource type")

	err = s.resourceTypeScopeRepo.Create(s.Ctx, &resourcetypescope.ResourceTypeScope{
		Name:           testScopeName,
		ResourceTypeID: resourceType.ResourceTypeID,
	})
	require.NoError(s.T(), err, "Could not create test scope")

	// Create a test role
	role, err := test.CreateTestRole(s.Ctx, s.DB, *resourceType, "test-permission-role")
	require.NoError(s.T(), err, "Could not create test role")

	// Lookup the scope we created
	scopes, err := s.resourceTypeScopeRepo.LookupForType(s.Ctx, resourceType.ResourceTypeID)
	require.NoError(s.T(), err, "Error looking up scopes")
	require.Equal(s.T(), 1, len(scopes))

	testScope := scopes[0]

	// Add the scope to the role
	s.roleRepo.AddScope(s.Ctx, role, &testScope)

	s.testRole = *role
}

func (s *permissionModelServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
}

func (s *permissionModelServiceBlackBoxTest) TeardownSuite() {
	// Delete the test scope we created
	s.DB.Unscoped().Exec(`DELETE FROM resource_type_scope WHERE
  name = 'test_permission_scope`)
}

func (s *permissionModelServiceBlackBoxTest) TestPermissionForUserAssignedDirectRoleForResource() {
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create test identity")

	resource, err := s.createTestResourceAndAssignDefaultRole(identity)
	require.NoError(s.T(), err)

	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, resource.ResourceID, testScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for resource")
}

func (s *permissionModelServiceBlackBoxTest) TestPermissionForOrganizationMemberAssignedIndirectRoleForResource() {
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create test identity")

	otherIdentity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create other test identity")

	org, err := s.createTestOrganization(s.DB, s.Application, identity.ID, "test-permission-org")
	require.NoError(s.T(), err, "Could not create test organization")

	resource, err := s.createTestResourceAndAssignDefaultRole(org)
	require.NoError(s.T(), err)

	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, resource.ResourceID, testScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for resource")

	result, err = s.permissionService.HasScope(s.Ctx, otherIdentity.ID, resource.ResourceID, testScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "Other user should not have assigned scope for resource")
}

func (s *permissionModelServiceBlackBoxTest) createTestResourceAndAssignDefaultRole(identity account.Identity) (*resource.Resource, error) {
	// Lookup our default resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, "openshift.io/resource/area")
	require.NoError(s.T(), err, "Could not lookup resource type")

	resource := &resource.Resource{
		ResourceID:       uuid.NewV4().String(),
		ParentResourceID: nil,
		ResourceType:     *resourceType,
		ResourceTypeID:   resourceType.ResourceTypeID,
	}

	err = s.resourceRepo.Create(s.Ctx, resource)
	require.NoError(s.T(), err, "Could not create resource")
	if err != nil {
		return nil, err
	}

	createdResource, err := s.resourceRepo.Load(s.Ctx, resource.ResourceID)
	require.NoError(s.T(), err, "Could not load resource")
	if err != nil {
		return nil, err
	}

	err = s.identityRoleRepo.Create(s.Ctx, &identityrole.IdentityRole{
		IdentityID: identity.ID,
		ResourceID: resource.ResourceID,
		RoleID:     s.testRole.RoleID,
	})
	require.NoError(s.T(), err, "Could not assign role to identity")
	if err != nil {
		return nil, err
	}

	return createdResource, nil
}

func (s *permissionModelServiceBlackBoxTest) createTestOrganization(db *gorm.DB, appDB application.DB,
	creatorIdentityID uuid.UUID, name string) (account.Identity, error) {

	orgModelService := organizationModel.NewOrganizationModelService(db, appDB)
	orgService := organizationService.NewOrganizationService(orgModelService, appDB)

	var organization *account.Identity

	orgID, err := orgService.CreateOrganization(s.Ctx, creatorIdentityID, name)
	if err != nil {
		return *organization, err
	}

	repo := account.NewIdentityRepository(db)

	organization, err = repo.Load(s.Ctx, *orgID)
	if err != nil {
		return *organization, err
	}

	return *organization, nil
}
