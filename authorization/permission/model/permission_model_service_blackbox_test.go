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
	testResourceTypeArea            = "test.permission.resource.type/area"
	testResourceTypeWorkItem        = "test.permission.resource.type/workitem"
	testResourceTypeWorkItemComment = "test.permission.resource.type/workitemcomment"
	testAreaScopeName               = "test_area_scope"
	testWorkItemScopeName           = "test_workitem_scope"
	testWorkItemCommentScopeName    = "test_workitemcomment_scope"
)

type permissionModelServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	identityRepo            account.IdentityRepository
	identityRoleRepo        identityrole.IdentityRoleRepository
	resourceRepo            resource.ResourceRepository
	resourceTypeRepo        resourcetype.ResourceTypeRepository
	resourceTypeScopeRepo   resourcetypescope.ResourceTypeScopeRepository
	roleRepo                roleRepo.RoleRepository
	roleMappingRepo         roleRepo.RoleMappingRepository
	orgModelService         organizationModel.OrganizationModelService
	permissionService       permissionModelService.PermissionModelService
	testAreaRole            roleRepo.Role
	testWorkItemRole        roleRepo.Role
	testWorkItemCommentRole roleRepo.Role
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
	s.roleMappingRepo = roleRepo.NewRoleMappingRepository(s.DB)
	s.orgModelService = organizationModel.NewOrganizationModelService(s.DB, s.Application)
	s.permissionService = permissionModelService.NewPermissionModelService(s.DB, s.Application)

	// Create a test "area" resource type
	role, err := s.setupResourceType(testResourceTypeArea, testAreaScopeName, "test-permission-area-role")
	require.NoError(s.T(), err, "Could not setup test area resource type")
	s.testAreaRole = *role

	// Create a test "workitem" resource type
	role, err = s.setupResourceType(testResourceTypeWorkItem, testWorkItemScopeName, "test-permission-workitem-role")
	require.NoError(s.T(), err, "Could not setup test workitem resource type")
	s.testWorkItemRole = *role

	// Create a test "workitemcomment" resource type
	role, err = s.setupResourceType(testResourceTypeWorkItemComment, testWorkItemCommentScopeName, "test-permission-workitemcomment-role")
	require.NoError(s.T(), err, "Could not setup test workitemcomment resource type")
	s.testWorkItemCommentRole = *role
}

func (s *permissionModelServiceBlackBoxTest) setupResourceType(resourceTypeName string, scopeName, roleName string) (*roleRepo.Role, error) {
	// Create a test resource type
	err := s.resourceTypeRepo.Create(s.Ctx, &resourcetype.ResourceType{
		Name: resourceTypeName,
	})
	if err != nil {
		return nil, err
	}

	// Lookup our test resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, resourceTypeName)
	if err != nil {
		return nil, err
	}

	// Create a test scope
	err = s.resourceTypeScopeRepo.Create(s.Ctx, &resourcetypescope.ResourceTypeScope{
		Name:           scopeName,
		ResourceTypeID: resourceType.ResourceTypeID,
	})
	if err != nil {
		return nil, err
	}

	// Lookup the scope we created
	scopes, err := s.resourceTypeScopeRepo.LookupForType(s.Ctx, resourceType.ResourceTypeID)
	if err != nil {
		return nil, err
	}
	require.Equal(s.T(), 1, len(scopes))
	testScope := scopes[0]

	// Create a test role for the test resource type
	role, err := test.CreateTestRole(s.Ctx, s.DB, *resourceType, roleName)
	if err != nil {
		return nil, err
	}

	// Add the scope to the test role
	err = s.roleRepo.AddScope(s.Ctx, role, &testScope)
	if err != nil {
		return nil, err
	}

	return role, nil
}

func (s *permissionModelServiceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
}

func (s *permissionModelServiceBlackBoxTest) TeardownSuite() {
	s.DBTestSuite.TearDownSuite()
	// Delete the test scope we created
	s.DB.Unscoped().Exec("DELETE FROM resource_type_scope WHERE name = ?", testAreaScopeName)
	s.DB.Unscoped().Exec("DELETE FROM resource_type_scope WHERE name = ?", testWorkItemScopeName)
}

func (s *permissionModelServiceBlackBoxTest) TestPermissionForUserAssignedDirectRoleForResource() {
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create test identity")

	resource, err := s.createTestResourceAndAssignDefaultRole(identity)
	require.NoError(s.T(), err)

	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for resource")
}

func (s *permissionModelServiceBlackBoxTest) TestPermissionForUserAssignedDirectRoleForParentResource() {
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create test identity")

	otherIdentity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create other test identity")

	resource, err := s.createTestResourceAndAssignDefaultRole(identity)
	require.NoError(s.T(), err)

	otherResource, err := s.createTestResourceWithNoPermissions(identity)
	require.NoError(s.T(), err)

	childResource, err := s.createTestChildResource(*resource, testResourceTypeArea)
	require.NoError(s.T(), err)

	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")

	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for parent resource")

	result, err = s.permissionService.HasScope(s.Ctx, otherIdentity.ID, childResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "Other user should not have assigned scope for child resource")

	result, err = s.permissionService.HasScope(s.Ctx, otherIdentity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "Other user should not have assigned scope for parent resource")

	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, otherResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for other resource")
}

func (s *permissionModelServiceBlackBoxTest) TestPermissionForOrganizationMemberAssignedIndirectRoleForParentResource() {
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create test identity")

	org, err := s.createTestOrganization(s.DB, s.Application, identity.ID, "test-permission-org")
	require.NoError(s.T(), err, "Could not create test organization")

	resource, err := s.createTestResourceAndAssignDefaultRole(org)
	require.NoError(s.T(), err)

	childResource, err := s.createTestChildResource(*resource, testResourceTypeArea)
	require.NoError(s.T(), err)

	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	err = s.addMember(s.DB, s.Application, org.ID, identity.ID)
	require.NoError(s.T(), err, "Error adding member to organization")

	otherIdentity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create other test identity")

	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")

	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for parent resource")

	result, err = s.permissionService.HasScope(s.Ctx, otherIdentity.ID, childResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "Other user should not have assigned scope for child resource")

	result, err = s.permissionService.HasScope(s.Ctx, otherIdentity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "Other user should not have assigned scope for parent resource")

	// TODO remove this once membership repo is implemented
	s.removeMember(s.DB, s.Application, org.ID, identity.ID)
}

func (s *permissionModelServiceBlackBoxTest) TestPermissionForOrganizationMemberAssignedIndirectRoleForResource() {
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create test identity")

	otherIdentity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create other test identity")

	org, err := s.createTestOrganization(s.DB, s.Application, identity.ID, "test-permission-org")
	require.NoError(s.T(), err, "Could not create test organization")

	err = s.addMember(s.DB, s.Application, org.ID, identity.ID)
	require.NoError(s.T(), err, "Error adding member to organization")

	resource, err := s.createTestResourceAndAssignDefaultRole(org)
	require.NoError(s.T(), err)

	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for resource")

	result, err = s.permissionService.HasScope(s.Ctx, otherIdentity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "Other user should not have assigned scope for resource")

	// TODO remove this once membership repo is implemented
	err = s.removeMember(s.DB, s.Application, org.ID, identity.ID)
}

func (s *permissionModelServiceBlackBoxTest) TestPermissionForUserAssignedMappedRoleForResource() {
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create test identity")

	parentResource, err := s.createTestResource(testResourceTypeArea)
	require.NoError(s.T(), err, "Error creating parent resource")

	err = s.assignRoleForResource(*parentResource, identity, s.testAreaRole)
	require.NoError(s.T(), err, "Error assigning role for parent resource")

	childResource, err := s.createTestChildResource(*parentResource, testResourceTypeWorkItem)
	require.NoError(s.T(), err, "Error creating child resource")

	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, parentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for parent resource")

	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	err = s.createRoleMapping(s.DB, s.Application, parentResource.ResourceID, s.testAreaRole.RoleID, s.testWorkItemRole.RoleID)
	require.NoError(s.T(), err, "Could not create role mapping")

	// After creating the role mapping the user should now have the scope
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")
}

func (s *permissionModelServiceBlackBoxTest) TestPermissionForOrgMemberAssignedMappedRoleForResource() {
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create test identity")

	org, err := s.createTestOrganization(s.DB, s.Application, identity.ID, "test-permission-org")
	require.NoError(s.T(), err, "Could not create test organization")

	parentResource, err := s.createTestResource(testResourceTypeArea)
	require.NoError(s.T(), err, "Error creating parent resource")

	err = s.assignRoleForResource(*parentResource, org, s.testAreaRole)
	require.NoError(s.T(), err, "Error assigning role for parent resource")

	childResource, err := s.createTestChildResource(*parentResource, testResourceTypeWorkItem)
	require.NoError(s.T(), err, "Error creating child resource")

	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, parentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for parent resource")

	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Add the user to the organization
	err = s.addMember(s.DB, s.Application, org.ID, identity.ID)
	require.NoError(s.T(), err, "Error adding member to organization")

	// They should now have the permission for the parent resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, parentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for parent resource")

	// But still no permission for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Now we map the parent's role to the child
	err = s.createRoleMapping(s.DB, s.Application, parentResource.ResourceID, s.testAreaRole.RoleID, s.testWorkItemRole.RoleID)
	require.NoError(s.T(), err, "Could not create role mapping")

	// After creating the role mapping the user should now have the scope
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")

	// TODO remove this cleanup code once membership repo is implemented
	s.removeMember(s.DB, s.Application, org.ID, identity.ID)
}

func (s *permissionModelServiceBlackBoxTest) TestPermissionForOrgMemberAssignedMappedRoleForGrandparentResource() {
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create test identity")

	org, err := s.createTestOrganization(s.DB, s.Application, identity.ID, "test-permission-org")
	require.NoError(s.T(), err, "Could not create test organization")

	grandparentResource, err := s.createTestResource(testResourceTypeArea)
	require.NoError(s.T(), err, "Error creating grandparent resource")

	parentResource, err := s.createTestChildResource(*grandparentResource, testResourceTypeArea)
	require.NoError(s.T(), err, "Error creating parent resource")

	err = s.assignRoleForResource(*grandparentResource, org, s.testAreaRole)
	require.NoError(s.T(), err, "Error assigning role for grandparent resource")

	childResource, err := s.createTestChildResource(*parentResource, testResourceTypeWorkItem)
	require.NoError(s.T(), err, "Error creating child resource")

	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, grandparentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for grandparent resource")

	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Add the user to the organization
	err = s.addMember(s.DB, s.Application, org.ID, identity.ID)
	require.NoError(s.T(), err, "Error adding member to organization")

	// They should now have the permission for the grandparent resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, grandparentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for grandparent resource")

	// ... and the parent resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, parentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for parent resource")

	// But still no permission for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Now we map the grandparent's role to the child
	err = s.createRoleMapping(s.DB, s.Application, grandparentResource.ResourceID, s.testAreaRole.RoleID, s.testWorkItemRole.RoleID)
	require.NoError(s.T(), err, "Could not create role mapping")

	// After creating the role mapping the user should now have the scope
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")

	// TODO remove this cleanup code once membership repo is implemented
	s.removeMember(s.DB, s.Application, org.ID, identity.ID)
}

func (s *permissionModelServiceBlackBoxTest) TestPermissionForOrgMemberAssignedDoubleMappedRoleForGrandparentResource() {
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user", "")
	require.NoError(s.T(), err, "Could not create test identity")

	org, err := s.createTestOrganization(s.DB, s.Application, identity.ID, "test-permission-org")
	require.NoError(s.T(), err, "Could not create test organization")

	grandparentResource, err := s.createTestResource(testResourceTypeArea)
	require.NoError(s.T(), err, "Error creating grandparent resource")

	parentResource, err := s.createTestChildResource(*grandparentResource, testResourceTypeWorkItem)
	require.NoError(s.T(), err, "Error creating parent resource")

	err = s.assignRoleForResource(*grandparentResource, org, s.testAreaRole)
	require.NoError(s.T(), err, "Error assigning role for grandparent resource")

	childResource, err := s.createTestChildResource(*parentResource, testResourceTypeWorkItemComment)
	require.NoError(s.T(), err, "Error creating child resource")

	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, grandparentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for grandparent resource")

	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Add the user to the organization
	err = s.addMember(s.DB, s.Application, org.ID, identity.ID)
	require.NoError(s.T(), err, "Error adding member to organization")

	// They should now have the permission for the grandparent resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, grandparentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for grandparent resource")

	// But not the parent resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, parentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for parent resource")

	// And still no permission for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Now we map the grandparent's role to the parent
	err = s.createRoleMapping(s.DB, s.Application, grandparentResource.ResourceID, s.testAreaRole.RoleID, s.testWorkItemRole.RoleID)
	require.NoError(s.T(), err, "Could not create role mapping")

	// After creating the role mapping the user should now have the scope for the parent resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, parentResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for parent resource")

	// But they should have no permissions for the child resource yet
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemCommentScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Now the tricky bit... we map the parent's role to the child
	err = s.createRoleMapping(s.DB, s.Application, parentResource.ResourceID, s.testWorkItemRole.RoleID, s.testWorkItemCommentRole.RoleID)
	require.NoError(s.T(), err, "Could not create role mapping")

	// Now they should have permissions for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemCommentScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")

	// TODO remove this cleanup code once membership repo is implemented
	s.removeMember(s.DB, s.Application, org.ID, identity.ID)
}

func (s *permissionModelServiceBlackBoxTest) createTestResource(resourceTypeName string) (*resource.Resource, error) {
	// Lookup the specified resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, resourceTypeName)
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

	return createdResource, nil
}

func (s *permissionModelServiceBlackBoxTest) assignRoleForResource(resource resource.Resource, identity account.Identity, role roleRepo.Role) error {
	err := s.identityRoleRepo.Create(s.Ctx, &identityrole.IdentityRole{
		IdentityID: identity.ID,
		ResourceID: resource.ResourceID,
		RoleID:     role.RoleID,
	})
	require.NoError(s.T(), err, "Could not assign role to identity")

	if err != nil {
		return err
	}

	return nil
}

func (s *permissionModelServiceBlackBoxTest) createTestResourceAndAssignDefaultRole(identity account.Identity) (*resource.Resource, error) {
	resource, err := s.createTestResource(testResourceTypeArea)
	require.NoError(s.T(), err, "Could not create resource")

	err = s.assignRoleForResource(*resource, identity, s.testAreaRole)
	require.NoError(s.T(), err, "Could not assign role to resource")

	return resource, nil
}

func (s *permissionModelServiceBlackBoxTest) createTestResourceWithNoPermissions(identity account.Identity) (*resource.Resource, error) {
	// Lookup our default resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, testResourceTypeArea)
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

	return createdResource, nil
}

func (s *permissionModelServiceBlackBoxTest) createTestChildResource(parentResource resource.Resource, resourceTypeName string) (*resource.Resource, error) {
	// Lookup the resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, resourceTypeName)
	require.NoError(s.T(), err, "Could not lookup resource type")

	resource := &resource.Resource{
		ResourceID:       uuid.NewV4().String(),
		ParentResourceID: &parentResource.ResourceID,
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

func (s *permissionModelServiceBlackBoxTest) addMember(db *gorm.DB, appDB application.DB,
	memberOf uuid.UUID, memberId uuid.UUID) error {

	// TODO replace this with the repository method once membership repo is implemented
	db.Unscoped().Exec("INSERT INTO membership (member_of, member_id) VALUES (?, ?)", memberOf, memberId)

	return nil
}

// TODO remove this when the membership repository is implemented
func (s *permissionModelServiceBlackBoxTest) removeMember(db *gorm.DB, appDB application.DB,
	memberOf uuid.UUID, memberId uuid.UUID) error {

	db.Unscoped().Exec("DELETE FROM membership WHERE member_of = ? and member_id = ?", memberOf, memberId)
	return nil
}

func (s *permissionModelServiceBlackBoxTest) createRoleMapping(db *gorm.DB, appDB application.DB,
	resourceID string, fromRoleID uuid.UUID, toRoleID uuid.UUID) error {
	err := s.roleMappingRepo.Create(s.Ctx, &roleRepo.RoleMapping{
		ResourceID: resourceID,
		FromRoleID: fromRoleID,
		ToRoleID:   toRoleID,
	})
	return err
}
