package service_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	permissionmodel "github.com/fabric8-services/fabric8-auth/authorization/permission/service"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	roleRepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"

	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
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

type permissionServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	identityRepo            account.IdentityRepository
	identityRoleRepo        roleRepo.IdentityRoleRepository
	resourceRepo            resource.ResourceRepository
	resourceTypeRepo        resourcetype.ResourceTypeRepository
	resourceTypeScopeRepo   resourcetype.ResourceTypeScopeRepository
	roleRepo                roleRepo.RoleRepository
	roleMappingRepo         roleRepo.RoleMappingRepository
	permissionService       permissionmodel.PermissionService
	testAreaRole            roleRepo.Role
	testWorkItemRole        roleRepo.Role
	testWorkItemCommentRole roleRepo.Role
}

func TestRunPermissionServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &permissionServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *permissionServiceBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()

	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.identityRoleRepo = roleRepo.NewIdentityRoleRepository(s.DB)
	s.resourceRepo = resource.NewResourceRepository(s.DB)
	s.resourceTypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
	s.resourceTypeScopeRepo = resourcetype.NewResourceTypeScopeRepository(s.DB)
	s.roleRepo = roleRepo.NewRoleRepository(s.DB)
	s.roleMappingRepo = roleRepo.NewRoleMappingRepository(s.DB)
	s.permissionService = permissionmodel.NewPermissionService(s.Application)

	// Create a test "area" resource type
	role := s.setupResourceType(testResourceTypeArea, testAreaScopeName, "test-permission-area-role")
	s.testAreaRole = *role

	// Create a test "workitem" resource type
	role = s.setupResourceType(testResourceTypeWorkItem, testWorkItemScopeName, "test-permission-workitem-role")
	s.testWorkItemRole = *role

	// Create a test "workitemcomment" resource type
	role = s.setupResourceType(testResourceTypeWorkItemComment, testWorkItemCommentScopeName, "test-permission-workitemcomment-role")
	s.testWorkItemCommentRole = *role
}

// Creates a record structure that includes a resource type, plus a role and scope for that resource type
func (s *permissionServiceBlackBoxTest) setupResourceType(resourceTypeName string, scopeName, roleName string) *roleRepo.Role {
	// Create a test resource type
	err := s.resourceTypeRepo.Create(s.Ctx, &resourcetype.ResourceType{
		Name: resourceTypeName,
	})
	require.NoError(s.T(), err, "Could not create resource type")

	// Lookup our test resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, resourceTypeName)
	require.NoError(s.T(), err, "Could not lookup resource type")

	// Create a test scope
	err = s.resourceTypeScopeRepo.Create(s.Ctx, &resourcetype.ResourceTypeScope{
		Name:           scopeName,
		ResourceTypeID: resourceType.ResourceTypeID,
	})
	require.NoError(s.T(), err, "Could not create resource type scope")

	// Lookup the scope we created
	scopes, err := s.resourceTypeScopeRepo.LookupForType(s.Ctx, resourceType.ResourceTypeID)
	require.NoError(s.T(), err, "Could not lookup resource type scope")
	require.Equal(s.T(), 1, len(scopes))
	testScope := scopes[0]

	// Create a test role for the test resource type
	role, err := test.CreateTestRole(s.Ctx, s.DB, *resourceType, roleName)
	require.NoError(s.T(), err, "Could not create role")

	// Add the scope to the test role
	err = s.roleRepo.AddScope(s.Ctx, role, &testScope)
	require.NoError(s.T(), err, "Could not add scope to role")

	return role
}

/*
 *  Tests that a user has the scope for a role assigned directly to the user for a resource
 */
func (s *permissionServiceBlackBoxTest) TestPermissionForUserAssignedDirectRoleForResource() {
	// Create the user identity
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user-jennifer", "")
	require.NoError(s.T(), err, "Could not create test identity")

	// Create the resource and assign our test role to the user
	resource, err := s.createTestResourceAndAssignDefaultRole(identity)
	require.NoError(s.T(), err)

	// Check that the user has the scope
	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for resource")

	// Also check the RequireScope method
	require.NoError(s.T(), s.permissionService.RequireScope(s.Ctx, identity.ID, resource.ResourceID, testAreaScopeName))
}

/*
 *  Tests that a user has the scope for a child resource, when the role has been assigned to parent resource of the same type
 */
func (s *permissionServiceBlackBoxTest) TestPermissionForUserAssignedDirectRoleForParentResource() {
	// Create the user identity
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user-jane", "")
	require.NoError(s.T(), err, "Could not create test identity")

	// Create another user identity
	otherIdentity, err := test.CreateTestIdentity(s.DB, "permission-service-test-bob", "")
	require.NoError(s.T(), err, "Could not create other test identity")

	// Create a resource and assign our test role to the user
	resource, err := s.createTestResourceAndAssignDefaultRole(identity)
	require.NoError(s.T(), err)

	// Create another resource with no permissions assigned
	otherResource, err := s.createTestResourceWithNoPermissions()
	require.NoError(s.T(), err)

	// Create a child resource for the first resource
	childResource, err := s.createTestChildResource(*resource, testResourceTypeArea)
	require.NoError(s.T(), err)

	// Check the user has the scope for the child resource
	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")

	// Check the user has the scope for the parent resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for parent resource")

	// Check the OTHER user does NOT have the scope for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, otherIdentity.ID, childResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "Other user should not have assigned scope for child resource")

	// Check the OTHER user does NOT have the scope for the parent resource
	result, err = s.permissionService.HasScope(s.Ctx, otherIdentity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "Other user should not have assigned scope for parent resource")

	// Check that our user does NOT have the scope for the OTHER resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, otherResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for other resource")

	// Also exercise the RequireScope method
	require.Error(s.T(), s.permissionService.RequireScope(s.Ctx, identity.ID, otherResource.ResourceID, testAreaScopeName))
}

/*
 *  Tests that a user has the scope for a child resource, when the role has been assigned to an organization of which
 *  the user is a member, for a parent resource of the same type
 */
func (s *permissionServiceBlackBoxTest) TestPermissionForOrganizationMemberAssignedIndirectRoleForParentResource() {
	// Create the user identity
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user-mary", "")
	require.NoError(s.T(), err, "Could not create test identity")

	// Create the organization identity
	org, err := test.CreateTestOrganization(s.Ctx, s.DB, s.Application, identity.ID, "test-permission-org")
	require.NoError(s.T(), err, "Could not create test organization")

	// Create a resource and assign our test role to the organization
	resource, err := s.createTestResourceAndAssignDefaultRole(org)
	require.NoError(s.T(), err)

	// Create a child resource of the same type as the parent
	childResource, err := s.createTestChildResource(*resource, testResourceTypeArea)
	require.NoError(s.T(), err)

	// Check that the user does NOT have the scope for the child resource yet
	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Add the member to the organization
	err = s.addMember(s.DB, org.ID, identity.ID)
	require.NoError(s.T(), err, "Error adding member to organization")

	// TODO remove this once membership repo is implemented
	defer s.removeMember(s.DB, org.ID, identity.ID)

	// Create another user identity
	otherIdentity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user-albert", "")
	require.NoError(s.T(), err, "Could not create other test identity")

	// Check that the user now has the scope for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")

	// Check that the user has the scope for the parent resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for parent resource")

	// Check that the OTHER user does not have the scope for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, otherIdentity.ID, childResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "Other user should not have assigned scope for child resource")

	// Check that the OTHER user does not have the scope for the parent resource
	result, err = s.permissionService.HasScope(s.Ctx, otherIdentity.ID, resource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "Other user should not have assigned scope for parent resource")
}

/*
 *  Tests that a user has the scope for a child resource, when the role has been assigned for a parent resource of a
 *  different type to the child resource where the role for the parent resource has been mapped to the role of the child resource
 */
func (s *permissionServiceBlackBoxTest) TestPermissionForUserAssignedMappedRoleForResource() {
	// Create the user identity
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user-jacques", "")
	require.NoError(s.T(), err, "Could not create test identity")

	// Create the parent resource
	parentResource, err := s.createTestResource(testResourceTypeArea)
	require.NoError(s.T(), err, "Error creating parent resource")

	// Assign a role to the user for the parent resource
	err = s.assignRoleForResource(*parentResource, identity, s.testAreaRole)
	require.NoError(s.T(), err, "Error assigning role for parent resource")

	// Create a child resource
	childResource, err := s.createTestChildResource(*parentResource, testResourceTypeWorkItem)
	require.NoError(s.T(), err, "Error creating child resource")

	// Check the user has the scope for the parent resource
	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, parentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for parent resource")

	// Check the user does NOT have the scope for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Create a role mapping that maps from the parent resource type to the child resource type
	err = test.CreateTestRoleMapping(s.Ctx, s.DB, s.Application, parentResource.ResourceID, s.testAreaRole.RoleID, s.testWorkItemRole.RoleID)
	require.NoError(s.T(), err, "Could not create role mapping")

	// After creating the role mapping the user should now have the scope
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")
}

/*
 *  Tests that a user has the scope for a child resource, when the role has been assigned to an organization for which
 *  the user is a member, for a parent resource of a different type to the child resource where the role for the parent
 *  resource has been mapped to the role of the child resource
 */
func (s *permissionServiceBlackBoxTest) TestPermissionForOrgMemberAssignedMappedRoleForResource() {
	// Create the user identity
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user-thomas", "")
	require.NoError(s.T(), err, "Could not create test identity")

	// Create the organization identity
	org, err := test.CreateTestOrganization(s.Ctx, s.DB, s.Application, identity.ID, "test-permission-org")
	require.NoError(s.T(), err, "Could not create test organization")

	// Create the parent resource
	parentResource, err := s.createTestResource(testResourceTypeArea)
	require.NoError(s.T(), err, "Error creating parent resource")

	// Assign a role for the parent resource to the organization
	err = s.assignRoleForResource(*parentResource, org, s.testAreaRole)
	require.NoError(s.T(), err, "Error assigning role for parent resource")

	// Create the child resource, of a different resource type
	childResource, err := s.createTestChildResource(*parentResource, testResourceTypeWorkItem)
	require.NoError(s.T(), err, "Error creating child resource")

	// Check that the user does not have the scope for the parent resource
	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, parentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for parent resource")

	// Check that the user does not have the scope for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Add the user to the organization
	err = s.addMember(s.DB, org.ID, identity.ID)
	require.NoError(s.T(), err, "Error adding member to organization")

	// TODO remove this cleanup code once membership repo is implemented
	defer s.removeMember(s.DB, org.ID, identity.ID)

	// They should now have the permission for the parent resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, parentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for parent resource")

	// But still no permission for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Now we map the parent's role to the child
	err = test.CreateTestRoleMapping(s.Ctx, s.DB, s.Application, parentResource.ResourceID, s.testAreaRole.RoleID, s.testWorkItemRole.RoleID)
	require.NoError(s.T(), err, "Could not create role mapping")

	// After creating the role mapping the user should now have the scope
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")
}

/*
 *  Tests that a user has the scope for a child resource, when the role has been assigned for a grandparent resource of a
 *  different type to the child resource, but where the parent resource has the same type as the grandparent resource,
 *  where the role for the grandparent resource type has been mapped to the role of the child resource type
 */
func (s *permissionServiceBlackBoxTest) TestPermissionForOrgMemberAssignedMappedRoleForGrandparentResource() {
	// Create the user identity
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user-richard", "")
	require.NoError(s.T(), err, "Could not create test identity")

	// Create the organization identity
	org, err := test.CreateTestOrganization(s.Ctx, s.DB, s.Application, identity.ID, "test-permission-org")
	require.NoError(s.T(), err, "Could not create test organization")

	// Create the grandparent resource
	grandparentResource, err := s.createTestResource(testResourceTypeArea)
	require.NoError(s.T(), err, "Error creating grandparent resource")

	// Create the parent resource of the same type as the grandparent
	parentResource, err := s.createTestChildResource(*grandparentResource, testResourceTypeArea)
	require.NoError(s.T(), err, "Error creating parent resource")

	// Assign a role to the grandparent resource
	err = s.assignRoleForResource(*grandparentResource, org, s.testAreaRole)
	require.NoError(s.T(), err, "Error assigning role for grandparent resource")

	// Create the child resource of a different type to the parent & grandparent
	childResource, err := s.createTestChildResource(*parentResource, testResourceTypeWorkItem)
	require.NoError(s.T(), err, "Error creating child resource")

	// Check the user does not have the scope for the grandparent resource
	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, grandparentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for grandparent resource")

	// Check the user does not have the scope for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Add the user to the organization
	err = s.addMember(s.DB, org.ID, identity.ID)
	require.NoError(s.T(), err, "Error adding member to organization")

	// TODO remove this cleanup code once membership repo is implemented
	defer s.removeMember(s.DB, org.ID, identity.ID)

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
	err = test.CreateTestRoleMapping(s.Ctx, s.DB, s.Application, grandparentResource.ResourceID, s.testAreaRole.RoleID, s.testWorkItemRole.RoleID)
	require.NoError(s.T(), err, "Could not create role mapping")

	// After creating the role mapping the user should now have the scope
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")
}

/*
 *  Tests that a user has the scope for a child resource, when the user is a member of an organization in which they are a member.
 *  There is a three-level resource hierarchy; grandparent -> parent -> child, where all three resources are of different types.
 *  There are two role mappings - one that maps the role from the grandparent resource type to the test role of the parent
 *  resource type, and one that maps the role from the parent resource type to the test role of the child resource type
 */
func (s *permissionServiceBlackBoxTest) TestPermissionForOrgMemberAssignedDoubleMappedRoleForGrandparentResource() {
	// Create the user identity
	identity, err := test.CreateTestIdentity(s.DB, "permission-service-test-user-harold", "")
	require.NoError(s.T(), err, "Could not create test identity")

	// Create the organization identity
	org, err := test.CreateTestOrganization(s.Ctx, s.DB, s.Application, identity.ID, "test-permission-org")
	require.NoError(s.T(), err, "Could not create test organization")

	// Create the grandparent resource
	grandparentResource, err := s.createTestResource(testResourceTypeArea)
	require.NoError(s.T(), err, "Error creating grandparent resource")

	// Create the parent resource of a different type
	parentResource, err := s.createTestChildResource(*grandparentResource, testResourceTypeWorkItem)
	require.NoError(s.T(), err, "Error creating parent resource")

	// Assign a role to the grandparent resource to the organization
	err = s.assignRoleForResource(*grandparentResource, org, s.testAreaRole)
	require.NoError(s.T(), err, "Error assigning role for grandparent resource")

	// Create the child resource of yet another different type
	childResource, err := s.createTestChildResource(*parentResource, testResourceTypeWorkItemComment)
	require.NoError(s.T(), err, "Error creating child resource")

	// Check the user does not have the scope for the grandparent resource
	result, err := s.permissionService.HasScope(s.Ctx, identity.ID, grandparentResource.ResourceID, testAreaScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for grandparent resource")

	// Check the user does not have the scope for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemScopeName)
	require.NoError(s.T(), err)
	require.False(s.T(), result, "User should not have assigned scope for child resource")

	// Add the user to the organization
	err = s.addMember(s.DB, org.ID, identity.ID)
	require.NoError(s.T(), err, "Error adding member to organization")

	// TODO remove this cleanup code once membership repo is implemented
	defer s.removeMember(s.DB, org.ID, identity.ID)

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
	err = test.CreateTestRoleMapping(s.Ctx, s.DB, s.Application, grandparentResource.ResourceID, s.testAreaRole.RoleID, s.testWorkItemRole.RoleID)
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
	err = test.CreateTestRoleMapping(s.Ctx, s.DB, s.Application, parentResource.ResourceID, s.testWorkItemRole.RoleID, s.testWorkItemCommentRole.RoleID)
	require.NoError(s.T(), err, "Could not create role mapping")

	// Now they should have permissions for the child resource
	result, err = s.permissionService.HasScope(s.Ctx, identity.ID, childResource.ResourceID, testWorkItemCommentScopeName)
	require.NoError(s.T(), err)
	require.True(s.T(), result, "User should have assigned scope for child resource")
}

// Creates a test resource with the specified type
func (s *permissionServiceBlackBoxTest) createTestResource(resourceTypeName string) (*resource.Resource, error) {
	// Lookup the specified resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, resourceTypeName)
	require.NoError(s.T(), err, "Could not lookup resource type")

	resource, err := test.CreateTestResource(s.Ctx, s.DB, *resourceType, "test-permission-resource", nil)
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

// Assigns a role to a user for a resource
func (s *permissionServiceBlackBoxTest) assignRoleForResource(resource resource.Resource, identity account.Identity, role roleRepo.Role) error {
	err := s.identityRoleRepo.Create(s.Ctx, &roleRepo.IdentityRole{
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

// Create a test resource of the default type and assign the default role to the specified user
func (s *permissionServiceBlackBoxTest) createTestResourceAndAssignDefaultRole(identity account.Identity) (*resource.Resource, error) {
	resource, err := s.createTestResource(testResourceTypeArea)
	require.NoError(s.T(), err, "Could not create resource")

	err = s.assignRoleForResource(*resource, identity, s.testAreaRole)
	require.NoError(s.T(), err, "Could not assign role to resource")

	return resource, nil
}

// Create a test resource of the default type with no assigned permissions
func (s *permissionServiceBlackBoxTest) createTestResourceWithNoPermissions() (*resource.Resource, error) {
	// Lookup our default resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, testResourceTypeArea)
	require.NoError(s.T(), err, "Could not lookup resource type")

	resource, err := test.CreateTestResource(s.Ctx, s.DB, *resourceType, "test-permission-resource", nil)
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

// Creates a child resource of the specified parent resource, of the specified type
func (s *permissionServiceBlackBoxTest) createTestChildResource(parentResource resource.Resource, resourceTypeName string) (*resource.Resource, error) {
	// Lookup the resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, resourceTypeName)
	require.NoError(s.T(), err, "Could not lookup resource type")

	resource, err := test.CreateTestResource(s.Ctx, s.DB, *resourceType, "test-permission-resource", &parentResource.ResourceID)
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

// Adds a member to the specified identity (i.e. organization)
func (s *permissionServiceBlackBoxTest) addMember(db *gorm.DB, memberOf uuid.UUID, memberId uuid.UUID) error {

	// TODO replace this with the repository method once membership repo is implemented
	db.Unscoped().Exec("INSERT INTO membership (member_of, member_id) VALUES (?, ?)", memberOf, memberId)

	return nil
}

// Removes a member
// TODO remove this when the membership repository is implemented
func (s *permissionServiceBlackBoxTest) removeMember(db *gorm.DB, memberOf uuid.UUID, memberId uuid.UUID) error {

	db.Unscoped().Exec("DELETE FROM membership WHERE member_of = ? and member_id = ?", memberOf, memberId)
	return nil
}
