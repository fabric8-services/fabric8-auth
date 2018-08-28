package service_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	testResourceTypeArea            = "test.permission.resource.type/area"
	testResourceTypeWorkItem        = "test.permission.resource.type/workitem"
	testResourceTypeWorkItemComment = "test.permission.resource.type/workitemcomment"
	// "test-scope"               = "test_area_scope"
	// testWorkItemScopeName        = "test_workitem_scope"
	// "test-child-role-scope" = "test_workitemcomment_scope"
)

type PermissionServiceTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestPermissionService(t *testing.T) {
	suite.Run(t, &PermissionServiceTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *PermissionServiceTestSuite) TestHasScope() {

	permissionService := s.Application.PermissionService()

	s.T().Run("user assigned with direct role on resource", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		// Create the user identity
		identity := g.CreateIdentity()
		// Create the resource and assign our test role to the user
		resourceType := g.CreateResourceType()
		role := g.CreateRole(resourceType, "test-role").AddScope("test-scope")
		resource := g.CreateResource(resourceType).AddRole(identity, role)
		// when
		// Check that the user has the scope
		result, err := permissionService.HasScope(s.Ctx, identity.ID(), resource.ResourceID(), "test-scope")
		// then
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for resource")

		// Also check the RequireScope method
		require.NoError(t, permissionService.RequireScope(s.Ctx, identity.ID(), resource.ResourceID(), "test-scope"))
	})

	s.T().Run("user assigned role on parent resource", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		// Create the user identity
		identity := g.CreateIdentity()
		// Create another user identity
		otherIdentity := g.CreateIdentity()
		// Create the resource and assign our test role to the user
		resourceType := g.CreateResourceType()
		role := g.CreateRole(resourceType, "test-role").AddScope("test-scope")
		parentResource := g.CreateResource(resourceType).AddRole(identity, role)
		// Create another resource of the same type, with no permissions assigned
		otherResource := g.CreateResource(resourceType)
		// Create a child resource for the first resource, with the same resource type
		childResource := g.CreateResource(parentResource, resourceType)

		// Check the user has the scope for the child resource
		result, err := permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for child resource")

		// Check the user has the scope for the parent resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), parentResource.ResourceID(), "test-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for parent resource")

		// Check the OTHER user does NOT have the scope for the child resource
		result, err = permissionService.HasScope(s.Ctx, otherIdentity.ID(), childResource.ResourceID(), "test-scope")
		require.NoError(t, err)
		require.False(t, result, "Other user should not have assigned scope for child resource")

		// Check the OTHER user does NOT have the scope for the parent resource
		result, err = permissionService.HasScope(s.Ctx, otherIdentity.ID(), parentResource.ResourceID(), "test-scope")
		require.NoError(t, err)
		require.False(t, result, "Other user should not have assigned scope for parent resource")

		// Check that our user does NOT have the scope for the OTHER resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), otherResource.ResourceID(), "test-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for other resource")

		// Also exercise the RequireScope method
		require.Error(t, permissionService.RequireScope(s.Ctx, identity.ID(), otherResource.ResourceID(), "test-scope"))
	})

	/*
	 *  Tests that a user has the scope for a child resource, when the role has been assigned to an organization of which
	 *  the user is a member, for a parent resource of the same type
	 */
	s.T().Run("organization member assigned indirect role for parent resource", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		// Create the user identity
		identity := g.CreateIdentity()
		// Create another user identity
		otherIdentity := g.CreateIdentity()
		// Create the organization
		org := g.CreateOrganization()
		// Create a resource and assign our test role to the organization
		resourceType := g.CreateResourceType()
		role := g.CreateRole(resourceType, "test-role").AddScope("test-scope")
		parentResource := g.CreateResource(resourceType).AddRole(org, role)
		// Create a child resource of the same type as the parent
		childResource := g.CreateResource(parentResource, resourceType)
		// Check that the user does NOT have the scope for the child resource yet
		result, err := permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for child resource")

		// when
		// Add the member to the organization
		org.AddMember(identity)

		// then
		// Check that the user has the scope for the parent resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), parentResource.ResourceID(), "test-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for parent resource")
		// Check that the user now has the scope for the child resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for child resource")
		// Check that the OTHER user does not have the scope for the child resource
		result, err = permissionService.HasScope(s.Ctx, otherIdentity.ID(), childResource.ResourceID(), "test-scope")
		require.NoError(t, err)
		require.False(t, result, "Other user should not have assigned scope for child resource")
		// Check that the OTHER user does not have the scope for the parent resource
		result, err = permissionService.HasScope(s.Ctx, otherIdentity.ID(), parentResource.ResourceID(), "test-scope")
		require.NoError(t, err)
		require.False(t, result, "Other user should not have assigned scope for parent resource")
	})

	/*
	 *  Tests that a user has the scope for a child resource, when the role has been assigned for a parent resource of a
	 *  different type to the child resource where the role for the parent resource has been mapped to the role of the child resource
	 */
	s.T().Run("user with assigned mapped role for resource", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		// Create the user identity
		identity := g.CreateIdentity()
		// Create the parent resource
		// Create a resource and assign our test role to the organization
		parentResourceType := g.CreateResourceType()
		parentRole := g.CreateRole(parentResourceType, "test-parent-role").AddScope("test-parent-scope")
		parentResource := g.CreateResource(parentResourceType).AddRole(identity, parentRole)
		// Create a child resource of the same type as the parent
		childResourceType := g.CreateResourceType()
		childRole := g.CreateRole(childResourceType, "test-child-role").AddScope("test-child-scope")
		childResource := g.CreateResource(parentResource, childResourceType)
		// Check the user has the scope for the parent resource
		result, err := permissionService.HasScope(s.Ctx, identity.ID(), parentResource.ResourceID(), "test-parent-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for parent resource")
		// Check the user does NOT have the scope for the child resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for child resource")

		// when
		// Create a role mapping that maps from the parent resource type to the child resource type
		g.CreateRoleMapping(childResource, parentRole, childRole)

		// then
		// After creating the role mapping the user should now have the scope
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for child resource")
	})

	/*
	 *  Tests that a user has the scope for a child resource, when the role has been assigned to an organization for which
	 *  the user is a member, for a parent resource of a different type to the child resource where the role for the parent
	 *  resource has been mapped to the role of the child resource
	 */
	s.T().Run("org member assigned mapped role for resource", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		// Create the user identity
		identity := g.CreateIdentity()
		// Create the organization
		org := g.CreateOrganization()
		// Create the parent resource
		parentResourceType := g.CreateResourceType()
		parentResource := g.CreateResource(parentResourceType)
		// create role and assign to org on parent resource
		parentRole := g.CreateRole(parentResourceType).AddScope("test-parent-role-scope")
		parentResource.AddRole(org, parentRole)
		// Create the child resource, of a different resource type
		childResourceType := g.CreateResourceType()
		childResource := g.CreateResource(parentResource, childResourceType)
		// create a role for the child resource type
		childRole := g.CreateRole(childResourceType).AddScope("test-child-role-scope")
		// Check that the user does NOT have the scope for the parent resource
		result, err := permissionService.HasScope(s.Ctx, identity.ID(), parentResource.ResourceID(), "test-parent-role-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have any assigned scope for parent resource")
		// Check that the user does NOT have the scope for the child resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-role-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have any assigned scope for child resource")
		// Add the user to the organization
		org.AddMember(identity)
		// user should now have the permission for the parent resource...
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), parentResource.ResourceID(), "test-parent-role-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have an assigned scope for parent resource")
		// ... but still no permission for the child resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-role-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have any assigned scope for child resource")

		// when
		// Now we map the parent's role to the child
		g.CreateRoleMapping(childResource, parentRole, childRole)

		// then
		// After creating the role mapping the user should now have the scope
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-role-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have an assigned scope for child resource")
	})

	/*
	 *  Tests that a user has the scope for a child resource, when the role has been assigned for a grandparent resource of a
	 *  different type to the child resource, but where the parent resource has the same type as the grandparent resource,
	 *  where the role for the grandparent resource type has been mapped to the role of the child resource type
	 */
	s.T().Run("org member assigned mapped role for grandparent resource", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		// Create the user identity
		identity := g.CreateIdentity()
		// Create the organization
		org := g.CreateOrganization()
		// Create the grand parent resource with a role assigned to the org
		ancestorResourceType := g.CreateResourceType()
		grandparentResource := g.CreateResource(ancestorResourceType)
		grandparentRole := g.CreateRole(ancestorResourceType).AddScope("test-ancestor-role-scope")
		grandparentResource.AddRole(org, grandparentRole)
		// Create the parent resource of the same type as the grandparent
		parentResource := g.CreateResource(grandparentResource, ancestorResourceType)
		// Create the child resource of a different type to the parent & grandparent
		childResourceType := g.CreateResourceType()
		childResource := g.CreateResource(parentResource, childResourceType)
		childRole := g.CreateRole(childResourceType).AddScope("test-child-role-scope")
		// Check the user does not have the scope for the grandparent resource
		result, err := permissionService.HasScope(s.Ctx, identity.ID(), grandparentResource.ResourceID(), "test-ancestor-role-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for grandparent resource")
		// Check the user does not have the scope for the child resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-role-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for child resource")
		// Add the user to the organization
		org.AddMember(identity)
		// user should now have the permission for the grandparent resource...
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), grandparentResource.ResourceID(), "test-ancestor-role-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for grandparent resource")
		// ... and the parent resource...
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), parentResource.ResourceID(), "test-ancestor-role-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for parent resource")
		// ... but still no permission for the child resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-role-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for child resource")
		// Now we map the grandparent's role to the child
		g.CreateRoleMapping(childResource, grandparentRole, childRole)
		// After creating the role mapping the user should now have the scope
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-role-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for child resource")
	})

	/*
	 *  Tests that a user has the scope for a child resource, when the user is a member of an organization in which they are a member.
	 *  There is a three-level resource hierarchy; grandparent -> parent -> child, where all three resources are of different types.
	 *  There are two role mappings - one that maps the role from the grandparent resource type to the test role of the parent
	 *  resource type, and one that maps the role from the parent resource type to the test role of the child resource type
	 */
	s.T().Run("org member assigned double mapped role for grandparent resource", func(t *testing.T) {
		// given
		g := s.NewTestGraph(t)
		// Create the user identity
		identity := g.CreateIdentity()
		// Create the organization
		org := g.CreateOrganization()
		// Create the grand parent resource with a role
		grandparentResourceType := g.CreateResourceType()
		grandparentResource := g.CreateResource(grandparentResourceType)
		grandparentRole := g.CreateRole(grandparentResourceType).AddScope("test-grandparent-role-scope")
		grandparentResource.AddRole(org, grandparentRole)
		// Create the parent resource of a different type as the grandparent
		parentResourceType := g.CreateResourceType()
		parentResource := g.CreateResource(grandparentResource, parentResourceType)
		parentRole := g.CreateRole(parentResourceType).AddScope("test-parent-role-scope")
		// Create the child resource of a different type to the parent & grandparent
		childResourceType := g.CreateResourceType()
		childResource := g.CreateResource(parentResource, childResourceType)
		childRole := g.CreateRole(childResourceType).AddScope("test-child-role-scope")
		// Check the user does not have the scope for the grandparent resource
		result, err := permissionService.HasScope(s.Ctx, identity.ID(), grandparentResource.ResourceID(), "test-grandparent-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for grandparent resource")
		// Check the user does not have the scope for the child resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-role-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for child resource")

		// Add the user to the organization
		org.AddMember(identity)
		// user should now have the permission for the grandparent resource...
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), grandparentResource.ResourceID(), "test-grandparent-role-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for grandparent resource")
		// ... but not the parent resource ...
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), parentResource.ResourceID(), "test-parent-role-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for parent resource")
		// ... still no permission for the child resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-role-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for child resource")

		// Now we map the grandparent's role to the parent
		g.CreateRoleMapping(parentResource, grandparentRole, parentRole)
		// After creating the role mapping the user should now have the scope for the parent resource...
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), parentResource.ResourceID(), "test-parent-role-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for parent resource")
		// .. but still no permissions for the child resource yet
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-role-scope")
		require.NoError(t, err)
		require.False(t, result, "User should not have assigned scope for child resource")

		// Now the tricky bit... we map the parent's role to the child resource
		g.CreateRoleMapping(childResource, parentRole, childRole)
		// Now user should have permissions for the child resource
		result, err = permissionService.HasScope(s.Ctx, identity.ID(), childResource.ResourceID(), "test-child-role-scope")
		require.NoError(t, err)
		require.True(t, result, "User should have assigned scope for child resource")
	})

}
