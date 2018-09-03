package repository_test

import (
	"context"
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type resourceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo             resource.ResourceRepository
	identityRepo     account.IdentityRepository
	resourceTypeRepo resourcetype.ResourceTypeRepository
}

func TestRunResourceBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *resourceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = resource.NewResourceRepository(s.DB)
	s.identityRepo = account.NewIdentityRepository(s.DB)
	s.resourceTypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
}

func (s *resourceBlackBoxTest) TestOKToDelete() {
	resource := createAndLoadResource(s, nil)
	createAndLoadResource(s, nil)

	loadedResource, err := s.repo.Load(s.Ctx, resource.ResourceID)
	require.NotNil(s.T(), loadedResource, "Created resource should be loaded")
	require.Nil(s.T(), err, "Should be no error when loading existing resource")

	err = s.repo.Delete(s.Ctx, resource.ResourceID)
	assert.Nil(s.T(), err, "Should be no error when deleting resource")

	// Check the resource is deleted correctly
	loadedResource, err = s.repo.Load(s.Ctx, resource.ResourceID)
	require.Nil(s.T(), loadedResource, "Deleted resource should not be possible to load")
	require.NotNil(s.T(), err, "Should be error when loading non-existing resource")
}

func (s *resourceBlackBoxTest) TestOKToLoad() {
	createAndLoadResource(s, nil)
}

func (s *resourceBlackBoxTest) TestLoadUnknownFails() {
	id := uuid.NewV4().String()
	_, err := s.repo.Load(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "resource with id '%s' not found", id)
}

func (s *resourceBlackBoxTest) TestOKToLoadChildren() {
	parent := createAndLoadResource(s, nil)

	// No children
	foundChildren, err := s.repo.LoadChildren(s.Ctx, parent.ResourceID)
	require.NoError(s.T(), err)
	assert.Len(s.T(), foundChildren, 0)

	// Create children
	var children []string
	for i := 0; i < 5; i++ {
		children = append(children, createAndLoadResource(s, &parent.ResourceID).ResourceID)
		// Create grandchild
		createAndLoadResource(s, &children[i])
	}

	foundChildren, err = s.repo.LoadChildren(s.Ctx, parent.ResourceID)
	require.NoError(s.T(), err)
	assert.Len(s.T(), foundChildren, 5)
	for _, child := range foundChildren {
		assert.Contains(s.T(), children, child.ResourceID)
		assert.Equal(s.T(), parent.ResourceType.Name, child.ResourceType.Name)

		grandChildren, err := s.repo.LoadChildren(s.Ctx, child.ResourceID)
		require.NoError(s.T(), err)
		require.Len(s.T(), grandChildren, 1)

		grandGrandChildren, err := s.repo.LoadChildren(s.Ctx, grandChildren[0].ResourceID)
		require.NoError(s.T(), err)
		require.Len(s.T(), grandGrandChildren, 0)
	}
}

func (s *resourceBlackBoxTest) TestExistsResource() {
	t := s.T()

	t.Run("resource exists", func(t *testing.T) {
		//t.Parallel()
		resource := createAndLoadResource(s, nil)
		// when
		err := s.repo.CheckExists(s.Ctx, resource.ResourceID)
		// then
		require.Nil(t, err)
	})

	t.Run("resource doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		err := s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(s.T(), errors.NotFoundError{}, err)
	})
}

func (s *resourceBlackBoxTest) TestOKToSave() {
	resource := createAndLoadResource(s, nil)

	err := s.repo.Save(s.Ctx, resource)
	require.Nil(s.T(), err, "Could not update resource")

	_, err = s.repo.Load(s.Ctx, resource.ResourceID)
	require.Nil(s.T(), err, "Could not load resource")
}

func (s *resourceBlackBoxTest) TestCannotCreateDuplicateOrganizationNames() {
	// Lookup the organization resource type
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, authorization.IdentityResourceTypeOrganization)
	require.NoError(s.T(), err, "Could not find organization resource type")

	orgName := "Acme Corporation" + uuid.NewV4().String()

	// Create a new organization resource
	res := &resource.Resource{
		ResourceID:       uuid.NewV4().String(),
		ParentResourceID: nil,
		Name:             orgName,
		ResourceType:     *resourceType,
		ResourceTypeID:   resourceType.ResourceTypeID,
	}

	err = s.repo.Create(s.Ctx, res)
	require.NoError(s.T(), err)

	// Now try to create another organization resource with the same name
	res = &resource.Resource{
		ResourceID:       uuid.NewV4().String(),
		ParentResourceID: nil,
		Name:             orgName,
		ResourceType:     *resourceType,
		ResourceTypeID:   resourceType.ResourceTypeID,
	}

	err = s.repo.Create(s.Ctx, res)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.DataConflictError{}, err)
}

func (s *resourceBlackBoxTest) TestCreateResourceDataConflict() {
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, "openshift.io/resource/area")
	require.NoError(s.T(), err, "Could not find resource type")

	resource := &resource.Resource{
		ResourceID:     uuid.NewV4().String(),
		ResourceType:   *resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
	}

	err = s.repo.Create(s.Ctx, resource)
	require.NoError(s.T(), err, "Could not create resource")

	err = s.repo.Create(s.Ctx, resource)
	testsupport.AssertError(s.T(), err, errors.DataConflictError{}, "resource with ID %s already exists", resource.ResourceID)
	//require.IsType(s.T(), errors.DataConflictError{}, err)
}

func createAndLoadResource(s *resourceBlackBoxTest, parentResourceID *string) *resource.Resource {
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, "openshift.io/resource/area")
	require.Nil(s.T(), err, "Could not find resource type")

	resource := &resource.Resource{
		ResourceID:       uuid.NewV4().String(),
		ParentResourceID: parentResourceID,
		ResourceType:     *resourceType,
		ResourceTypeID:   resourceType.ResourceTypeID,
	}

	err = s.repo.Create(s.Ctx, resource)
	require.Nil(s.T(), err, "Could not create resource")

	createdResource, err := s.repo.Load(s.Ctx, resource.ResourceID)
	require.Nil(s.T(), err, "Could not load resource")

	return createdResource
}

func (s *resourceBlackBoxTest) TestFindWithRoleByResourceTypeAndIdentity() {

	s.T().Run("individual", func(t *testing.T) {

		t.Run("individual is admin on no resource", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			rt := g.CreateResourceType()
			r := g.CreateResource(rt)
			require.Equal(t, rt.ResourceType().Name, r.Resource().ResourceType.Name)
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				rt.ResourceType().Name,
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Empty(t, resources)
		})

		t.Run("individual is admin on 1 resource", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			rt := g.CreateResourceType()
			role := g.CreateRole(rt).AddScope("resource-scope1").AddScope("space-scope2").AddScope("space-scope3")
			user := g.CreateUser()
			r := g.CreateResource(rt).AddRole(user, role)
			require.Equal(t, rt.Name(), r.Resource().ResourceType.Name)
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				rt.Name(),
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Len(t, resources, 1)
			assert.Equal(t, r.Resource().ResourceID, resources[0])
		})

		t.Run("individual is admin on 2 resources", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			rt := g.CreateResourceType()
			role := g.CreateRole(rt).AddScope("space-scope1").AddScope("space-scope2").AddScope("space-scope3")
			user := g.CreateUser()
			r1 := g.CreateResource(rt).AddRole(user, role)
			require.Equal(t, rt.Name(), r1.Resource().ResourceType.Name)
			r2 := g.CreateResource(rt).AddRole(user, role)
			require.Equal(t, rt.Name(), r2.Resource().ResourceType.Name)
			g.CreateSpace() // another space on which the user has no role
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				rt.Name(),
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, resources, 2)
			// resources should be space1 and space2, not space3
			assert.ElementsMatch(t, []string{r1.ResourceID(), r2.ResourceID()}, resources)
		})

		t.Run("individual is admin in the parent resource but no default or custom role mapping", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			parentResourceType := g.CreateResourceType()
			parentResource := g.CreateResource(user, parentResourceType) // user will be creator and have a role in the org
			childResourceType := g.CreateResourceType()
			g.CreateResource(childResourceType, parentResource)
			// here we don't map the admin role in the org to a contributor role in the space,
			// so the user is not considered as a contributor in the created space
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				childResourceType.Name(),
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Empty(t, resources)
		})

		t.Run("individual is contributor in the parent resource with default role mapping", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			parentType := g.CreateResourceType()
			parentRole := g.CreateRole(parentType).AddScope("parent-scope1").AddScope("parent-scope2").AddScope("parent-scope3")
			parentResource := g.CreateResource(parentType).AddRole(user, parentRole) // user will be creator and have a role in the org
			childType := g.CreateResourceType()
			childResource := g.CreateResource(childType, parentResource)
			// here we map the role in the org to another role in the space,
			// so the user also inherits a role in the created space
			childRole := g.CreateRole(childType).AddScope("child-scope1").AddScope("child-scope2").AddScope("child-scope3")
			g.CreateDefaultRoleMapping(childType, parentRole, childRole)
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				childType.Name(),
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, resources, 1)
			assert.Equal(t, childResource.Resource().ResourceID, resources[0])
		})

		t.Run("individual is admin in the parent organization with custom role mapping", func(t *testing.T) {
			t.Skipf("not implemented yet")
		})

	})

	s.T().Run("teams", func(t *testing.T) {

		t.Run("individual belongs to admin team on no resource", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			g.CreateTeam("team").AddMember(user)
			rt := g.CreateResourceType()
			require.Equal(t, rt.Name(), rt.Name())
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				rt.Name(),
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Len(t, resources, 0)
		})

		t.Run("individual belongs to admin team on 1 resource", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			team := g.CreateTeam("team").AddMember(user)
			rt := g.CreateResourceType()
			role := g.CreateRole(rt).AddScope("resource-scope1").AddScope("resource-scope2").AddScope("resource-scope3")
			r := g.CreateResource(rt).AddRole(team, role)
			require.Equal(t, rt.Name(), rt.Name())
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				rt.Name(),
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, resources, 1)
			assert.Equal(t, r.Resource().ResourceID, resources[0])
		})

		t.Run("individual is member of admin team in the parent resource with default role mapping", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			creator := g.CreateUser()
			parentResourceType := g.CreateResourceType()                    // team (hence user) will be creator and admin of the org
			parentResource := g.CreateResource(creator, parentResourceType) // team (hence user) will be creator and admin of the org
			user := g.CreateUser()
			team := g.CreateTeam("team").AddMember(user)
			parentRole := g.CreateRole(parentResourceType).AddScope("parent-scope1").AddScope("parent-scope2").AddScope("parent-scope3")
			parentResource.AddRole(team, parentRole)
			childResourceType := g.CreateResourceType()
			childResource := g.CreateResource(childResourceType, parentResource)
			// here we map the admin role in the org to a contributor role in the space,
			// so the user is also considered as a contributor in the created space
			childRole := g.CreateRole(childResourceType).AddScope("child-scope1").AddScope("child-scope2").AddScope("child-scope3")
			g.CreateDefaultRoleMapping(childResourceType, parentRole, childRole)
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				childResourceType.Name(),
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, resources, 1)
			assert.Equal(t, childResource.Resource().ResourceID, resources[0])
		})

		t.Run("individual is member of admin team in the parent organization with custom role mapping", func(t *testing.T) {
			t.Skipf("not implemented yet")
		})
	})

}
