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

	spaceType := s.Graph.LoadResourceType(authorization.ResourceTypeSpace)
	organizationType := s.Graph.LoadResourceType(authorization.IdentityResourceTypeOrganization)

	s.T().Run("individual", func(t *testing.T) {

		t.Run("individual is admin on no space", func(t *testing.T) {
			// given
			g := s.NewTestGraph(s.T())
			user := g.CreateUser()
			space := g.CreateSpace()
			require.Equal(t, authorization.ResourceTypeSpace, space.Resource().ResourceType.Name)
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Len(t, resources, 0)
		})

		t.Run("individual is admin on 1 space", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			role := g.CreateRole(spaceType).AddScope("space-scope1").AddScope("space-scope2").AddScope("space-scope3")
			user := g.CreateUser()
			space := g.CreateSpace().AddRole(user, role)
			require.Equal(t, authorization.ResourceTypeSpace, space.Resource().ResourceType.Name)
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Len(t, resources, 1)
			assert.Equal(t, space.Resource().ResourceID, resources[0])
		})

		t.Run("individual is admin on 2 spaces", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			role := g.CreateRole(spaceType).AddScope("space-scope1").AddScope("space-scope2").AddScope("space-scope3")
			user := g.CreateUser()
			space1 := g.CreateSpace().AddRole(user, role)
			require.Equal(t, authorization.ResourceTypeSpace, space1.Resource().ResourceType.Name)
			space2 := g.CreateSpace().AddRole(user, role)
			require.Equal(t, authorization.ResourceTypeSpace, space2.Resource().ResourceType.Name)
			g.CreateSpace() // another space on which the user has no role
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, resources, 2)
			// resources should be space1 and space2, not space3
			assert.ElementsMatch(t, []string{space1.SpaceID(), space2.SpaceID()}, resources)
		})

		t.Run("individual is admin in the parent organization but no default or custom role mapping", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			org := g.CreateOrganization(user) // user will be creator and have a role in the org
			g.CreateSpace(org)
			// here we don't map the admin role in the org to a contributor role in the space,
			// so the user is not considered as a contributor in the created space
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Empty(t, resources)
		})

		t.Run("individual is contributor in the parent organization with default role mapping", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			orgRole := g.CreateRole(organizationType).AddScope("org-scope1").AddScope("org-scope2").AddScope("org-scope3")
			spaceRole := g.CreateRole(spaceType).AddScope("space-scope1").AddScope("space-scope2").AddScope("space-scope3")
			user := g.CreateUser()
			org := g.CreateOrganization(user).AddRole(user, orgRole) // user will be creator and have a role in the org
			space := g.CreateSpace(org)
			// here we map the role in the org to another role in the space,
			// so the user also inherits a role in the created space
			spaceType := g.ResourceTypeByID(space.Resource().ResourceType.ResourceTypeID)
			g.CreateDefaultRoleMapping(spaceType, orgRole, spaceRole)
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, resources, 1)
			assert.Equal(t, space.Resource().ResourceID, resources[0])
		})

		t.Run("individual is admin in the parent organization with custom role mapping", func(t *testing.T) {
			t.Skipf("not implemented yet")
		})

	})

	s.T().Run("teams", func(t *testing.T) {

		t.Run("individual belongs to admin team on no space", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			g.CreateTeam("team").AddMember(user)
			space := g.CreateSpace()
			require.Equal(t, authorization.ResourceTypeSpace, space.Resource().ResourceType.Name)
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			assert.Len(t, resources, 0)
		})

		t.Run("individual belongs to admin team on 1 space", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			user := g.CreateUser()
			team := g.CreateTeam("team").AddMember(user)
			role := g.CreateRole(spaceType).AddScope("org-scope1").AddScope("org-scope2").AddScope("org-scope3")
			space := g.CreateSpace().AddRole(team, role)
			require.Equal(t, authorization.ResourceTypeSpace, space.Resource().ResourceType.Name)
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, resources, 1)
			assert.Equal(t, space.Resource().ResourceID, resources[0])
		})

		t.Run("individual is member of admin team in the parent organization with default role mapping", func(t *testing.T) {
			// given
			g := s.NewTestGraph(t)
			creator := g.CreateUser()
			org := g.CreateOrganization(creator) // team (hence user) will be creator and admin of the org
			user := g.CreateUser()
			team := g.CreateTeam("team").AddMember(user)
			orgRole := g.CreateRole(organizationType).AddScope("org-scope1").AddScope("org-scope2").AddScope("org-scope3")
			org.AddRole(team, orgRole)
			space := g.CreateSpace(org)
			// here we map the admin role in the org to a contributor role in the space,
			// so the user is also considered as a contributor in the created space
			spaceRole := g.CreateRole(organizationType).AddScope("space-scope1").AddScope("space-scope2").AddScope("space-scope3")
			spaceType := g.ResourceTypeByID(space.Resource().ResourceType.ResourceTypeID)
			g.CreateDefaultRoleMapping(spaceType, orgRole, spaceRole)
			// when
			resources, err := s.repo.FindWithRoleByResourceTypeAndIdentity(
				context.Background(),
				authorization.ResourceTypeSpace,
				user.IdentityID())
			// then
			require.NoError(t, err)
			require.Len(t, resources, 1)
			assert.Equal(t, space.Resource().ResourceID, resources[0])
		})

		t.Run("individual is member of admin team in the parent organization with custom role mapping", func(t *testing.T) {
			t.Skipf("not implemented yet")
		})
	})

}
