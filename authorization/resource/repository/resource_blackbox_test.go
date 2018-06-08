package repository_test

import (
	"testing"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/fabric8-services/fabric8-auth/authorization"
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
	require.Nil(s.T(), err, "Could not find resource type")

	resource := &resource.Resource{
		ResourceID:     uuid.NewV4().String(),
		ResourceType:   *resourceType,
		ResourceTypeID: resourceType.ResourceTypeID,
	}

	err = s.repo.Create(s.Ctx, resource)
	require.Nil(s.T(), err, "Could not create resource")

	err = s.repo.Create(s.Ctx, resource)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.DataConflictError{}, err)
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
