package repository_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

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
	resource := createAndLoadResource(s)
	createAndLoadResource(s)

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
	createAndLoadResource(s)
}

func (s *resourceBlackBoxTest) TestExistsResource() {
	t := s.T()

	t.Run("resource exists", func(t *testing.T) {
		//t.Parallel()
		resource := createAndLoadResource(s)
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
	resource := createAndLoadResource(s)

	err := s.repo.Save(s.Ctx, resource)
	require.Nil(s.T(), err, "Could not update resource")

	_, err = s.repo.Load(s.Ctx, resource.ResourceID)
	require.Nil(s.T(), err, "Could not load resource")
}

func createAndLoadResource(s *resourceBlackBoxTest) *resource.Resource {
	resourceType, err := s.resourceTypeRepo.Lookup(s.Ctx, "openshift.io/resource/area")
	require.Nil(s.T(), err, "Could not create resource type")

	resource := &resource.Resource{
		ResourceID:       uuid.NewV4().String(),
		ParentResourceID: nil,
		ResourceType:     *resourceType,
		ResourceTypeID:   resourceType.ResourceTypeID,
	}

	err = s.repo.Create(s.Ctx, resource)
	require.Nil(s.T(), err, "Could not create resource")

	createdResource, err := s.repo.Load(s.Ctx, resource.ResourceID)
	require.Nil(s.T(), err, "Could not load resource")
	assert.Equal(s.T(), "openshift.io/resource/area", createdResource.ResourceType.Name)

	return createdResource
}
