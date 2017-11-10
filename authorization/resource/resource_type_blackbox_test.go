package resource_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	res "github.com/fabric8-services/fabric8-auth/resource"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/satori/go.uuid"
)

type resourceTypeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo resource.ResourceTypeRepository
}

func TestRunResourceTypeBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceTypeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite("../../config.yaml")})
}

func (s *resourceTypeBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = resource.NewResourceTypeRepository(s.DB)
}

func (s *resourceTypeBlackBoxTest) TestOKToDelete() {
	t := s.T()
	res.Require(t, res.Database)

	// create 2 resources types, where the first one would be deleted.
	resourceType := createAndLoadResourceType(s)
	createAndLoadResourceType(s)

	err := s.repo.Delete(s.Ctx, resourceType.ResourceTypeID)
	assert.Nil(s.T(), err)

	// lets see how many are present.
	resourceTypes, err := s.repo.List(s.Ctx)
	require.Nil(s.T(), err, "Could not list resource types")
	require.True(s.T(), len(resourceTypes) > 0)

	for _, data := range resourceTypes {
		// The resource type 'resourceType' was deleted and rest were not deleted, hence we check
		// that none of the resource type objects returned include the one deleted.
		require.NotEqual(s.T(), resourceType.ResourceTypeID.String(), data.ResourceTypeID.String())
	}
}

func (s *resourceTypeBlackBoxTest) TestOKToLoad() {
	t := s.T()
	res.Require(t, res.Database)

	createAndLoadResourceType(s) // this function does the needful already
}

func (s *resourceTypeBlackBoxTest) TestExistsResourceType() {
	t := s.T()
	res.Require(t, res.Database)

	t.Run("resource type exists", func(t *testing.T) {
		//t.Parallel()
		resourceType := createAndLoadResourceType(s)
		// when
		_, err := s.repo.CheckExists(s.Ctx, resourceType.ResourceTypeID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("resource type doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		_, err := s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(s.T(), errors.NotFoundError{}, err)
	})
}

func (s *resourceTypeBlackBoxTest) TestOKToSave() {
	t := s.T()
	res.Require(t, res.Database)

	resourceType := createAndLoadResourceType(s)

	resourceType.Name = "newResourceTypeNameTestType"
	err := s.repo.Save(s.Ctx, resourceType)
	require.Nil(s.T(), err, "Could not update resourceType")

	updatedResourceType, err := s.repo.Load(s.Ctx, resourceType.ResourceTypeID)
	require.Nil(s.T(), err, "Could not load resource type")
	assert.Equal(s.T(), resourceType.Name, updatedResourceType.Name)
	assert.Equal(s.T(), resourceType.Description, "An area is a logical grouping within a space")
}

func createAndLoadResourceType(s *resourceTypeBlackBoxTest) *resource.ResourceType {
	resourceType := &resource.ResourceType{
		ResourceTypeID: uuid.NewV4(),
		Name:           "resource_type_blackbox_test_Area" + uuid.NewV4().String(),
		Description:    "An area is a logical grouping within a space",
	}

	err := s.repo.Create(s.Ctx, resourceType)
	require.Nil(s.T(), err, "Could not create resource type")

	createdResourceType, err := s.repo.Load(s.Ctx, resourceType.ResourceTypeID)
	require.Nil(s.T(), err, "Could not load resource type")
	require.Equal(s.T(), resourceType.Name, createdResourceType.Name)
	require.Equal(s.T(), resourceType.ResourceTypeID, createdResourceType.ResourceTypeID)
	require.Equal(s.T(), resourceType.Description, createdResourceType.Description)

	return createdResourceType
}
