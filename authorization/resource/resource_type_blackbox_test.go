package resource_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/migration"
	res "github.com/fabric8-services/fabric8-auth/resource"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/satori/go.uuid"
)

type resourceTypeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo  resource.ResourceTypeRepository
	clean func()
	ctx   context.Context
}

func TestRunResourceTypeBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceTypeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite("../../config.yaml")})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *resourceTypeBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	s.DBTestSuite.PopulateDBTestSuite(s.ctx)
}

func (s *resourceTypeBlackBoxTest) SetupTest() {
	s.repo = resource.NewResourceTypeRepository(s.DB)
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
}

func (s *resourceTypeBlackBoxTest) TearDownTest() {
	s.clean()
}

func (s *resourceTypeBlackBoxTest) TestOKToDelete() {
	t := s.T()
	res.Require(t, res.Database)

	// create 2 resources types, where the first one would be deleted.
	resourceType := createAndLoadResourceType(s)
	createAndLoadResourceType(s)

	err := s.repo.Delete(s.ctx, resourceType.ResourceTypeID)
	assert.Nil(s.T(), err)

	// lets see how many are present.
	resourceTypes, err := s.repo.List(s.ctx)
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
		_, err := s.repo.CheckExists(s.ctx, resourceType.ResourceTypeID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("resource type doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		_, err := s.repo.CheckExists(s.ctx, uuid.NewV4().String())
		// then
		require.IsType(s.T(), errors.NotFoundError{}, err)
	})
}

func (s *resourceTypeBlackBoxTest) TestOKToSave() {
	t := s.T()
	res.Require(t, res.Database)

	resourceType := createAndLoadResourceType(s)

	resourceType.Name = "newResourceTypeNameTestType"
	err := s.repo.Save(s.ctx, resourceType)
	require.Nil(s.T(), err, "Could not update resourceType")

	updatedResourceType, err := s.repo.Load(s.ctx, resourceType.ResourceTypeID)
	require.Nil(s.T(), err, "Could not load resource type")
	assert.Equal(s.T(), resourceType.Name, updatedResourceType.Name)
	assert.Equal(s.T(), resourceType.Description, "An area is a logical grouping within a space")
}

func createAndLoadResourceType(s *resourceTypeBlackBoxTest) *resource.ResourceType {
	resourceType := &resource.ResourceType{
		ResourceTypeID:       uuid.NewV4(),
		Name:    "Area" + uuid.NewV4().String(),
		Description: "An area is a logical grouping within a space",
	}

	err := s.repo.Create(s.ctx, resourceType)
	require.Nil(s.T(), err, "Could not create resource type")

	createdResourceType, err := s.repo.Load(s.ctx, resourceType.ResourceTypeID)
	require.Nil(s.T(), err, "Could not load resource type")
	require.Equal(s.T(), resourceType.Name, createdResourceType.Name)
	require.Equal(s.T(), resourceType.ResourceTypeID, createdResourceType.ResourceTypeID)
	require.Equal(s.T(), resourceType.Description, createdResourceType.Description)

	return createdResourceType
}