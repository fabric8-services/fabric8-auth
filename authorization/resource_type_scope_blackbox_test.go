package authorization_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/migration"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/satori/go.uuid"

)

type resourceTypeScopeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo  authorization.ResourceTypeScopeRepository
	resourceTypeRepo  authorization.ResourceTypeRepository
	clean func()
	ctx   context.Context
}

func TestRunResourceTypeScopeBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceTypeScopeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

// SetupSuite overrides the DBTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
// It sets up a database connection for all the tests in this suite without polluting global space.
func (s *resourceTypeScopeBlackBoxTest) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.ctx = migration.NewMigrationContext(context.Background())
	s.DBTestSuite.PopulateDBTestSuite(s.ctx)
}

func (s *resourceTypeScopeBlackBoxTest) SetupTest() {
	s.repo = authorization.NewResourceTypeScopeRepository(s.DB)
	s.resourceTypeRepo = authorization.NewResourceTypeRepository(s.DB)
	s.clean = cleaner.DeleteCreatedEntities(s.DB)
}

func (s *resourceTypeScopeBlackBoxTest) TearDownTest() {
	s.clean()
}

func (s *resourceTypeScopeBlackBoxTest) TestOKToDelete() {
	t := s.T()
	resource.Require(t, resource.Database)

	// create 2 resources types, where the first one would be deleted.
	resourceTypeScope := createAndLoadResourceTypeScope(s)
	createAndLoadResourceTypeScope(s)

	err := s.repo.Delete(s.ctx, resourceTypeScope.ResourceTypeScopeID)
	assert.Nil(s.T(), err)

	// lets see how many are present.
	resourceTypeScopes, err := s.repo.List(s.ctx)
	require.Nil(s.T(), err, "Could not list resource type scopes")
	require.True(s.T(), len(resourceTypeScopes) > 0)

	for _, data := range resourceTypeScopes {
		// The resource type 'resourceType' was deleted and rest were not deleted, hence we check
		// that none of the resource type objects returned include the one deleted.
		require.NotEqual(s.T(), resourceTypeScope.ResourceTypeScopeID.String(), data.ResourceTypeScopeID.String())
	}
}

func (s *resourceTypeScopeBlackBoxTest) TestOKToLoad() {
	t := s.T()
	resource.Require(t, resource.Database)

	createAndLoadResourceTypeScope(s)
}

func (s *resourceTypeScopeBlackBoxTest) TestExistsResourceTypeScope() {
	t := s.T()
	resource.Require(t, resource.Database)

	t.Run("resource type scope exists", func(t *testing.T) {
		//t.Parallel()
		resourceTypeScope := createAndLoadResourceTypeScope(s)
		// when
		_, err := s.repo.CheckExists(s.ctx, resourceTypeScope.ResourceTypeScopeID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("resource type scope doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		_, err := s.repo.CheckExists(s.ctx, uuid.NewV4().String())
		// then
		require.IsType(s.T(), errors.NotFoundError{}, err)
	})
}

func (s *resourceTypeScopeBlackBoxTest) TestOKToSave() {
	t := s.T()
	resource.Require(t, resource.Database)

	resourceTypeScope := createAndLoadResourceTypeScope(s)

	resourceTypeScope.Name = "newResourceTypeScopeNameTestType"
	err := s.repo.Save(s.ctx, resourceTypeScope)
	require.Nil(s.T(), err, "Could not update resourceTypeScope")

	updatedResourceTypeScope, err := s.repo.Load(s.ctx, resourceTypeScope.ResourceTypeScopeID)
	require.Nil(s.T(), err, "Could not load resource type scope")
	assert.Equal(s.T(), resourceTypeScope.Name, updatedResourceTypeScope.Name)
	assert.Equal(s.T(), resourceTypeScope.Description, "Collaborators may perform many operations within an area")
}

func createAndLoadResourceTypeScope(s *resourceTypeScopeBlackBoxTest) *authorization.ResourceTypeScope {
	resourceType := &authorization.ResourceType{
		ResourceTypeID:       uuid.NewV4(),
		Name:    "Area" + uuid.NewV4().String(),
		Description: "An area is a logical grouping within a space",
	}

	err := s.resourceTypeRepo.Create(s.ctx, resourceType)
	require.Nil(s.T(), err, "Could not create resource type")

	resourceTypeScope := &authorization.ResourceTypeScope{
		ResourceTypeScopeID:       uuid.NewV4(),
		ResourceType: *resourceType,
		Name:    "collaborate" + uuid.NewV4().String(),
		Description: "Collaborators may perform many operations within an area",
	}

	err = s.repo.Create(s.ctx, resourceTypeScope)
	require.Nil(s.T(), err, "Could not create resource type scope")

	createdResourceTypeScope, err := s.repo.Load(s.ctx, resourceTypeScope.ResourceTypeScopeID)
	require.Nil(s.T(), err, "Could not load resource type scope")
	require.Equal(s.T(), resourceTypeScope.Name, createdResourceTypeScope.Name)
	require.Equal(s.T(), resourceTypeScope.ResourceTypeScopeID, createdResourceTypeScope.ResourceTypeScopeID)
	require.Equal(s.T(), resourceTypeScope.Description, createdResourceTypeScope.Description)

	return createdResourceTypeScope
}