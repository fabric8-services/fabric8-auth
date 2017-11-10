package resource_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/satori/go.uuid"

	res "github.com/fabric8-services/fabric8-auth/resource"
)

type resourceTypeScopeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo             resource.ResourceTypeScopeRepository
	resourceTypeRepo resource.ResourceTypeRepository
}

func TestRunResourceTypeScopeBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceTypeScopeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite("../../config.yaml")})
}

func (s *resourceTypeScopeBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = resource.NewResourceTypeScopeRepository(s.DB)
	s.resourceTypeRepo = resource.NewResourceTypeRepository(s.DB)
}

func (s *resourceTypeScopeBlackBoxTest) TestOKToDelete() {
	// create 2 resources types, where the first one would be deleted.
	resourceTypeScope := createAndLoadResourceTypeScope(s)
	createAndLoadResourceTypeScope(s)

	err := s.repo.Delete(s.Ctx, resourceTypeScope.ResourceTypeScopeID)
	assert.Nil(s.T(), err)

	// lets see how many are present.
	resourceTypeScopes, err := s.repo.List(s.Ctx, nil)
	require.Nil(s.T(), err, "Could not list resource type scopes")
	require.True(s.T(), len(resourceTypeScopes) > 0)

	for _, data := range resourceTypeScopes {
		// The resource type scope 'resourceTypeScope' was deleted and rest were not deleted, hence we check
		// that none of the resource type scope objects returned include the one deleted.
		require.NotEqual(s.T(), resourceTypeScope.ResourceTypeScopeID.String(), data.ResourceTypeScopeID.String())
	}
}

func (s *resourceTypeScopeBlackBoxTest) TestOKToLoad() {
	t := s.T()
	res.Require(t, res.Database)

	createAndLoadResourceTypeScope(s)
}

func (s *resourceTypeScopeBlackBoxTest) TestExistsResourceTypeScope() {
	t := s.T()
	res.Require(t, res.Database)

	t.Run("resource type scope exists", func(t *testing.T) {
		//t.Parallel()
		resourceTypeScope := createAndLoadResourceTypeScope(s)
		// when
		_, err := s.repo.CheckExists(s.Ctx, resourceTypeScope.ResourceTypeScopeID.String())
		// then
		require.Nil(t, err)
	})

	t.Run("resource type scope doesn't exist", func(t *testing.T) {
		//t.Parallel()
		// Check not existing
		_, err := s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
		// then
		require.IsType(s.T(), errors.NotFoundError{}, err)
	})
}

func (s *resourceTypeScopeBlackBoxTest) TestOKToSave() {
	t := s.T()
	res.Require(t, res.Database)

	resourceTypeScope := createAndLoadResourceTypeScope(s)

	resourceTypeScope.Name = "newResourceTypeScopeNameTestType"
	err := s.repo.Save(s.Ctx, resourceTypeScope)
	require.Nil(s.T(), err, "Could not update resourceTypeScope")

	updatedResourceTypeScope, err := s.repo.Load(s.Ctx, resourceTypeScope.ResourceTypeScopeID)
	require.Nil(s.T(), err, "Could not load resource type scope")
	assert.Equal(s.T(), resourceTypeScope.Name, updatedResourceTypeScope.Name)
	assert.Equal(s.T(), resourceTypeScope.Description, "Collaborators may perform many operations within an area")
}

func createAndLoadResourceTypeScope(s *resourceTypeScopeBlackBoxTest) *resource.ResourceTypeScope {

	resourceType := &resource.ResourceType{
		ResourceTypeID: uuid.NewV4(),
		Name:           "resource_type_scope_blackbox_test_Area" + uuid.NewV4().String(),
		Description:    "An area is a logical grouping within a space",
	}

	s.resourceTypeRepo.Create(s.Ctx, resourceType)

	resourceTypeScope := &resource.ResourceTypeScope{
		ResourceTypeScopeID: uuid.NewV4(),
		ResourceType:        *resourceType,
		ResourceTypeID:      resourceType.ResourceTypeID,
		Name:                "resource_type_scope_blackbox_test_collaborate" + uuid.NewV4().String(),
		Description:         "Collaborators may perform many operations within an area",
	}

	err := s.repo.Create(s.Ctx, resourceTypeScope)
	require.Nil(s.T(), err, "Could not create resource type scope")

	//s.DB.Preload("ResourceType").Table("ResourceTypeScope")
	createdResourceTypeScope, err := s.repo.Load(s.Ctx, resourceTypeScope.ResourceTypeScopeID)

	require.Nil(s.T(), err, "Could not load resource type scope")
	require.Equal(s.T(), resourceTypeScope.Name, createdResourceTypeScope.Name)
	require.Equal(s.T(), resourceTypeScope.ResourceTypeScopeID, createdResourceTypeScope.ResourceTypeScopeID)
	require.Equal(s.T(), resourceTypeScope.Description, createdResourceTypeScope.Description)
	require.Equal(s.T(), resourceTypeScope.ResourceType.ResourceTypeID, createdResourceTypeScope.ResourceType.ResourceTypeID)
	//require.Equal(s.T(), resourceTypeScope.ResourceTypeID, createdResourceTypeScope.ResourceType.ResourceTypeID)

	return createdResourceTypeScope
}
