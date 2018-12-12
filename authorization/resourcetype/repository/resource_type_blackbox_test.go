package repository_test

import (
	"testing"

	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type resourceTypeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo resourcetype.ResourceTypeRepository
}

var knownResourceTypes = [5]string{
	"openshift.io/resource/area",
	"openshift.io/resource/space",
	"identity/organization",
	"identity/team",
	"identity/group"}

func TestRunResourceTypeBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceTypeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *resourceTypeBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = resourcetype.NewResourceTypeRepository(s.DB)
}

func (s *resourceTypeBlackBoxTest) TestDefaultResourceTypesExist() {
	for _, resourceType := range knownResourceTypes {
		_, err := s.repo.Lookup(s.Ctx, resourceType)
		// then
		require.Nil(s.T(), err)
	}
}

func (s *resourceTypeBlackBoxTest) TestCreateResourceType() {
	resourceTypeRef := resourcetype.ResourceType{
		ResourceTypeID: uuid.NewV4(),
		Name:           uuid.NewV4().String(),
	}
	err := s.repo.Create(s.Ctx, &resourceTypeRef)
	require.NoError(s.T(), err)

	rt, err := s.repo.Lookup(s.Ctx, resourceTypeRef.Name)
	require.NoError(s.T(), err)
	require.Equal(s.T(), resourceTypeRef.Name, rt.Name)
	require.Equal(s.T(), resourceTypeRef.ResourceTypeID, rt.ResourceTypeID)
}

func (s *resourceTypeBlackBoxTest) TestCreateResourceTypeWithDefaultRoleID() {
	t := s.T()

	resourceTypeRef := resourcetype.ResourceType{
		ResourceTypeID: uuid.NewV4(),
		Name:           uuid.NewV4().String(),
	}
	err := s.Application.ResourceTypeRepository().Create(s.Ctx, &resourceTypeRef)
	require.NoError(t, err)

	rt, err := s.Application.ResourceTypeRepository().Lookup(s.Ctx, resourceTypeRef.Name)
	require.NoError(t, err)
	require.Equal(t, resourceTypeRef.Name, rt.Name)
	require.Equal(t, resourceTypeRef.ResourceTypeID, rt.ResourceTypeID)
	require.Nil(t, rt.DefaultRoleID)

	someRole := role.Role{
		RoleID:         uuid.NewV4(),
		ResourceTypeID: resourceTypeRef.ResourceTypeID,
		Name:           uuid.NewV4().String(),
	}
	err = s.Application.RoleRepository().Create(s.Ctx, &someRole)
	require.NoError(t, err)

	resourceTypeRef.DefaultRoleID = &someRole.RoleID
	err = s.repo.Save(s.Ctx, &resourceTypeRef)
	require.NoError(t, err)

	returnedRTRef, err := s.Application.ResourceTypeRepository().Lookup(s.Ctx, resourceTypeRef.Name)
	require.NoError(t, err)
	require.Equal(t, someRole.RoleID, *returnedRTRef.DefaultRoleID)
}

func (s *resourceTypeBlackBoxTest) TestCreateResourceTypeWithoutID() {
	t := s.T()
	resourceTypeRef := resourcetype.ResourceType{
		Name: uuid.NewV4().String(),
	}
	err := s.repo.Create(s.Ctx, &resourceTypeRef)
	require.NoError(t, err)

	rt, err := s.repo.Lookup(s.Ctx, resourceTypeRef.Name)
	require.NoError(t, err)
	require.Equal(t, resourceTypeRef.Name, rt.Name)
	require.Equal(t, resourceTypeRef.ResourceTypeID, rt.ResourceTypeID)

}

func (s *resourceTypeBlackBoxTest) TestOKToDelete() {
	// create two resource types, where the first one would be deleted.
	resourceType, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, "test-resource-type-foo")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), resourceType)

	_, err = testsupport.CreateTestResourceType(s.Ctx, s.DB, "test-resource-type-bar")
	require.NoError(s.T(), err)

	err = s.repo.Delete(s.Ctx, resourceType.ResourceTypeID)
	require.Nil(s.T(), err)

	// lets see how many are present.
	resourceTypes, err := s.repo.List(s.Ctx)
	require.Nil(s.T(), err, "Could not list resource types")
	require.True(s.T(), len(resourceTypes) > 0)

	for _, data := range resourceTypes {
		// The role 'test-resource-type-foo' was deleted and rest were not deleted, hence we check
		// that none of the resource type objects returned include the one deleted.
		require.NotEqual(s.T(), resourceType.ResourceTypeID.String(), data.ResourceTypeID.String())
	}
}

func (s *resourceTypeBlackBoxTest) TestDeleteUnknownFails() {
	id := uuid.NewV4()

	err := s.repo.Delete(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "resource_type with id '%s' not found", id.String())
}

func (s *resourceTypeBlackBoxTest) TestOKToLoad() {
	r, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, "test-resource-type/load")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), r)

	_, err = s.repo.Load(s.Ctx, r.ResourceTypeID)
	require.NoError(s.T(), err)
}

func (s *resourceTypeBlackBoxTest) TestOKToSave() {
	resourceType, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, "test-resource-type/save")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), resourceType)

	resourceType.Name = "test-resource-type/updated-name"
	err = s.repo.Save(s.Ctx, resourceType)
	require.Nil(s.T(), err, "Could not update resource type")

	updatedResourceType, err := s.repo.Load(s.Ctx, resourceType.ResourceTypeID)
	require.Nil(s.T(), err, "Could not load resource type")
	require.Equal(s.T(), resourceType.Name, updatedResourceType.Name)
}
