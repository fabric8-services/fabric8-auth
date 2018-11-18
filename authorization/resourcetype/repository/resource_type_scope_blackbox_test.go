package repository_test

import (
	"testing"

	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type resourceTypeScopeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo             resourcetype.ResourceTypeScopeRepository
	resourceTypeRepo resourcetype.ResourceTypeRepository
}

func TestRunResourceTypeScopeBlackBoxTest(t *testing.T) {
	suite.Run(t, &resourceTypeScopeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *resourceTypeScopeBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = resourcetype.NewResourceTypeScopeRepository(s.DB)
	s.resourceTypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
}

func (s *resourceTypeScopeBlackBoxTest) TestExistsResourceTypeScope() {
	rt := s.Graph.CreateResourceType()

	rts := &resourcetype.ResourceTypeScope{
		ResourceTypeID: rt.ResourceType().ResourceTypeID,
		Name: "foo",
	}

	err := s.repo.Create(s.Ctx, rts)
	require.NoError(s.T(), err)

	// Confirm that the scope exists
	exists, err := s.repo.CheckExists(s.Ctx, rts.ResourceTypeScopeID.String())
	require.NoError(s.T(), err)
	require.True(s.T(), exists)

	// Confirm that an invalid scope ID doesn't exist
	exists, err = s.repo.CheckExists(s.Ctx, uuid.NewV4().String())
	require.Error(s.T(), err)
	require.IsType(s.T(), err, errors.NotFoundError{})
}

func (s *resourceTypeScopeBlackBoxTest) TestCreateFailsForInvalidResourceType() {
	rts := &resourcetype.ResourceTypeScope{
		ResourceTypeID: uuid.NewV4(),
		Name: "foo",
	}

	err := s.repo.Create(s.Ctx, rts)
	require.Error(s.T(), err)
}

func (s *resourceTypeScopeBlackBoxTest) TestSaveOK() {
	rt := s.Graph.CreateResourceType()

	rts := &resourcetype.ResourceTypeScope{
		ResourceTypeID: rt.ResourceType().ResourceTypeID,
		Name: "foo",
	}

	err := s.repo.Create(s.Ctx, rts)
	require.NoError(s.T(), err)

	// Change the name and save it
	rts.Name = "bar"
	err = s.repo.Save(s.Ctx, rts)
	require.NoError(s.T(), err)

	// Reload the scope, and confirm the name is updated
	reloaded, err := s.repo.Load(s.Ctx, rts.ResourceTypeScopeID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), reloaded.Name, "bar")
}

func (s *resourceTypeScopeBlackBoxTest) TestSaveNonExistentScopeFails() {
	rt := s.Graph.CreateResourceType()

	rts := &resourcetype.ResourceTypeScope{
		ResourceTypeID: rt.ResourceType().ResourceTypeID,
		Name: "foo",
	}

	err := s.repo.Save(s.Ctx, rts)
	require.Error(s.T(), err)
}

func (s *resourceTypeScopeBlackBoxTest) TestListOK() {
	rt := s.Graph.CreateResourceType()
	rt.AddScope("foo")

	vals, err := s.repo.List(s.Ctx, rt.ResourceType())
	require.NoError(s.T(), err)

	require.NotNil(s.T(), vals)
	require.Len(s.T(), vals, 1)
	require.Equal(s.T(), vals[0].Name, "foo")

	rt.AddScope("bar")

	vals, err = s.repo.List(s.Ctx, rt.ResourceType())
	require.NoError(s.T(), err)

	require.NotNil(s.T(), vals)
	require.Len(s.T(), vals, 2)
}

func (s *resourceTypeScopeBlackBoxTest) TestLookupByResourceTypeAndScope() {
	rtRef, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rtRef)

	rts, err := testsupport.CreateTestScope(s.Ctx, s.DB, *rtRef, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rts)

	returnedScope, err := s.repo.LookupByResourceTypeAndScope(s.Ctx, rtRef.ResourceTypeID, rts.Name)
	require.NotNil(s.T(), returnedScope)
	require.NoError(s.T(), err)
	require.Equal(s.T(), rts.Name, returnedScope.Name)
	require.Equal(s.T(), rts.ResourceTypeScopeID, returnedScope.ResourceTypeScopeID)
}

func (s *resourceTypeScopeBlackBoxTest) TestOKToDelete() {
	rtRef, err := testsupport.CreateTestResourceType(s.Ctx, s.DB, uuid.NewV4().String())
	require.NoError(s.T(), err)
	rts, err := testsupport.CreateTestScope(s.Ctx, s.DB, *rtRef, uuid.NewV4().String())
	require.NoError(s.T(), err)

	err = s.repo.Delete(s.Ctx, rts.ResourceTypeScopeID)
	require.NoError(s.T(), err)

	_, err = s.repo.Load(s.Ctx, rts.ResourceTypeScopeID)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "resource_type_scope with id '%s' not found", rts.ResourceTypeScopeID.String())
}

func (s *resourceTypeScopeBlackBoxTest) TestDeleteUnknownFails() {
	id := uuid.NewV4()

	err := s.repo.Delete(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "resource_type_scope with id '%s' not found", id.String())
}
