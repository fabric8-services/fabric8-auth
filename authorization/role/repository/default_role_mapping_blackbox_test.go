package repository_test

import (
	"testing"

	rolerepo "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type defaultRoleMappingBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo rolerepo.DefaultRoleMappingRepository
}

func TestRunDefaultRoleMappingBlackBoxTest(t *testing.T) {
	suite.Run(t, &defaultRoleMappingBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *defaultRoleMappingBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = rolerepo.NewDefaultRoleMappingRepository(s.DB)
}

func (s *defaultRoleMappingBlackBoxTest) TestOKToDelete() {
	g := s.NewTestGraph()

	rt := g.CreateResourceType()
	rm := rolerepo.DefaultRoleMapping{
		ResourceTypeID: rt.ResourceType().ResourceTypeID,
		FromRoleID:     g.CreateRole(rt).Role().RoleID,
		ToRoleID:       g.CreateRole().Role().RoleID,
	}

	err := s.repo.Create(s.Ctx, &rm)
	require.NoError(s.T(), err)

	rt2 := g.CreateResourceType()
	rm2 := rolerepo.DefaultRoleMapping{
		ResourceTypeID: rt2.ResourceType().ResourceTypeID,
		FromRoleID:     g.CreateRole(rt).Role().RoleID,
		ToRoleID:       g.CreateRole().Role().RoleID,
	}

	err = s.repo.Create(s.Ctx, &rm2)
	require.NoError(s.T(), err)

	mappings, err := s.repo.List(s.Ctx)
	require.NoError(s.T(), err)

	found1 := false
	found2 := false

	for _, mapping := range mappings {
		if mapping.DefaultRoleMappingID == rm.DefaultRoleMappingID {
			found1 = true
		} else if mapping.DefaultRoleMappingID == rm2.DefaultRoleMappingID {
			found2 = true
		}
	}

	require.True(s.T(), found1, "first default role mapping not found")
	require.True(s.T(), found2, "second default role mapping not found")

	err = s.repo.Delete(s.Ctx, rm.DefaultRoleMappingID)
	require.NoError(s.T(), err)

	mappings, err = s.repo.List(s.Ctx)
	require.NoError(s.T(), err, "Could not list role mappings")

	for _, data := range mappings {
		// The default role mapping rm was deleted while rm2 was not deleted, hence we check
		// that none of the role mappings returned include the deleted record.
		require.NotEqual(s.T(), rm.DefaultRoleMappingID.String(), data.DefaultRoleMappingID.String())
	}
}

func (s *defaultRoleMappingBlackBoxTest) TestDeleteFailsForNonexistent() {
	id := uuid.NewV4()
	err := s.repo.Delete(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "default_role_mapping with id '%s' not found", id.String())
}

func (s *defaultRoleMappingBlackBoxTest) TestOKToLoad() {
	g := s.NewTestGraph()
	rt := g.CreateResourceType()
	rm := &rolerepo.DefaultRoleMapping{
		ResourceTypeID: rt.ResourceType().ResourceTypeID,
		FromRoleID:     g.CreateRole(g.ID("from"), rt).Role().RoleID,
		ToRoleID:       g.CreateRole(g.ID("to")).Role().RoleID,
	}

	err := s.repo.Create(s.Ctx, rm)
	require.NoError(s.T(), err)

	mapping, err := s.repo.Load(s.Ctx, rm.DefaultRoleMappingID)
	require.NoError(s.T(), err)

	require.Equal(s.T(), rt.ResourceType().ResourceTypeID, mapping.ResourceTypeID)
	require.Equal(s.T(), g.RoleByID("from").Role().RoleID, mapping.FromRoleID)
	require.Equal(s.T(), g.RoleByID("to").Role().RoleID, mapping.ToRoleID)
}

func (s *defaultRoleMappingBlackBoxTest) TestLoadFailsForNonexistent() {
	id := uuid.NewV4()
	_, err := s.repo.Load(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "default_role_mapping with id '%s' not found", id.String())
}

func (s *defaultRoleMappingBlackBoxTest) TestExistsDefaultRoleMapping() {
	g := s.NewTestGraph()
	rt := g.CreateResourceType()
	rm := &rolerepo.DefaultRoleMapping{
		ResourceTypeID: rt.ResourceType().ResourceTypeID,
		FromRoleID:     g.CreateRole(rt).Role().RoleID,
		ToRoleID:       g.CreateRole().Role().RoleID,
	}

	err := s.repo.Create(s.Ctx, rm)
	require.NoError(s.T(), err)

	err = s.repo.CheckExists(s.Ctx, rm.DefaultRoleMappingID)
	require.NoError(s.T(), err)
}

func (s *defaultRoleMappingBlackBoxTest) TestExistsUnknownDefaultRoleMappingFails() {
	id := uuid.NewV4()
	err := s.repo.CheckExists(s.Ctx, id)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "default_role_mapping with id '%s' not found", id.String())
}

func (s *defaultRoleMappingBlackBoxTest) TestOKToSave() {
	g := s.NewTestGraph()
	rt := g.CreateResourceType()
	rm := &rolerepo.DefaultRoleMapping{
		ResourceTypeID: rt.ResourceType().ResourceTypeID,
		FromRoleID:     g.CreateRole(rt).Role().RoleID,
		ToRoleID:       g.CreateRole().Role().RoleID,
	}

	otherRole := g.CreateRole()

	err := s.repo.Create(s.Ctx, rm)
	require.NoError(s.T(), err)

	rm.ResourceTypeID = g.CreateResourceType().ResourceType().ResourceTypeID
	rm.ToRoleID = otherRole.Role().RoleID
	err = s.repo.Save(s.Ctx, rm)
	require.NoError(s.T(), err)

	updated, err := s.repo.Load(s.Ctx, rm.DefaultRoleMappingID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), rm.ResourceTypeID, updated.ResourceTypeID)
	require.Equal(s.T(), otherRole.Role().RoleID, updated.ToRoleID)
}

func (s *defaultRoleMappingBlackBoxTest) TestFindForResourceType() {
	g := s.NewTestGraph()
	rt := g.CreateResourceType()
	rm := g.CreateDefaultRoleMapping(rt)

	// make some noise!!
	for i := 0; i < 10; i++ {
		g.CreateDefaultRoleMapping()
	}

	mappings, err := s.repo.FindForResourceType(s.Ctx, rt.ResourceType().ResourceTypeID)
	require.NoError(s.T(), err)

	require.Len(s.T(), mappings, 1)
	require.Equal(s.T(), mappings[0].DefaultRoleMappingID, rm.DefaultRoleMapping().DefaultRoleMappingID)
}
