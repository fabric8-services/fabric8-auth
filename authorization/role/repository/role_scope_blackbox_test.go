package repository_test

import (
	"testing"

	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	scope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
	rolescope "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleScopeBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo                  rolescope.RoleScopeRepository
	resourceTypeScopeRepo scope.ResourceTypeScopeRepository
	resourceTypeRepo      resourcetype.ResourceTypeRepository
}

func TestRunResourceTypeScopeBlackBoxTest(t *testing.T) {
	suite.Run(t, &roleScopeBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleScopeBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = rolescope.NewRoleScopeRepository(s.DB)
	s.resourceTypeScopeRepo = scope.NewResourceTypeScopeRepository(s.DB)
	s.resourceTypeRepo = resourcetype.NewResourceTypeRepository(s.DB)
}

func (s *roleScopeBlackBoxTest) TestCreateRoleScopeOK() {
	rt, err := s.resourceTypeRepo.Lookup(s.Ctx, "openshift.io/resource/area")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rt)

	rts, err := testsupport.CreateTestScope(s.Ctx, s.DB, *rt, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rts)

	randomRole, err := testsupport.CreateTestRole(s.Ctx, s.DB, *rt, "collab-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	rs := rolescope.RoleScope{
		ResourceTypeScopeID: rts.ResourceTypeScopeID,
		RoleID:              randomRole.RoleID,
	}

	err = s.repo.Create(s.Ctx, &rs)
	require.NoError(s.T(), err)
}

func (s *roleScopeBlackBoxTest) TestListRoleScopeByRoleOK() {
	rt, err := s.resourceTypeRepo.Lookup(s.Ctx, "openshift.io/resource/area")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rt)

	rts, err := testsupport.CreateTestScope(s.Ctx, s.DB, *rt, uuid.NewV4().String())
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rts)

	randomRole, err := testsupport.CreateTestRole(s.Ctx, s.DB, *rt, "collab-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	rs := rolescope.RoleScope{
		ResourceTypeScopeID: rts.ResourceTypeScopeID,
		RoleID:              randomRole.RoleID,
	}

	err = s.repo.Create(s.Ctx, &rs)
	require.NoError(s.T(), err)

	retrievedRoles, err := s.repo.LoadByRole(s.Ctx, randomRole.RoleID)
	require.NoError(s.T(), err)
	require.Len(s.T(), retrievedRoles, 1)
	require.Equal(s.T(), randomRole.RoleID, retrievedRoles[0].RoleID)
	require.Equal(s.T(), rs.ResourceTypeScopeID, retrievedRoles[0].ResourceTypeScopeID)

}

func (s *roleScopeBlackBoxTest) TestListRoleScopeByScopeOK() {
	rt, err := s.resourceTypeRepo.Lookup(s.Ctx, "openshift.io/resource/area")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), rt)

	// TODO: move to test/authorization.go
	rts := scope.ResourceTypeScope{
		ResourceTypeScopeID: uuid.NewV4(),
		ResourceTypeID:      rt.ResourceTypeID,
		Name:                uuid.NewV4().String(),
	}

	err = s.resourceTypeScopeRepo.Create(s.Ctx, &rts)

	randomRole, err := testsupport.CreateTestRole(s.Ctx, s.DB, *rt, "collab-"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	rs := rolescope.RoleScope{
		ResourceTypeScopeID: rts.ResourceTypeScopeID,
		RoleID:              randomRole.RoleID,
	}

	err = s.repo.Create(s.Ctx, &rs)
	require.NoError(s.T(), err)

	retrievedRoles, err := s.repo.LoadByScope(s.Ctx, rs.ResourceTypeScopeID)
	require.NoError(s.T(), err)
	require.Len(s.T(), retrievedRoles, 1)
	require.Equal(s.T(), randomRole.RoleID, retrievedRoles[0].RoleID)
	require.Equal(s.T(), rs.ResourceTypeScopeID, retrievedRoles[0].ResourceTypeScopeID)
}

func (s *roleScopeBlackBoxTest) TestListRoleScopeByRoleMultipleScopesOK() {
	s.T().Skip()
}
