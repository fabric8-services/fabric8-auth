package model_test

import (
	"testing"

	rolemodel "github.com/fabric8-services/fabric8-auth/authorization/role/model"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleManagementModelServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	repo rolemodel.RoleManagementModelService
}

func TestRunroleManagementModelServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &roleManagementModelServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleManagementModelServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = rolemodel.NewRoleManagementModelService(s.DB, s.Application)
}

func (s *roleManagementModelServiceBlackboxTest) TestGetIdentityRoleByResource() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	// something that we dont want to be returned
	identityRoleUnrelated, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRoleUnrelated)

	identityRoles, err := s.repo.ListByResource(s.Ctx, identityRole.Resource.ResourceID)
	require.NoError(t, err)
	require.Len(t, identityRoles, 1)
	require.Equal(t, identityRole.Resource.ResourceID, identityRoles[0].Resource.ResourceID)
	require.Equal(t, identityRole.Identity.ID, identityRoles[0].Identity.ID)
	require.Equal(t, identityRole.Role.RoleID, identityRoles[0].Role.RoleID)
}

func (s *roleManagementModelServiceBlackboxTest) TestGetIdentityRoleByResourceAndRoleName() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	// something that we don't want to be returned
	for i := 0; i < 10; i++ {
		identityRoleUnrelated, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
		require.NoError(t, err)
		require.NotNil(t, identityRoleUnrelated)
	}

	identityRoles, err := s.repo.ListByResourceAndRoleName(s.Ctx, identityRole.Resource.ResourceID, identityRole.Role.Name)
	require.NoError(t, err)
	require.Len(t, identityRoles, 1)
	require.Equal(t, identityRole.Resource.ResourceID, identityRoles[0].Resource.ResourceID)
	require.Equal(t, identityRole.Identity.ID, identityRoles[0].Identity.ID)
	require.Equal(t, identityRole.Role.RoleID, identityRoles[0].Role.RoleID)
}

func (s *roleManagementModelServiceBlackboxTest) TestGetIdentityRoleByResourceNotFound() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.repo.ListByResource(s.Ctx, uuid.NewV4().String())
	require.NoError(t, err)
	require.Equal(t, 0, len(identityRoles))
}

func (s *roleManagementModelServiceBlackboxTest) TestGetIdentityRoleByResourceAndRoleNameNotFound() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.repo.ListByResourceAndRoleName(s.Ctx, uuid.NewV4().String(), uuid.NewV4().String())
	require.NoError(t, err)
	require.Equal(t, 0, len(identityRoles))
}
