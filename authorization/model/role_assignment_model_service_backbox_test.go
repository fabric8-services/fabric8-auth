package model_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/model"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleAssignmentModelServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	repo model.RoleAssignmentModelService
}

func TestRunRoleAssignmentModelServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &roleAssignmentModelServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleAssignmentModelServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	//s.DB.LogMode(true)
	s.repo = model.NewRoleAssignmentModelService(s.DB, s.Application)
}

func (s *roleAssignmentModelServiceBlackboxTest) TestGetIdentityRoleByResource() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.repo.ListByResource(s.Ctx, identityRole.Resource.ResourceID)
	require.NoError(t, err)
	require.Equal(t, true, len(identityRoles) >= 1)
	require.Equal(t, identityRole.Resource.ResourceID, identityRoles[0].Resource.ResourceID)
}

func (s *roleAssignmentModelServiceBlackboxTest) TestGetIdentityRoleByResourceNotFound() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.repo.ListByResource(s.Ctx, uuid.NewV4().String())
	require.NoError(t, err)
	require.Equal(t, 0, len(identityRoles))
}
