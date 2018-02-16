package authorization_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/authorization/models"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type roleAssignmentServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	assignmentService authorization.RoleAssignmentService
}

func TestRunRoleAssignmentServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &roleAssignmentServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *roleAssignmentServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	modelService := models.NewRoleAssignmentModelService(s.DB, s.Application)
	s.assignmentService = authorization.NewRoleAssignmentService(modelService, s.Application)
}
func (s *roleAssignmentServiceBlackboxTest) TestGetIdentityRoleByResource() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.assignmentService.ListByResource(s.Ctx, identityRole.Resource.ResourceID)
	require.NoError(t, err)
	require.Equal(t, true, len(identityRoles) >= 1)
	require.Equal(t, identityRole.Resource.ResourceID, identityRoles[0].Resource.ResourceID)
}

func (s *roleAssignmentServiceBlackboxTest) TestGetIdentityRoleByResourceNotFound() {
	t := s.T()
	identityRole, err := testsupport.CreateRandomIdentityRole(s.Ctx, s.DB)
	require.NoError(t, err)
	require.NotNil(t, identityRole)

	identityRoles, err := s.assignmentService.ListByResource(s.Ctx, uuid.NewV4().String())
	require.Error(t, errors.NotFoundError{})
	require.Equal(t, 0, len(identityRoles))
}
