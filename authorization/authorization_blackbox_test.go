package authorization_test

import (
	"github.com/fabric8-services/fabric8-auth/authorization"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

type invitationBlackBoxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunInvitationBlackBoxTest(t *testing.T) {
	suite.Run(t, &invitationBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *invitationBlackBoxTest) TestCanHaveMembers() {
	require.True(s.T(), authorization.CanHaveMembers(authorization.IdentityResourceTypeOrganization))
	require.True(s.T(), authorization.CanHaveMembers(authorization.IdentityResourceTypeTeam))
	require.True(s.T(), authorization.CanHaveMembers(authorization.IdentityResourceTypeGroup))
}
