package service_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type userServiceBlackboxTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestRunUserServiceBlackboxTestSuite(t *testing.T) {
	suite.Run(t, &userServiceBlackboxTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *userServiceBlackboxTestSuite) TestDeprovisionUnknownUserFails() {
	username := uuid.NewV4().String()
	_, err := s.Application.UserService().DeprovisionUser(s.Ctx, username)
	testsupport.AssertError(s.T(), err, errors.NotFoundError{}, "user identity with username '%s' not found", username)
}

func (s *userServiceBlackboxTestSuite) TestDeprovisionOK() {
	userToDeprovision := s.Graph.CreateUser()
	userToStayIntact := s.Graph.CreateUser()

	identity, err := s.Application.UserService().DeprovisionUser(s.Ctx, userToDeprovision.Identity().Username)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), true, identity.User.Deprovisioned)
	assert.Equal(s.T(), userToDeprovision.User().ID, identity.User.ID)
	assert.Equal(s.T(), userToDeprovision.IdentityID(), identity.ID)

	loadedUser := s.Graph.LoadUser(userToDeprovision.IdentityID())
	assert.Equal(s.T(), true, loadedUser.User().Deprovisioned)
	userToDeprovision.Identity().User.Deprovisioned = true
	testsupport.AssertIdentityEqual(s.T(), userToDeprovision.Identity(), loadedUser.Identity())

	loadedUser = s.Graph.LoadUser(userToStayIntact.IdentityID())
	assert.Equal(s.T(), false, loadedUser.User().Deprovisioned)
	testsupport.AssertIdentityEqual(s.T(), userToStayIntact.Identity(), loadedUser.Identity())
}
