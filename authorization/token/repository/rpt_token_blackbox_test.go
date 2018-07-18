package repository_test

import (
	"testing"

	tokenRepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type tokenBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo tokenRepo.RPTTokenRepository
}

func TestRunInvitationBlackBoxTest(t *testing.T) {
	suite.Run(t, &tokenBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *tokenBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = tokenRepo.NewRPTTokenRepository(s.DB)
}

func (s *tokenBlackBoxTest) TestOKToDelete() {
	token := s.Graph.CreateRPTToken()

	tokens, err := s.repo.ListForIdentity(s.Ctx, token.Token().IdentityID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), 1, len(tokens))

	err = s.repo.Delete(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)

	tokens, err = s.repo.ListForIdentity(s.Ctx, token.Token().IdentityID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), 0, len(tokens))
}
