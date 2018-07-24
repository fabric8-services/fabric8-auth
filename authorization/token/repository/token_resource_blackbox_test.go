package repository_test

import (
	"testing"

	tokenRepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type tokenResourceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo tokenRepo.TokenResourceRepository
}

func TestRunTokenResourceBlackBoxTest(t *testing.T) {
	suite.Run(t, &tokenResourceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *tokenResourceBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = tokenRepo.NewTokenResourceRepository(s.DB)
}

func (s *tokenResourceBlackBoxTest) TestOKToDelete() {
	token := s.Graph.CreateRPTToken()

	tr := s.Graph.CreateTokenResource(token)

	tokens, err := s.repo.ListForToken(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)
	require.Equal(s.T(), 1, len(tokens))

	err = s.repo.Delete(s.Ctx, tr.TokenResource().TokenID, tr.TokenResource().ResourceID)
	require.NoError(s.T(), err)

	tokens, err = s.repo.ListForToken(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)
	require.Equal(s.T(), 0, len(tokens))
}
