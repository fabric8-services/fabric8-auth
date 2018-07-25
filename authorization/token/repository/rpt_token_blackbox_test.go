package repository_test

import (
	"testing"

	tokenRepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type tokenBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo tokenRepo.RPTTokenRepository
}

func TestRunTokenBlackBoxTest(t *testing.T) {
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

func (s *tokenBlackBoxTest) TestDeleteFailsForInvalidToken() {
	err := s.repo.Delete(s.Ctx, uuid.NewV4())
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.NotFoundError{}, err)
}

func (s *tokenBlackBoxTest) TestDeleteUnknownFails() {
	id := uuid.NewV4()

	err := s.repo.Delete(s.Ctx, id)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.NotFoundError{}, err)
}

func (s *tokenBlackBoxTest) TestOKToLoad() {
	token := s.Graph.CreateRPTToken()

	_, err := s.repo.Load(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)
}

func (s *tokenBlackBoxTest) TestExistsToken() {
	token := s.Graph.CreateRPTToken()

	exists, err := s.repo.CheckExists(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)
	require.True(s.T(), exists)
}

func (s *tokenBlackBoxTest) TestNotExistsTokenFails() {
	exists, err := s.repo.CheckExists(s.Ctx, uuid.NewV4())
	require.Error(s.T(), err)
	require.False(s.T(), exists)
}

func (s *tokenBlackBoxTest) TestOKToSave() {
	token := s.Graph.CreateRPTToken()

	loadedToken, err := s.repo.Load(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)
	require.Equal(s.T(), loadedToken.Status, 0)

	loadedToken.Status = 1
	err = s.repo.Save(s.Ctx, loadedToken)
	require.NoError(s.T(), err)

	loadedToken, err = s.repo.Load(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)
	require.Equal(s.T(), loadedToken.Status, 1)
}

func (s *tokenBlackBoxTest) TestCreateFailsForDuplicateKey() {
	token := s.Graph.CreateRPTToken()

	err := s.repo.Create(s.Ctx, token.Token())
	require.Error(s.T(), err, "create token should fail for token with duplicate key")
}

func (s *tokenBlackBoxTest) TestSaveFailsForDeletedToken() {
	token := s.Graph.CreateRPTToken()

	err := s.repo.Delete(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)

	err = s.repo.Save(s.Ctx, token.Token())
	require.Error(s.T(), err, "save token should fail for deleted token")
}
