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

func (s *tokenResourceBlackBoxTest) TestDeleteUnknownFails() {
	tokenID := uuid.NewV4()
	resourceID := "foo"

	err := s.repo.Delete(s.Ctx, tokenID, resourceID)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.NotFoundError{}, err)
}

func (s *tokenResourceBlackBoxTest) TestOKToLoad() {
	tr := s.Graph.CreateTokenResource()

	_, err := s.repo.Load(s.Ctx, tr.TokenResource().TokenID, tr.TokenResource().ResourceID)
	require.NoError(s.T(), err)
}

func (s *tokenResourceBlackBoxTest) TestExistsTokenResource() {
	tr := s.Graph.CreateTokenResource()

	exists, err := s.repo.CheckExists(s.Ctx, tr.TokenResource().TokenID, tr.TokenResource().ResourceID)
	require.NoError(s.T(), err)
	require.True(s.T(), exists)
}

func (s *tokenResourceBlackBoxTest) TestNotExistsTokenFails() {
	exists, err := s.repo.CheckExists(s.Ctx, uuid.NewV4(), uuid.NewV4().String())
	require.Error(s.T(), err)
	require.False(s.T(), exists)
}

func (s *tokenResourceBlackBoxTest) TestOKToSave() {
	tr := s.Graph.CreateTokenResource()

	loaded, err := s.repo.Load(s.Ctx, tr.TokenResource().TokenID, tr.TokenResource().ResourceID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), loaded.Status, 0)

	loaded.Status = 1
	err = s.repo.Save(s.Ctx, loaded)
	require.NoError(s.T(), err)

	loaded, err = s.repo.Load(s.Ctx, tr.TokenResource().TokenID, tr.TokenResource().ResourceID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), loaded.Status, 1)
}

func (s *tokenResourceBlackBoxTest) TestCreateFailsForDuplicateKey() {
	tr := s.Graph.CreateTokenResource()

	err := s.repo.Create(s.Ctx, tr.TokenResource())
	require.Error(s.T(), err, "create token resource should fail for token resource with duplicate key")
}

func (s *tokenResourceBlackBoxTest) TestSaveFailsForDeletedTokenResource() {
	tr := s.Graph.CreateTokenResource()

	err := s.repo.Delete(s.Ctx, tr.TokenResource().TokenID, tr.TokenResource().ResourceID)
	require.NoError(s.T(), err)

	err = s.repo.Save(s.Ctx, tr.TokenResource())
	require.Error(s.T(), err, "save token resource should fail for deleted token resource")
}
