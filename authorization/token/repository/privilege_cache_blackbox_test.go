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

type privilegeCacheBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo tokenRepo.PrivilegeCacheRepository
}

func TestRunPrivilegeCacheBlackBoxTest(t *testing.T) {
	suite.Run(t, &privilegeCacheBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *privilegeCacheBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.DB.LogMode(true)
	s.repo = tokenRepo.NewPrivilegeCacheRepository(s.DB)
}

func (s *privilegeCacheBlackBoxTest) TestOKToDelete() {
	token := s.Graph.CreateToken()

	tr := s.Graph.CreatePrivilegeCache(token)
	token.AddPrivilege(tr)

	tokens, err := s.repo.ListForToken(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)
	require.Equal(s.T(), 1, len(tokens))

	err = s.repo.Delete(s.Ctx, tr.PrivilegeCache().PrivilegeCacheID)
	require.NoError(s.T(), err)

	tokens, err = s.repo.ListForToken(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)
	require.Equal(s.T(), 0, len(tokens))
}

func (s *privilegeCacheBlackBoxTest) TestDeleteUnknownFails() {
	privilegeCacheID := uuid.NewV4()

	err := s.repo.Delete(s.Ctx, privilegeCacheID)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.NotFoundError{}, err)
}

func (s *privilegeCacheBlackBoxTest) TestOKToLoad() {
	tr := s.Graph.CreatePrivilegeCache()

	_, err := s.repo.Load(s.Ctx, tr.PrivilegeCache().PrivilegeCacheID)
	require.NoError(s.T(), err)
}

func (s *privilegeCacheBlackBoxTest) TestExistsPrivilegeCache() {
	tr := s.Graph.CreatePrivilegeCache()

	exists, err := s.repo.CheckExists(s.Ctx, tr.PrivilegeCache().PrivilegeCacheID)
	require.NoError(s.T(), err)
	require.True(s.T(), exists)
}

func (s *privilegeCacheBlackBoxTest) TestNotExistsTokenFails() {
	exists, err := s.repo.CheckExists(s.Ctx, uuid.NewV4())
	require.Error(s.T(), err)
	require.False(s.T(), exists)
}

func (s *privilegeCacheBlackBoxTest) TestOKToSave() {
	tr := s.Graph.CreatePrivilegeCache()

	loaded, err := s.repo.Load(s.Ctx, tr.PrivilegeCache().PrivilegeCacheID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), loaded.Stale, false)

	loaded.Stale = true
	err = s.repo.Save(s.Ctx, loaded)
	require.NoError(s.T(), err)

	loaded, err = s.repo.Load(s.Ctx, tr.PrivilegeCache().PrivilegeCacheID)
	require.NoError(s.T(), err)
	require.Equal(s.T(), loaded.Stale, true)
}

func (s *privilegeCacheBlackBoxTest) TestCreateFailsForDuplicateKey() {
	tr := s.Graph.CreatePrivilegeCache()

	err := s.repo.Create(s.Ctx, tr.PrivilegeCache())
	require.Error(s.T(), err, "create privilege cache should fail for privilege cache with duplicate key")
}

func (s *privilegeCacheBlackBoxTest) TestSaveFailsForDeletedPrivilegeCache() {
	tr := s.Graph.CreatePrivilegeCache()

	err := s.repo.Delete(s.Ctx, tr.PrivilegeCache().PrivilegeCacheID)
	require.NoError(s.T(), err)

	err = s.repo.Save(s.Ctx, tr.PrivilegeCache())
	require.Error(s.T(), err, "save privilege cache should fail for deleted privilege cache")
}
