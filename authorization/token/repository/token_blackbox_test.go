package repository_test

import (
	"testing"
	"time"

	tokenPkg "github.com/fabric8-services/fabric8-auth/authorization/token"
	tokenRepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type tokenBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo tokenRepo.TokenRepository
}

func TestRunTokenBlackBoxTest(t *testing.T) {
	suite.Run(t, &tokenBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *tokenBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = tokenRepo.NewTokenRepository(s.DB)
}

func (s *tokenBlackBoxTest) TestOKToDelete() {
	token := s.Graph.CreateToken()

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
	token := s.Graph.CreateToken()

	_, err := s.repo.Load(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)
}

func (s *tokenBlackBoxTest) TestExistsToken() {
	token := s.Graph.CreateToken()

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
	token := s.Graph.CreateToken()

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
	token := s.Graph.CreateToken()

	err := s.repo.Create(s.Ctx, token.Token())
	require.Error(s.T(), err, "create token should fail for token with duplicate key")
}

func (s *tokenBlackBoxTest) TestSaveFailsForDeletedToken() {
	token := s.Graph.CreateToken()

	err := s.repo.Delete(s.Ctx, token.TokenID())
	require.NoError(s.T(), err)

	err = s.repo.Save(s.Ctx, token.Token())
	require.Error(s.T(), err, "save token should fail for deleted token")
}

func (s *tokenBlackBoxTest) TestStatusUpdates() {
	token := s.Graph.CreateToken().Token()

	// A newly created token should be valid by default
	require.True(s.T(), token.Valid())

	token.SetStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED, true)
	require.True(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED))
	require.False(s.T(), token.Valid())

	token.SetStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED, false)
	require.False(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED))
	require.True(s.T(), token.Valid())

	token.SetStatus(tokenPkg.TOKEN_STATUS_REVOKED, true)
	require.True(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_REVOKED))
	require.False(s.T(), token.Valid())
	require.False(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_LOGGED_OUT))
	require.False(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_STALE))
	require.False(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED))

	token.SetStatus(tokenPkg.TOKEN_STATUS_STALE, true)
	require.True(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_REVOKED))
	require.True(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_STALE))
	require.False(s.T(), token.Valid())
	require.False(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED))
	require.False(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_LOGGED_OUT))

	token.SetStatus(tokenPkg.TOKEN_STATUS_LOGGED_OUT, true)
	require.True(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_REVOKED))
	require.True(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_STALE))
	require.True(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_LOGGED_OUT))
	require.False(s.T(), token.Valid())
	require.False(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED))

	token.SetStatus(tokenPkg.TOKEN_STATUS_LOGGED_OUT, true)
	require.True(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_LOGGED_OUT))

	token.SetStatus(tokenPkg.TOKEN_STATUS_LOGGED_OUT, false)
	require.False(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_LOGGED_OUT))
	require.False(s.T(), token.Valid())
	require.True(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_REVOKED))
	require.True(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_STALE))
	require.False(s.T(), token.HasStatus(tokenPkg.TOKEN_STATUS_DEPROVISIONED))

	token.SetStatus(tokenPkg.TOKEN_STATUS_REVOKED, false)
	token.SetStatus(tokenPkg.TOKEN_STATUS_STALE, false)

	require.True(s.T(), token.Valid())
}

func (s *tokenBlackBoxTest) TestCreateListPrivileges() {
	t := s.Graph.CreateToken()
	pc := s.Graph.CreatePrivilegeCache()

	// Create some noise
	err := s.repo.CreatePrivilege(s.Ctx, &tokenRepo.TokenPrivilege{
		TokenID:          s.Graph.CreateToken().TokenID(),
		PrivilegeCacheID: s.Graph.CreatePrivilegeCache().PrivilegeCache().PrivilegeCacheID,
	})
	require.NoError(s.T(), err)

	tp := &tokenRepo.TokenPrivilege{
		TokenID:          t.TokenID(),
		PrivilegeCacheID: pc.PrivilegeCache().PrivilegeCacheID,
	}

	err = s.repo.CreatePrivilege(s.Ctx, tp)
	require.NoError(s.T(), err)

	privs, err := s.repo.ListPrivileges(s.Ctx, t.TokenID())
	require.NoError(s.T(), err)

	require.Len(s.T(), privs, 1)
	require.Equal(s.T(), pc.PrivilegeCache().PrivilegeCacheID, privs[0].PrivilegeCacheID)
}

func (s *tokenBlackBoxTest) TestSetStatusFlagsForIdentity() {
	user1 := s.Graph.CreateUser()
	user2 := s.Graph.CreateUser()

	t1 := s.Graph.CreateToken(user1)
	t2 := s.Graph.CreateToken(user1)
	s.Graph.CreateToken(user1)

	t4 := s.Graph.CreateToken(user2)
	s.Graph.CreateToken(user2)

	require.True(s.T(), t1.Token().Valid())

	err := s.repo.SetStatusFlagsForIdentity(s.Ctx, user1.IdentityID(), tokenPkg.TOKEN_STATUS_REVOKED)
	require.NoError(s.T(), err)

	t1Loaded := s.Graph.LoadToken(t1.TokenID())

	require.False(s.T(), t1Loaded.Token().Valid())
	require.True(s.T(), t1Loaded.Token().HasStatus(tokenPkg.TOKEN_STATUS_REVOKED))

	t2Loaded := s.Graph.LoadToken(t2.TokenID())
	require.False(s.T(), t2Loaded.Token().Valid())

	t4Loaded := s.Graph.LoadToken(t4.TokenID())
	require.True(s.T(), t4Loaded.Token().Valid())
}

func (s *tokenBlackBoxTest) TestCleanupExpiredTokens() {
	// Start by deleting all tokens
	s.DB.Exec("DELETE FROM TOKEN")

	now := time.Now()
	yesterday := now.AddDate(0, 0, -1)
	tomorrow := now.AddDate(0, 0, 1)

	t1 := s.Graph.CreateToken(yesterday)
	t2 := s.Graph.CreateToken(yesterday)
	t3 := s.Graph.CreateToken(now)
	t4 := s.Graph.CreateToken(now)
	t5 := s.Graph.CreateToken(now)
	t6 := s.Graph.CreateToken(tomorrow)
	t7 := s.Graph.CreateToken(tomorrow)

	require.Equal(s.T(), 7, s.countTokens())

	// Let's start by cleaning up all tokens that expired more than 1 hour ago
	err := s.repo.CleanupExpiredTokens(s.Ctx, 1)
	require.NoError(s.T(), err)

	// We should be left with 5 tokens (the "yesterday" tokens should now be gone)
	require.Equal(s.T(), s.countTokens(), 5)

	// Check the exact token IDs
	require.False(s.T(), s.tokenExists(t1.TokenID()))
	require.False(s.T(), s.tokenExists(t2.TokenID()))
	require.True(s.T(), s.tokenExists(t3.TokenID()))
	require.True(s.T(), s.tokenExists(t4.TokenID()))
	require.True(s.T(), s.tokenExists(t5.TokenID()))
	require.True(s.T(), s.tokenExists(t6.TokenID()))
	require.True(s.T(), s.tokenExists(t7.TokenID()))

	// Now let's clean up all the expired tokens, without any retention
	err = s.repo.CleanupExpiredTokens(s.Ctx, 0)
	require.NoError(s.T(), err)

	// We should now be left with just 2 tokens
	require.Equal(s.T(), 2, s.countTokens())

	// Check the exact token IDs
	require.False(s.T(), s.tokenExists(t1.TokenID()))
	require.False(s.T(), s.tokenExists(t2.TokenID()))
	require.False(s.T(), s.tokenExists(t3.TokenID()))
	require.False(s.T(), s.tokenExists(t4.TokenID()))
	require.False(s.T(), s.tokenExists(t5.TokenID()))
	require.True(s.T(), s.tokenExists(t6.TokenID()))
	require.True(s.T(), s.tokenExists(t7.TokenID()))
}

func (s *tokenBlackBoxTest) countTokens() int {
	var result *int64

	err := s.DB.Table("token").Count(&result).Error
	require.NoError(s.T(), err)

	return int(*result)
}

func (s *tokenBlackBoxTest) tokenExists(tokenID uuid.UUID) bool {
	exists, err := s.repo.CheckExists(s.Ctx, tokenID)
	if err != nil {
		require.IsType(s.T(), err, errors.NotFoundError{})
	}

	return exists
}
