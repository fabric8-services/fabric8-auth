package worker_test

import (
	tokenRepo "github.com/fabric8-services/fabric8-auth/authorization/token/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token/worker"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

type tokenCleanupWorkerBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo tokenRepo.TokenRepository
}

func TestRunTokenCleanupWorkerBlackBoxTest(t *testing.T) {
	suite.Run(t, &tokenCleanupWorkerBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *tokenCleanupWorkerBlackBoxTest) TestCleanupWorker() {
	now := time.Now()
	yesterday := now.AddDate(0, 0, -1)
	tomorrow := now.AddDate(0, 0, 1)

	// Clean up all tokens
	require.NoError(s.T(), s.deleteAllTokens(s.T()))

	s.Graph.CreateToken(yesterday)
	s.Graph.CreateToken(yesterday)
	s.Graph.CreateToken(tomorrow)

	require.Equal(s.T(), 3, s.countTokens(s.T()))

	// Start the worker with a 1 second timer
	worker := worker.NewTokenCleanupWorker(s.Ctx, s.Application)

	// Activate token cleanup once every hour
	worker.Start(time.NewTicker(time.Second))
	defer worker.Stop()

	// Wait 5 seconds
	time.Sleep(time.Duration(5) * time.Second)

	// We should now have 1 token remaining
	require.Equal(s.T(), s.countTokens(s.T()), 1)
}

func (s *tokenCleanupWorkerBlackBoxTest) deleteAllTokens(t *testing.T) error {
	return s.DB.Exec("DELETE FROM token").Error
}

func (s *tokenCleanupWorkerBlackBoxTest) countTokens(t *testing.T) int {
	var result *int64

	err := s.DB.Table("token").Count(&result).Error
	require.NoError(t, err)

	return int(*result)
}
