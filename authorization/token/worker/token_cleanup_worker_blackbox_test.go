package worker_test

import (
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/authorization/token/worker"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type tokenCleanupWorkerBlackBoxTest struct {
	gormtestsupport.DBTestSuite
}

func TestRunTokenCleanupWorkerBlackBoxTest(t *testing.T) {
	suite.Run(t, &tokenCleanupWorkerBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *tokenCleanupWorkerBlackBoxTest) TestCleanupWorker() {
	now := time.Now()
	yesterday := now.AddDate(0, 0, -1)
	tomorrow := now.AddDate(0, 0, 1)

	// Clean up all tokens
	require.NoError(s.T(), s.deleteAllTokens())

	t1 := s.Graph.CreateToken(yesterday)
	t2 := s.Graph.CreateToken(yesterday)
	t3 := s.Graph.CreateToken(tomorrow)

	require.Equal(s.T(), 3, s.countTokens())

	// Start the worker with a 50ms ticker
	worker := worker.NewTokenCleanupWorker(s.Ctx, s.Application)
	worker.Start(time.NewTicker(time.Millisecond * 50))
	defer worker.Stop()

	for i := 0; i < 30; i++ {
		time.Sleep(time.Millisecond * 100)

		if s.countTokens() == 1 {
			break
		}
	}

	require.False(s.T(), s.tokenExists(t1.TokenID()))
	require.False(s.T(), s.tokenExists(t2.TokenID()))
	require.True(s.T(), s.tokenExists(t3.TokenID()))
}

func (s *tokenCleanupWorkerBlackBoxTest) deleteAllTokens() error {
	return s.DB.Exec("DELETE FROM token").Error
}

func (s *tokenCleanupWorkerBlackBoxTest) countTokens() int {
	var result *int64

	err := s.DB.Table("token").Count(&result).Error
	require.NoError(s.T(), err)

	return int(*result)
}

func (s *tokenCleanupWorkerBlackBoxTest) tokenExists(tokenID uuid.UUID) bool {
	exists, err := s.Application.TokenRepository().CheckExists(s.Ctx, tokenID)
	if err != nil {
		require.IsType(s.T(), err, errors.NotFoundError{})
	}

	return exists
}
