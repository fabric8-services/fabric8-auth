package repository_test

import (
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/authentication/provider/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	uuid "github.com/satori/go.uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type stateBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo repository.OauthStateReferenceRepository
}

func TestRunStateBlackBoxTest(t *testing.T) {
	suite.Run(t, &stateBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *stateBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = repository.NewOauthStateReferenceRepository(s.DB)
}

func (s *stateBlackBoxTest) TestCreateDeleteLoad() {
	// given
	state := &repository.OauthStateReference{
		State:    uuid.NewV4().String(),
		Referrer: "domain.org",
	}

	responseMode := "fragment"
	state2 := &repository.OauthStateReference{
		State:        uuid.NewV4().String(),
		Referrer:     "anotherdomain.com",
		ResponseMode: &responseMode,
	}

	_, err := s.repo.Create(s.Ctx, state)
	require.Nil(s.T(), err, "Could not create state reference")
	foundState, err := s.repo.Load(s.Ctx, state.State)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), foundState)
	require.True(s.T(), state.Equal(*foundState))

	_, err = s.repo.Create(s.Ctx, state2)
	require.Nil(s.T(), err, "Could not create state reference")
	foundState, err = s.repo.Load(s.Ctx, state2.State)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), foundState)
	require.True(s.T(), state2.Equal(*foundState))

	// when
	err = s.repo.Delete(s.Ctx, state.ID)
	// then
	assert.Nil(s.T(), err)
	_, err = s.repo.Load(s.Ctx, state.State)
	require.NotNil(s.T(), err)
	require.IsType(s.T(), errors.NotFoundError{}, err)

	foundState, err = s.repo.Load(s.Ctx, state2.State)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), foundState)
	require.True(s.T(), state2.Equal(*foundState))
}

func (s *stateBlackBoxTest) TestCleanup() {
	// given a set of 1001 stale OAuthstate refs
	for i := 0; i < 1100; i++ { // 1100 occurrences
		state := &repository.OauthStateReference{
			Lifecycle: gormsupport.Lifecycle{
				CreatedAt: time.Now().Add(-10 * 24 * 60 * time.Minute), // 10 days ago
			},
			State:    uuid.NewV4().String(),
			Referrer: "domain.org",
		}
		_, err := s.repo.Create(s.Ctx, state)
		require.Nil(s.T(), err, "Could not create state reference")
	}
	recentState := &repository.OauthStateReference{
		State:    uuid.NewV4().String(),
		Referrer: "anotherdomain.com",
	}
	_, err := s.repo.Create(s.Ctx, recentState)
	require.Nil(s.T(), err, "Could not create state reference")

	// when
	count, err := s.repo.Cleanup(s.Ctx)

	// then
	require.Nil(s.T(), err)
	// check that 1000 rows were deleted (out of 1100 "stale" records)
	assert.Equal(s.T(), int64(1000), count)

	// check that recent state was NOT deleted
	s2, err := s.repo.Load(s.Ctx, recentState.State)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), s2)

}
