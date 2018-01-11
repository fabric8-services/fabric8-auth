package auth_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type stateBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	repo auth.OauthStateReferenceRepository
}

func TestRunStateBlackBoxTest(t *testing.T) {
	suite.Run(t, &stateBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *stateBlackBoxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = auth.NewOauthStateReferenceRepository(s.DB)
}

func (s *stateBlackBoxTest) TestCreateDeleteLoad() {
	// given
	state := &auth.OauthStateReference{
		State:    uuid.NewV4().String(),
		Referrer: "domain.org"}

	state2 := &auth.OauthStateReference{
		State:    uuid.NewV4().String(),
		Referrer: "anotherdomain.com"}

	_, err := s.repo.Create(s.Ctx, state)
	require.Nil(s.T(), err, "Could not create state reference")
	_, err = s.repo.Create(s.Ctx, state2)
	require.Nil(s.T(), err, "Could not create state reference")
	// when
	err = s.repo.Delete(s.Ctx, state.ID)
	// then
	assert.Nil(s.T(), err)
	_, err = s.repo.Load(s.Ctx, state.State)
	require.NotNil(s.T(), err)
	require.IsType(s.T(), errors.NotFoundError{}, err)

	foundState, err := s.repo.Load(s.Ctx, state2.State)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), foundState)
	require.True(s.T(), state2.Equal(*foundState))
}
