package repository_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type verificationCodeBlackboxTest struct {
	gormtestsupport.DBTestSuite
	repo *repository.GormVerificationCodeRepository
}

func TestRunverificationCodeBlackboxTest(t *testing.T) {
	suite.Run(t, &verificationCodeBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *verificationCodeBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = repository.NewVerificationCodeRepository(s.DB)
}

func (s *verificationCodeBlackboxTest) TestVerificationCodeOKToLoad() {
	createAndLoadVerificationCode(s)
}

func (s *verificationCodeBlackboxTest) TestVerificationCodeOKToLoadByCode() {
	verificationCode := createAndLoadVerificationCode(s)
	require.NotNil(s.T(), verificationCode)
	listLoadedByCode, err := s.repo.LoadByCode(context.Background(), verificationCode.Code)
	require.NoError(s.T(), err)
	require.Len(s.T(), listLoadedByCode, 1)
	require.Equal(s.T(), verificationCode.UserID, listLoadedByCode[0].UserID)
	s.assertCode(*verificationCode, listLoadedByCode[0])
}

func (s *verificationCodeBlackboxTest) TestVerificationCodeOKToDelete() {
	verificationCode := createAndLoadVerificationCode(s)
	require.NotNil(s.T(), verificationCode)

	err := s.repo.Delete(context.Background(), verificationCode.ID)
	require.NoError(s.T(), err)

	loaded, err := s.repo.Load(context.Background(), verificationCode.ID)
	require.Nil(s.T(), loaded)
	require.Error(s.T(), err, errors.NotFoundError{})
}

func createAndLoadVerificationCode(s *verificationCodeBlackboxTest) *repository.VerificationCode {

	identity, err := test.CreateTestIdentityAndUser(s.DB, uuid.NewV4().String(), "kc")

	require.NoError(s.T(), err)

	verificationCode := repository.VerificationCode{
		ID:     uuid.NewV4(),
		Code:   uuid.NewV4().String(),
		UserID: identity.User.ID,
		User:   identity.User,
	}
	err = s.repo.Create(s.Ctx, &verificationCode)
	require.Nil(s.T(), err, "Could not create verificationCode")
	// when
	verificationCodeRetrieved, err := s.repo.Load(s.Ctx, verificationCode.ID)
	// then
	require.Nil(s.T(), err, "Could not load verificationCode")
	s.assertCode(verificationCode, *verificationCodeRetrieved)
	return verificationCodeRetrieved
}

func (s *verificationCodeBlackboxTest) assertCode(expected repository.VerificationCode, actual repository.VerificationCode) {
	assert.Equal(s.T(), expected.Code, actual.Code)
	assert.Equal(s.T(), expected.ID, actual.ID)
	assert.Equal(s.T(), actual.UserID, expected.UserID)
}
