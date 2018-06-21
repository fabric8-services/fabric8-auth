package service_test

import (
	"context"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/account/service"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

type verificationServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	verificationService service.EmailVerificationService
	repo                *repository.GormVerificationCodeRepository
}

func TestRunVerificationServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &verificationServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *verificationServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = repository.NewVerificationCodeRepository(s.DB)
	s.verificationService = service.NewEmailVerificationClient(s.Application)
}

func (s *verificationServiceBlackboxTest) TestSendVerificationCodeOK() {
	identity, err := test.CreateTestIdentity(s.DB, uuid.NewV4().String(), "kc")
	require.NoError(s.T(), err)
	require.Equal(s.T(), identity.ProviderType, "kc")

	r := &goa.RequestData{
		Request: &http.Request{Host: "example.com"},
	}

	generatedCode, err := s.verificationService.SendVerificationCode(context.Background(), r, identity)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), generatedCode)

	// let's check if it's present in the db
	verificationCodes, err := s.Application.VerificationCodes().LoadByCode(context.Background(), generatedCode.Code)
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), verificationCodes)
}

func (s *verificationServiceBlackboxTest) TestVerifyCodeOK() {
	identity, err := test.CreateTestIdentity(s.DB, uuid.NewV4().String(), "kc")
	require.NoError(s.T(), err)
	require.Equal(s.T(), identity.ProviderType, "kc")

	generatedCode := uuid.NewV4().String()
	newVerificationCode := repository.VerificationCode{
		User: identity.User,
		Code: generatedCode,
	}

	err = s.Application.VerificationCodes().Create(context.Background(), &newVerificationCode)
	codeOK, err := s.verificationService.VerifyCode(context.Background(), generatedCode)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), codeOK)

	// let's check if it's present in the db - should be deleted
	verificationCodes, err := s.Application.VerificationCodes().LoadByCode(context.Background(), generatedCode)
	require.NoError(s.T(), err)
	require.Empty(s.T(), verificationCodes)
}

func (s *verificationServiceBlackboxTest) TestVerifyCodeFails() {
	identity, err := test.CreateTestIdentity(s.DB, uuid.NewV4().String(), "kc")
	require.NoError(s.T(), err)
	require.Equal(s.T(), identity.ProviderType, "kc")

	generatedCode := uuid.NewV4().String()
	newVerificationCode := repository.VerificationCode{
		User: identity.User,
		Code: generatedCode,
	}

	err = s.Application.VerificationCodes().Create(context.Background(), &newVerificationCode)
	require.NoError(s.T(), err)

	codeOK, err := s.verificationService.VerifyCode(context.Background(), generatedCode+"dfdkjfd")
	require.Error(s.T(), err)
	require.Nil(s.T(), codeOK)
}
