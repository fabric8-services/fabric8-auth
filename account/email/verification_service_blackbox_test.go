package email_test

import (
	"context"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/account/email"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/suite"
	"testing"
	//"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type verificationServiceBlackboxTest struct {
	gormtestsupport.DBTestSuite
	verificationService email.EmailVerificationService
	repo                *account.GormVerificationCodeRepository
}

func TestRunVerificationServiceBlackboxTest(t *testing.T) {
	suite.Run(t, &verificationServiceBlackboxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *verificationServiceBlackboxTest) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.repo = account.NewVerificationCodeRepository(s.DB)
	s.verificationService = email.NewEmailVerificationClient(s.Application)
}

func (s *verificationServiceBlackboxTest) TestSendVerificationCodeOK() {
	identity, err := test.CreateTestIdentity(s.DB, uuid.NewV4().String(), "kc")
	require.Nil(s.T(), err)
	require.Equal(s.T(), identity.ProviderType, "kc")

	generatedCode, err := s.verificationService.SendVerificationCode(context.Background(), identity.User)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), generatedCode)

	// let's check if it's present in the db
	verificationCodes, err := s.Application.VerificationCodes().LoadByCode(context.Background(), generatedCode.Code)
	require.Nil(s.T(), err)
	require.NotEmpty(s.T(), verificationCodes)
}

func (s *verificationServiceBlackboxTest) TestVerifyCodeOK() {
	identity, err := test.CreateTestIdentity(s.DB, uuid.NewV4().String(), "kc")
	require.Nil(s.T(), err)
	require.Equal(s.T(), identity.ProviderType, "kc")

	generatedCode := uuid.NewV4().String()
	newVerificationCode := account.VerificationCode{
		User: identity.User,
		Code: generatedCode,
	}

	fmt.Println(identity.User.ID)
	err = s.Application.VerificationCodes().Create(context.Background(), &newVerificationCode)
	codeOK, err := s.verificationService.VerifyCode(context.Background(), generatedCode)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), codeOK)

	// let's check if it's present in the db - should be deleted
	verificationCodes, err := s.Application.VerificationCodes().LoadByCode(context.Background(), generatedCode)
	require.Nil(s.T(), err)
	require.Empty(s.T(), verificationCodes)
}
