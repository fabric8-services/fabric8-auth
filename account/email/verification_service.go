package email

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/satori/go.uuid"

	"context"
)

type EmailVerificationService interface {
	SendVerificationCode(ctx context.Context, user account.User) (*account.VerificationCode, error)
	VerifyCode(ctx context.Context, code string) (*account.VerificationCode, error)
}

type EmailVerificationClient struct {
	db application.DB
}

// NewEmailVerificationClient creates a new Keycloakc
func NewEmailVerificationClient(db application.DB) *EmailVerificationClient {
	return &EmailVerificationClient{
		db: db,
	}
}

// SendVerificationCode generates and sends out an email with verification code.
func (c *EmailVerificationClient) SendVerificationCode(ctx context.Context, user account.User) (*account.VerificationCode, error) {

	generatedCode := uuid.NewV4().String()
	newVerificationCode := account.VerificationCode{
		User: user,
		Code: generatedCode,
	}

	err := application.Transactional(c.db, func(appl application.Application) error {
		log.Info(ctx, map[string]interface{}{
			"email": user.Email,
		}, "verification code to be sent")
		err := appl.VerificationCodes().Create(ctx, &newVerificationCode)
		return err
	})
	/*
		TODO: Invoke the EmailService to send out an email
	*/
	if err != nil {
		return nil, err
	}
	return &newVerificationCode, err
}

// VerifyCode validates whether the code is present in our database and returns a non-nil if yes.
func (c *EmailVerificationClient) VerifyCode(ctx context.Context, code string) (*account.VerificationCode, error) {

	var verificationCode *account.VerificationCode
	err := application.Transactional(c.db, func(appl application.Application) error {

		log.Debug(ctx, map[string]interface{}{
			"code": code,
		}, "verification code to be validated")

		verificationCodeList, err := appl.VerificationCodes().LoadByCode(ctx, code)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err": err,
			}, "error looking up verification code")
			return err
		}
		if verificationCodeList == nil || len(verificationCodeList) == 0 {
			return err
		}

		verificationCode = &verificationCodeList[0]

		user := verificationCode.User
		user.EmailVerified = true
		err = appl.Users().Save(ctx, &user)
		if err != nil {
			return err
		}

		err = appl.VerificationCodes().Delete(ctx, verificationCode.ID)
		return err

	})
	if err != nil {
		return nil, err
	}
	return verificationCode, nil
}
