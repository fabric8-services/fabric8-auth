package email

import "github.com/fabric8-services/fabric8-auth/application"
import "github.com/fabric8-services/fabric8-auth/account"
import "github.com/fabric8-services/fabric8-auth/log"
import "github.com/fabric8-services/fabric8-auth/errors"
import errs "github.com/pkg/errors"
import "github.com/satori/go.uuid"

import "context"

type EmailVerificationService interface {
	SendVerificationCode(ctx context.Context, user account.User) error
	VerifyCode(ctx context.Context, code string) (bool, error)
}

type EmailVerificationClient struct {
	db application.DB
}

// NewKeycloakIDPServiceClient creates a new Keycloakc
func NewEmailVerificationClient(db application.DB) *EmailVerificationClient {
	return &EmailVerificationClient{
		db: db,
	}
}

// SendVerificationCode generates and sends out an email with verification code.
func (c *EmailVerificationClient) SendVerificationCode(ctx context.Context, user account.User) error {

	newVerificationCode := account.VerificationCode{
		User:     user,
		Code:     uuid.NewV4().String(),
		Verified: false,
	}

	return application.Transactional(c.db, func(appl application.Application) error {
		log.Info(ctx, map[string]interface{}{
			"email": user.Email,
		}, "verification code to be sent")
		err := appl.VerificationCodes().Create(ctx, &newVerificationCode)
		/*
			TODO: Invoke the EmailService to send out an email
		*/
		return err
	})
	return nil
}

// VerifyCode validates whether the code is present in our database.
func (c *EmailVerificationClient) VerifyCode(ctx context.Context, code string) (bool, error) {

	err := application.Transactional(c.db, func(appl application.Application) error {

		log.Info(ctx, map[string]interface{}{
			"code": code,
		}, "verification code to be validated")

		verificationCode, err := appl.VerificationCodes().LoadByCode(ctx, code)
		if err != nil {
			return err
		}
		if verificationCode == nil {
			return errors.NewInternalError(ctx, errs.New("could not find verification code"))
		}

		// if verification code was previously used, it can't be used again.
		if verificationCode.Verified {
			return errors.NewForbiddenError("verification code has already been used")
		}

		user, err := appl.Users().Load(ctx, verificationCode.User.ID)
		if err != nil {
			return err
		}
		if user == nil {
			return errors.NewInternalError(ctx, errs.New("could not find user id"))
		}

		user.EmailVerified = true
		err = appl.Users().Save(ctx, user)
		if err != nil {
			return err
		}

		verificationCode.Verified = true
		err = appl.VerificationCodes().Save(ctx, verificationCode)
		return err

	})
	if err != nil {
		return false, err
	}
	return true, nil
}
