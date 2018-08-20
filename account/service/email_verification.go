package service

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	authclient "github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/notification"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
)

type EmailVerificationService interface {
	SendVerificationCode(ctx context.Context, req *goa.RequestData, identity repository.Identity) (*repository.VerificationCode, error)
	VerifyCode(ctx context.Context, code string) (*repository.VerificationCode, error)
}

type EmailVerificationClient struct {
	app          application.Application
	notification service.NotificationService
}

// NewEmailVerificationClient creates a new client for managing email verification.
func NewEmailVerificationClient(app application.Application) *EmailVerificationClient {
	return &EmailVerificationClient{
		app:          app,
		notification: app.NotificationService(),
	}
}

// SendVerificationCode generates and sends out an email with verification code.
func (c *EmailVerificationClient) SendVerificationCode(ctx context.Context, req *goa.RequestData, identity repository.Identity) (*repository.VerificationCode, error) {

	generatedCode := uuid.NewV4().String()
	newVerificationCode := repository.VerificationCode{
		User: identity.User,
		Code: generatedCode,
	}

	log.Info(ctx, map[string]interface{}{
		"email": identity.User.Email,
	}, "verification code to be sent")

	err := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		err := tr.VerificationCodes().Create(ctx, &newVerificationCode)
		return err
	})
	if err != nil {
		return nil, err
	}

	notificationCustomAttributes := map[string]interface{}{
		"verifyURL": c.generateVerificationURL(ctx, req, generatedCode),
	}

	emailMessage := notification.NewUserEmailUpdated(identity.ID.String(), notificationCustomAttributes)
	c.notification.SendMessageAsync(ctx, emailMessage)

	return &newVerificationCode, err
}

func (c *EmailVerificationClient) generateVerificationURL(ctx context.Context, req *goa.RequestData, code string) string {
	return rest.AbsoluteURL(req, authclient.VerifyEmailUsersPath(), nil) + "?code=" + code
}

// VerifyCode validates whether the code is present in our database and returns a non-nil if yes.
func (c *EmailVerificationClient) VerifyCode(ctx context.Context, code string) (*repository.VerificationCode, error) {

	var verificationCode *repository.VerificationCode

	log.Debug(ctx, map[string]interface{}{
		"code": code,
	}, "verification code to be validated")

	err := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {

		verificationCodeList, err := tr.VerificationCodes().LoadByCode(ctx, code)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err": err,
			}, "error looking up verification code")
			return err
		}
		if verificationCodeList == nil || len(verificationCodeList) == 0 {
			return errors.NewNotFoundError("code", code)
		}

		verificationCode = &verificationCodeList[0]

		user := verificationCode.User
		user.EmailVerified = true
		err = tr.Users().Save(ctx, &user)
		if err != nil {
			return err
		}

		err = tr.VerificationCodes().Delete(ctx, verificationCode.ID)
		return err

	})
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"code": code,
			"err":  err,
		}, "verification failed")
	}
	return verificationCode, err
}
