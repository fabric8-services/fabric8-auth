package controller

import (
	"fmt"
	"strings"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
)

// UserinfoController implements the userinfo resource.
type UserinfoController struct {
	*goa.Controller
	db           application.DB
	tokenManager token.Manager
}

// NewUserinfoController creates a userinfo controller.
func NewUserinfoController(service *goa.Service, db application.DB, tokenManager token.Manager) *UserinfoController {
	return &UserinfoController{
		Controller:   service.NewController("UserinfoController"),
		db:           db,
		tokenManager: tokenManager,
	}
}

// Show runs the show action.
func (c *UserinfoController) Show(ctx *app.ShowUserinfoContext) error {
	id, err := c.tokenManager.Locate(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Bad Token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("Bad Token"))
	}

	return application.Transactional(c.db, func(appl application.Application) error {
		identity, err := appl.Identities().Load(ctx, id)
		if err != nil || identity == nil {
			log.Error(ctx, map[string]interface{}{
				"identity_id": id,
			}, "Auth token contains id %s of unknown Identity", id)
			return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(fmt.Sprintf("Auth token contains id %s of unknown Identity\n", id)))
		}
		var user *account.User
		userID := identity.UserID
		if userID.Valid {
			user, err = appl.Users().Load(ctx.Context, userID.UUID)
			if err != nil {
				return jsonapi.JSONErrorResponse(ctx, errors.NewInternalErrorFromString(ctx, fmt.Sprintf("Can't load user with id %s", userID.UUID)))
			}
		}

		fullName := strings.Split(user.FullName, " ")
		sub := identity.ID.String()
		userInfo := &app.UserInfo{
			Sub:               &sub,
			GivenName:         &fullName[0],
			PreferredUsername: &identity.Username,
			FamilyName:        &fullName[1],
			Email:             &user.Email,
		}

		return ctx.OK(userInfo)
	})

}
