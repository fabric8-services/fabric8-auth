package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authentication/account"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
)

// UserinfoController implements the userinfo resource.
type UserinfoController struct {
	*goa.Controller
	app          application.Application
	tokenManager manager.TokenManager
}

// NewUserinfoController creates a userinfo controller.
func NewUserinfoController(service *goa.Service, app application.Application, tokenManager manager.TokenManager) *UserinfoController {
	return &UserinfoController{
		Controller:   service.NewController("UserinfoController"),
		app:          app,
		tokenManager: tokenManager,
	}
}

// Show runs the show action, used in the OAuth/OpenID connect authentication flow
func (c *UserinfoController) Show(ctx *app.ShowUserinfoContext) error {
	identityID, err := c.tokenManager.Locate(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Bad Token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("bad or missing token"))
	}
	log.Debug(ctx, map[string]interface{}{"identity_id": identityID}, "showing user info...")
	user, identity, err := c.app.UserService().UserInfo(ctx, identityID)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	if user.Deprovisioned {
		ctx.ResponseData.Header().Add("Access-Control-Expose-Headers", "WWW-Authenticate")
		ctx.ResponseData.Header().Set("WWW-Authenticate", "DEPROVISIONED description=\"Account has been deprovisioned\"")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("Account has been deprovisioned"))
	}

	givenName, familyName := account.SplitFullName(user.FullName)
	sub := identity.ID.String()
	userInfo := &app.UserInfo{
		Sub:               &sub,
		GivenName:         &givenName,
		PreferredUsername: &identity.Username,
		FamilyName:        &familyName,
		Email:             &user.Email,
	}

	return ctx.OK(userInfo)
}
