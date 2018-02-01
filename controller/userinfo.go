package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
)

// UserinfoController implements the userinfo resource.
type UserinfoController struct {
	*goa.Controller
	tokenManager token.Manager
}

// NewUserinfoController creates a userinfo controller.
func NewUserinfoController(service *goa.Service, tokenManager token.Manager) *UserinfoController {
	return &UserinfoController{
		Controller:   service.NewController("UserinfoController"),
		tokenManager: tokenManager,
	}
}

// Show runs the show action.
func (c *UserinfoController) Show(ctx *app.ShowUserinfoContext) error {

	tokenClaims, err := c.tokenManager.ParseToken(ctx, goajwt.ContextJWT(ctx).Raw)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "Couldn't parse token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	userInfo := &app.UserInfo{
		Sub:           &tokenClaims.Subject,
		GivenName:     &tokenClaims.GivenName,
		PreferredName: &tokenClaims.Username,
		FamilyName:    &tokenClaims.FamilyName,
		Email:         &tokenClaims.Email,
	}
	return ctx.OK(userInfo)
}
