package controller

import (
	"regexp"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/goadesign/goa"
)

type searchConfiguration interface {
	GetHTTPAddress() string
	GetMaxUsersListLimit() int
}

// SearchController implements the search resource.
type SearchController struct {
	*goa.Controller
	app           application.Application
	configuration searchConfiguration
}

// NewSearchController creates a search controller.
func NewSearchController(service *goa.Service, app application.Application, configuration searchConfiguration) *SearchController {
	return &SearchController{Controller: service.NewController("SearchController"), app: app, configuration: configuration}
}

// Users runs the user search action.
func (c *SearchController) Users(ctx *app.UsersSearchContext) error {

	_, err := c.app.UserService().LoadContextIdentityIfNotBanned(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
	}

	q := ctx.Q
	if len(q) == 0 {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("", "search query should be longer"))
	}

	var result []account.Identity
	var count int

	exceeded := false
	offset, limit := computePagingLimits(ctx.PageOffset, ctx.PageLimit)

	r, err := regexp.Compile(`\w`) // check for A-Z a-z 0-9

	searchLimit := limit
	// Don't return more users than allowed by configuration
	if offset >= c.configuration.GetMaxUsersListLimit() {
		exceeded = true
	} else if offset+limit > c.configuration.GetMaxUsersListLimit() {
		searchLimit = c.configuration.GetMaxUsersListLimit() - offset
	}

	if r.MatchString(q) && len(q) > 1 { // 2 or more characters
		err = transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
			result, count, err = tr.Identities().Search(ctx, q, offset, searchLimit)
			return err
		})
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err": err,
			}, "unable to run search query on users.")
			return jsonapi.JSONErrorResponse(ctx, err)
		}
	}

	if exceeded {
		result = []account.Identity{}
	}
	if count > c.configuration.GetMaxUsersListLimit() {
		// Hide the real count if it's more than the max allowed limit
		count = c.configuration.GetMaxUsersListLimit()
	}

	var users []*app.UserData
	for i := range result {
		ident := result[i]
		id := ident.ID.String()
		userID := ident.User.ID.String()

		email := ident.User.Email
		if ident.User.EmailPrivate {
			email = ""
		}

		users = append(users, &app.UserData{
			Type: "identities",
			ID:   &id,
			Attributes: &app.UserDataAttributes{
				CreatedAt:    &ident.User.CreatedAt,
				UpdatedAt:    &ident.User.UpdatedAt,
				Username:     &ident.Username,
				FullName:     &ident.User.FullName,
				ImageURL:     &ident.User.ImageURL,
				Bio:          &ident.User.Bio,
				URL:          &ident.User.URL,
				UserID:       &userID,
				IdentityID:   &id,
				Email:        &email,
				EmailPrivate: &ident.User.EmailPrivate,
				Company:      &ident.User.Company,
			},
		})
	}

	// If there are no search results ensure that the 'data' section of the jsonapi
	// response is not null, rather [] (empty array)
	if users == nil {
		users = []*app.UserData{}
	}
	response := app.UserList{
		Data:  users,
		Links: &app.PagingLinks{},
		Meta:  &app.UserListMeta{TotalCount: count},
	}
	setPagingLinks(response.Links, buildAbsoluteURL(ctx.RequestData), len(result), offset, limit, count, "q="+q)

	return ctx.OK(&response)

}
