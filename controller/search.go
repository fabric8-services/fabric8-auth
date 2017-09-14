package controller

import (
	"fmt"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
)

type searchConfiguration interface {
	GetHTTPAddress() string
	GetMaxUsersListLimit() int
}

// SearchController implements the search resource.
type SearchController struct {
	*goa.Controller
	db            application.DB
	configuration searchConfiguration
}

// NewSearchController creates a search controller.
func NewSearchController(service *goa.Service, db application.DB, configuration searchConfiguration) *SearchController {
	return &SearchController{Controller: service.NewController("SearchController"), db: db, configuration: configuration}
}

// Users runs the user search action.
func (c *SearchController) Users(ctx *app.UsersSearchContext) error {

	q := ctx.Q
	if q == "" {
		return ctx.BadRequest(goa.ErrBadRequest(fmt.Errorf("empty search query not allowed")))
	}

	var result []account.Identity
	var count int
	var err error

	offset, limit := computePagingLimits(ctx.PageOffset, ctx.PageLimit)
	if limit > c.configuration.GetMaxUsersListLimit() {
		// Don't return more users then allowed by configuration
		limit = c.configuration.GetMaxUsersListLimit()
	}

	err = application.Transactional(c.db, func(appl application.Application) error {
		result, count, err = appl.Identities().Search(ctx, q, offset, limit)
		return err
	})
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to run search query on users.")
		ctx.InternalServerError()
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
		users = append(users, &app.UserData{
			// FIXME : should be "users" in the long term
			Type: "identities",
			ID:   &id,
			Attributes: &app.UserDataAttributes{
				CreatedAt:  &ident.User.CreatedAt,
				UpdatedAt:  &ident.User.UpdatedAt,
				Username:   &ident.Username,
				FullName:   &ident.User.FullName,
				ImageURL:   &ident.User.ImageURL,
				Bio:        &ident.User.Bio,
				URL:        &ident.User.URL,
				UserID:     &userID,
				IdentityID: &id,
				Email:      &ident.User.Email,
				Company:    &ident.User.Company,
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
