package keycloak

import (
	"context"
	"net/http"
	"net/url"
	"time"

	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"
	errs "github.com/pkg/errors"
)

func RefreshToken(ctx context.Context, refreshTokenEndpoint string, clientID string, clientSecret string, refreshTokenString string) (*token.TokenSet, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.PostForm(refreshTokenEndpoint, url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"refresh_token": {refreshTokenString},
		"grant_type":    {"refresh_token"},
	})

	if err != nil {
		return nil, autherrors.NewInternalError(ctx, errs.Wrap(err, "error when obtaining token"))
	}
	defer rest.CloseResponse(res)
	switch res.StatusCode {
	case 200:
		// OK
	case 401:
		return nil, autherrors.NewUnauthorizedError(res.Status + " " + rest.ReadBody(res.Body))
	case 400:
		return nil, autherrors.NewUnauthorizedError(res.Status + " " + rest.ReadBody(res.Body))
	default:
		return nil, autherrors.NewInternalError(ctx, errs.New(res.Status+" "+rest.ReadBody(res.Body)))
	}

	return token.ReadTokenSet(ctx, res)

}
