package remoteservice

import (
	"context"
	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-auth/wit/witservice"
	"github.com/fabric8-services/fabric8-wit/goasupport"
	goaclient "github.com/goadesign/goa/client"
)

// CreateSecureRemoteWITClient creates a client for sending requests to the remote WIT service. Pass nil for accessToken if you wish to
// use the token in the context.
func CreateSecureRemoteWITClient(ctx context.Context, remoteEndpoint string, accessToken *string) (*witservice.Client, error) {
	u, err := url.Parse(remoteEndpoint)
	if err != nil {
		return nil, err
	}
	witclient := witservice.New(goaclient.HTTPClientDoer(http.DefaultClient))
	witclient.Host = u.Host
	witclient.Scheme = u.Scheme

	if accessToken == nil {
		witclient.SetJWTSigner(goasupport.NewForwardSigner(ctx))
		return witclient, nil
	}
	staticToken := goaclient.StaticToken{
		Value: *accessToken,
	}
	jwtSigner := goaclient.JWTSigner{
		TokenSource: &goaclient.StaticTokenSource{
			StaticToken: &staticToken,
		},
	}
	witclient.SetJWTSigner(&jwtSigner)
	return witclient, nil
}
