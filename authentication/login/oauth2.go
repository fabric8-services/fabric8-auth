package login

import (
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// OauthConfig represents OAuth2 config
type OauthConfig interface {
	Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error)
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
}
