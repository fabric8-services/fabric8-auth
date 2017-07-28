package provider

import (
	"fmt"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/oauth2"
)

const (
	// InvalidCodeError could occure when the OAuth Exchange with GitHub return no valid AccessToken
	InvalidCodeError string = "Invalid OAuth2.0 code"
)

// GithubLoginService defines the basic entrypoint required to perform a remote oauth login
type GithubLoginService interface {
	Perform(ctx *app.LinkLinkContext) error
}

// NewGitHubOAuth creates a new login.GithubService capable of using GitHub for authorization
func NewGitHubOAuth(config *oauth2.Config, identities account.IdentityRepository, users account.UserRepository, externalTokenRepository ExternalProviderTokenRepository) GithubLoginService {
	return &gitHubOAuth{
		config:     config,
		identities: identities,
		users:      users,
		externalTokenRepository: externalTokenRepository,
	}
}

type gitHubOAuth struct {
	config                  *oauth2.Config
	identities              account.IdentityRepository
	users                   account.UserRepository
	externalTokenRepository ExternalProviderTokenRepository
}

func (gh *gitHubOAuth) Perform(ctx *app.LinkLinkContext) error {
	state := ctx.Params.Get("state")
	code := ctx.Params.Get("code")
	referer := ctx.RequestData.Header.Get("Referer")

	if code != "" {
		// After redirect from oauth provider
		if state == "" {
			return ctx.TemporaryRedirect()
		}

		// TODO : check oauth state reference table.

		ghtoken, err := gh.config.Exchange(ctx, code)

		/*

			In case of invalid code, this is what we get in the ghtoken object

			&oauth2.Token{AccessToken:"", TokenType:"", RefreshToken:"", Expiry:time.Time{sec:0, nsec:0, loc:(*time.Location)(nil)}, raw:url.Values{"error":[]string{"bad_verification_code"}, "error_description":[]string{"The code passed is incorrect or expired."}, "error_uri":[]string{"https://developer.github.com/v3/oauth/#bad-verification-code"}}}

		*/

		if err != nil || ghtoken.AccessToken == "" {
			fmt.Println(err)
			ctx.ResponseData.Header().Set("Location", referer+"?error="+InvalidCodeError)
			return ctx.TemporaryRedirect()
		}

		// TODO: check identities table if the specific github account is linked,
		// if not, create identity, else skip.  ( re-linking accounts )

		// TODO: insert token into ExternalProviderTokens table.

		ctx.ResponseData.Header().Set("Location", referer+"?token="+ghtoken.AccessToken)
		return ctx.TemporaryRedirect()
	}

	// First time access, redirect to oauth provider

	// store referer id to state for redirect later
	// TODO: persist state referer
	fmt.Println("Got Request from: ", referer)
	state = uuid.NewV4().String()

	redirectURL := gh.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
	ctx.ResponseData.Header().Set("Location", redirectURL)
	return ctx.TemporaryRedirect()
}
