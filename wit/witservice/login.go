// Code generated by goagen v1.2.0, DO NOT EDIT.
//
// API "wit": login Resource Client
//
// Command:
// $ goagen
// --design=github.com/fabric8-services/fabric8-wit/design
// --notool=true
// --out=$(GOPATH)/src/github.com/fabric8-services/fabric8-auth/wit
// --pkg=witservice
// --version=v1.2.0

package witservice

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// AuthorizeLoginPath computes a request path to the authorize action of login.
func AuthorizeLoginPath() string {

	return fmt.Sprintf("/api/login/authorize")
}

// Authorize with the WIT
func (c *Client) AuthorizeLogin(ctx context.Context, path string, link *bool, redirect *string, scope *string) (*http.Response, error) {
	req, err := c.NewAuthorizeLoginRequest(ctx, path, link, redirect, scope)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewAuthorizeLoginRequest create the request corresponding to the authorize action endpoint of the login resource.
func (c *Client) NewAuthorizeLoginRequest(ctx context.Context, path string, link *bool, redirect *string, scope *string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	values := u.Query()
	if link != nil {
		tmp2 := strconv.FormatBool(*link)
		values.Set("link", tmp2)
	}
	if redirect != nil {
		values.Set("redirect", *redirect)
	}
	if scope != nil {
		values.Set("scope", *scope)
	}
	u.RawQuery = values.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// GenerateLoginPath computes a request path to the generate action of login.
func GenerateLoginPath() string {

	return fmt.Sprintf("/api/login/generate")
}

// Generate a set of Tokens for different Auth levels. NOT FOR PRODUCTION. Only available if server is running in dev mode
func (c *Client) GenerateLogin(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewGenerateLoginRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewGenerateLoginRequest create the request corresponding to the generate action endpoint of the login resource.
func (c *Client) NewGenerateLoginRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// LinkLoginPath computes a request path to the link action of login.
func LinkLoginPath() string {

	return fmt.Sprintf("/api/login/link")
}

// Link an Identity Provider account to the user account
func (c *Client) LinkLogin(ctx context.Context, path string, provider *string, redirect *string) (*http.Response, error) {
	req, err := c.NewLinkLoginRequest(ctx, path, provider, redirect)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewLinkLoginRequest create the request corresponding to the link action endpoint of the login resource.
func (c *Client) NewLinkLoginRequest(ctx context.Context, path string, provider *string, redirect *string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	values := u.Query()
	if provider != nil {
		values.Set("provider", *provider)
	}
	if redirect != nil {
		values.Set("redirect", *redirect)
	}
	u.RawQuery = values.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.JWTSigner != nil {
		c.JWTSigner.Sign(req)
	}
	return req, nil
}

// LinkcallbackLoginPath computes a request path to the linkcallback action of login.
func LinkcallbackLoginPath() string {

	return fmt.Sprintf("/api/login/linkcallback")
}

// Callback from Keyckloak when Identity Provider account successfully linked to the user account
func (c *Client) LinkcallbackLogin(ctx context.Context, path string, next *string, sessionState *string, state *string) (*http.Response, error) {
	req, err := c.NewLinkcallbackLoginRequest(ctx, path, next, sessionState, state)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewLinkcallbackLoginRequest create the request corresponding to the linkcallback action endpoint of the login resource.
func (c *Client) NewLinkcallbackLoginRequest(ctx context.Context, path string, next *string, sessionState *string, state *string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	values := u.Query()
	if next != nil {
		values.Set("next", *next)
	}
	if sessionState != nil {
		values.Set("sessionState", *sessionState)
	}
	if state != nil {
		values.Set("state", *state)
	}
	u.RawQuery = values.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// LinksessionLoginPath computes a request path to the linksession action of login.
func LinksessionLoginPath() string {

	return fmt.Sprintf("/api/login/linksession")
}

// Link an Identity Provider account to the user account represented by user's session. This endpoint is to be used for auto linking during login.
func (c *Client) LinksessionLogin(ctx context.Context, path string, provider *string, redirect *string, sessionState *string) (*http.Response, error) {
	req, err := c.NewLinksessionLoginRequest(ctx, path, provider, redirect, sessionState)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewLinksessionLoginRequest create the request corresponding to the linksession action endpoint of the login resource.
func (c *Client) NewLinksessionLoginRequest(ctx context.Context, path string, provider *string, redirect *string, sessionState *string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	values := u.Query()
	if provider != nil {
		values.Set("provider", *provider)
	}
	if redirect != nil {
		values.Set("redirect", *redirect)
	}
	if sessionState != nil {
		values.Set("sessionState", *sessionState)
	}
	u.RawQuery = values.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// RefreshLoginPath computes a request path to the refresh action of login.
func RefreshLoginPath() string {

	return fmt.Sprintf("/api/login/refresh")
}

// Refresh access token
func (c *Client) RefreshLogin(ctx context.Context, path string, payload *RefreshToken) (*http.Response, error) {
	req, err := c.NewRefreshLoginRequest(ctx, path, payload)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewRefreshLoginRequest create the request corresponding to the refresh action endpoint of the login resource.
func (c *Client) NewRefreshLoginRequest(ctx context.Context, path string, payload *RefreshToken) (*http.Request, error) {
	var body bytes.Buffer
	err := c.Encoder.Encode(payload, &body, "*/*")
	if err != nil {
		return nil, fmt.Errorf("failed to encode body: %s", err)
	}
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("POST", u.String(), &body)
	if err != nil {
		return nil, err
	}
	header := req.Header
	header.Set("Content-Type", "application/json")
	return req, nil
}
