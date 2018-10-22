// Code generated by goagen v1.3.0, DO NOT EDIT.
//
// API "tenant": status Resource Client
//
// Command:
// $ goagen
// --design=github.com/fabric8-services/fabric8-tenant/design
// --notool=true
// --out=$(GOPATH)/src/github.com/fabric8-services/fabric8-auth/authentication/account
// --pkg=tenant
// --version=v1.3.0

package tenant

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// ShowStatusPath computes a request path to the show action of status.
func ShowStatusPath() string {

	return fmt.Sprintf("/api/status")
}

// Show the status of the current running instance
func (c *Client) ShowStatus(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewShowStatusRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewShowStatusRequest create the request corresponding to the show action endpoint of the status resource.
func (c *Client) NewShowStatusRequest(ctx context.Context, path string) (*http.Request, error) {
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
