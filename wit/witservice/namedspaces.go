// Code generated by goagen v1.2.0, DO NOT EDIT.
//
// API "wit": namedspaces Resource Client
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
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// ListNamedspacesPath computes a request path to the list action of namedspaces.
func ListNamedspacesPath(userName string) string {
	param0 := userName

	return fmt.Sprintf("/api/namedspaces/%s", param0)
}

// List spaces owned by a user.
func (c *Client) ListNamedspaces(ctx context.Context, path string, pageLimit *int, pageOffset *string) (*http.Response, error) {
	req, err := c.NewListNamedspacesRequest(ctx, path, pageLimit, pageOffset)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewListNamedspacesRequest create the request corresponding to the list action endpoint of the namedspaces resource.
func (c *Client) NewListNamedspacesRequest(ctx context.Context, path string, pageLimit *int, pageOffset *string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	values := u.Query()
	if pageLimit != nil {
		tmp3 := strconv.Itoa(*pageLimit)
		values.Set("page[limit]", tmp3)
	}
	if pageOffset != nil {
		values.Set("page[offset]", *pageOffset)
	}
	u.RawQuery = values.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// ShowNamedspacesPath computes a request path to the show action of namedspaces.
func ShowNamedspacesPath(userName string, spaceName string) string {
	param0 := userName
	param1 := spaceName

	return fmt.Sprintf("/api/namedspaces/%s/%s", param0, param1)
}

// Retrieve space (as JSONAPI) for the given user name and space name.
func (c *Client) ShowNamedspaces(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewShowNamedspacesRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewShowNamedspacesRequest create the request corresponding to the show action endpoint of the namedspaces resource.
func (c *Client) NewShowNamedspacesRequest(ctx context.Context, path string) (*http.Request, error) {
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
