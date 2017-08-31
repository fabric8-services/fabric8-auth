// Code generated by goagen v1.2.0, DO NOT EDIT.
//
// API "wit": users Resource Client
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

// ListUsersPath computes a request path to the list action of users.
func ListUsersPath() string {

	return fmt.Sprintf("/api/users")
}

// List all users.
func (c *Client) ListUsers(ctx context.Context, path string, filterEmail *string, filterRegistrationCompleted *bool, filterUsername *string, ifModifiedSince *string, ifNoneMatch *string) (*http.Response, error) {
	req, err := c.NewListUsersRequest(ctx, path, filterEmail, filterRegistrationCompleted, filterUsername, ifModifiedSince, ifNoneMatch)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewListUsersRequest create the request corresponding to the list action endpoint of the users resource.
func (c *Client) NewListUsersRequest(ctx context.Context, path string, filterEmail *string, filterRegistrationCompleted *bool, filterUsername *string, ifModifiedSince *string, ifNoneMatch *string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	values := u.Query()
	if filterEmail != nil {
		values.Set("filter[email]", *filterEmail)
	}
	if filterRegistrationCompleted != nil {
		tmp12 := strconv.FormatBool(*filterRegistrationCompleted)
		values.Set("filter[registrationCompleted]", tmp12)
	}
	if filterUsername != nil {
		values.Set("filter[username]", *filterUsername)
	}
	u.RawQuery = values.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	header := req.Header
	if ifModifiedSince != nil {

		header.Set("If-Modified-Since", *ifModifiedSince)
	}
	if ifNoneMatch != nil {

		header.Set("If-None-Match", *ifNoneMatch)
	}
	return req, nil
}

// ShowUsersPath computes a request path to the show action of users.
func ShowUsersPath(id string) string {
	param0 := id

	return fmt.Sprintf("/api/users/%s", param0)
}

// Retrieve user for the given ID.
func (c *Client) ShowUsers(ctx context.Context, path string, ifModifiedSince *string, ifNoneMatch *string) (*http.Response, error) {
	req, err := c.NewShowUsersRequest(ctx, path, ifModifiedSince, ifNoneMatch)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewShowUsersRequest create the request corresponding to the show action endpoint of the users resource.
func (c *Client) NewShowUsersRequest(ctx context.Context, path string, ifModifiedSince *string, ifNoneMatch *string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	header := req.Header
	if ifModifiedSince != nil {

		header.Set("If-Modified-Since", *ifModifiedSince)
	}
	if ifNoneMatch != nil {

		header.Set("If-None-Match", *ifNoneMatch)
	}
	return req, nil
}

// UpdateUsersPayload is the users update action payload.
type UpdateUsersPayload struct {
	Data *UpdateUserData `form:"data" json:"data" xml:"data"`
}

// UpdateUsersPath computes a request path to the update action of users.
func UpdateUsersPath() string {

	return fmt.Sprintf("/api/users")
}

// update the authenticated user
func (c *Client) UpdateUsers(ctx context.Context, path string, payload *UpdateUsersPayload) (*http.Response, error) {
	req, err := c.NewUpdateUsersRequest(ctx, path, payload)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewUpdateUsersRequest create the request corresponding to the update action endpoint of the users resource.
func (c *Client) NewUpdateUsersRequest(ctx context.Context, path string, payload *UpdateUsersPayload) (*http.Request, error) {
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
	req, err := http.NewRequest("PATCH", u.String(), &body)
	if err != nil {
		return nil, err
	}
	header := req.Header
	header.Set("Content-Type", "application/json")
	if c.JWTSigner != nil {
		c.JWTSigner.Sign(req)
	}
	return req, nil
}
