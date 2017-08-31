// Code generated by goagen v1.2.0, DO NOT EDIT.
//
// API "wit": collaborators Resource Client
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
	uuid "github.com/goadesign/goa/uuid"
	"net/http"
	"net/url"
	"strconv"
)

// AddCollaboratorsPath computes a request path to the add action of collaborators.
func AddCollaboratorsPath(spaceID uuid.UUID, identityID string) string {
	param0 := spaceID.String()
	param1 := identityID

	return fmt.Sprintf("/api/spaces/%s/collaborators/%s", param0, param1)
}

// Add a user to the list of space collaborators.
func (c *Client) AddCollaborators(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewAddCollaboratorsRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewAddCollaboratorsRequest create the request corresponding to the add action endpoint of the collaborators resource.
func (c *Client) NewAddCollaboratorsRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.JWTSigner != nil {
		c.JWTSigner.Sign(req)
	}
	return req, nil
}

// AddManyCollaboratorsPayload is the collaborators add-many action payload.
type AddManyCollaboratorsPayload struct {
	Data []*UpdateUserID `form:"data" json:"data" xml:"data"`
	// An array of mixed types
	Included []interface{} `form:"included,omitempty" json:"included,omitempty" xml:"included,omitempty"`
}

// AddManyCollaboratorsPath computes a request path to the add-many action of collaborators.
func AddManyCollaboratorsPath(spaceID uuid.UUID) string {
	param0 := spaceID.String()

	return fmt.Sprintf("/api/spaces/%s/collaborators", param0)
}

// Add users to the list of space collaborators.
func (c *Client) AddManyCollaborators(ctx context.Context, path string, payload *AddManyCollaboratorsPayload) (*http.Response, error) {
	req, err := c.NewAddManyCollaboratorsRequest(ctx, path, payload)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewAddManyCollaboratorsRequest create the request corresponding to the add-many action endpoint of the collaborators resource.
func (c *Client) NewAddManyCollaboratorsRequest(ctx context.Context, path string, payload *AddManyCollaboratorsPayload) (*http.Request, error) {
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
	if c.JWTSigner != nil {
		c.JWTSigner.Sign(req)
	}
	return req, nil
}

// ListCollaboratorsPath computes a request path to the list action of collaborators.
func ListCollaboratorsPath(spaceID uuid.UUID) string {
	param0 := spaceID.String()

	return fmt.Sprintf("/api/spaces/%s/collaborators", param0)
}

// List collaborators for the given space ID.
func (c *Client) ListCollaborators(ctx context.Context, path string, pageLimit *int, pageOffset *string, ifModifiedSince *string, ifNoneMatch *string) (*http.Response, error) {
	req, err := c.NewListCollaboratorsRequest(ctx, path, pageLimit, pageOffset, ifModifiedSince, ifNoneMatch)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewListCollaboratorsRequest create the request corresponding to the list action endpoint of the collaborators resource.
func (c *Client) NewListCollaboratorsRequest(ctx context.Context, path string, pageLimit *int, pageOffset *string, ifModifiedSince *string, ifNoneMatch *string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	values := u.Query()
	if pageLimit != nil {
		tmp1 := strconv.Itoa(*pageLimit)
		values.Set("page[limit]", tmp1)
	}
	if pageOffset != nil {
		values.Set("page[offset]", *pageOffset)
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

// RemoveCollaboratorsPath computes a request path to the remove action of collaborators.
func RemoveCollaboratorsPath(spaceID uuid.UUID, identityID string) string {
	param0 := spaceID.String()
	param1 := identityID

	return fmt.Sprintf("/api/spaces/%s/collaborators/%s", param0, param1)
}

// Remove a user from the list of space collaborators.
func (c *Client) RemoveCollaborators(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewRemoveCollaboratorsRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewRemoveCollaboratorsRequest create the request corresponding to the remove action endpoint of the collaborators resource.
func (c *Client) NewRemoveCollaboratorsRequest(ctx context.Context, path string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.JWTSigner != nil {
		c.JWTSigner.Sign(req)
	}
	return req, nil
}

// RemoveManyCollaboratorsPayload is the collaborators remove-many action payload.
type RemoveManyCollaboratorsPayload struct {
	Data []*UpdateUserID `form:"data" json:"data" xml:"data"`
	// An array of mixed types
	Included []interface{} `form:"included,omitempty" json:"included,omitempty" xml:"included,omitempty"`
}

// RemoveManyCollaboratorsPath computes a request path to the remove-many action of collaborators.
func RemoveManyCollaboratorsPath(spaceID uuid.UUID) string {
	param0 := spaceID.String()

	return fmt.Sprintf("/api/spaces/%s/collaborators", param0)
}

// Remove users form the list of space collaborators.
func (c *Client) RemoveManyCollaborators(ctx context.Context, path string, payload *RemoveManyCollaboratorsPayload) (*http.Response, error) {
	req, err := c.NewRemoveManyCollaboratorsRequest(ctx, path, payload)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewRemoveManyCollaboratorsRequest create the request corresponding to the remove-many action endpoint of the collaborators resource.
func (c *Client) NewRemoveManyCollaboratorsRequest(ctx context.Context, path string, payload *RemoveManyCollaboratorsPayload) (*http.Request, error) {
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
	req, err := http.NewRequest("DELETE", u.String(), &body)
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
