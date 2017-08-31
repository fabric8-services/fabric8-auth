// Code generated by goagen v1.2.0, DO NOT EDIT.
//
// API "wit": workitemtype Resource Client
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
)

// CreateWorkitemtypePayload is the workitemtype create action payload.
type CreateWorkitemtypePayload struct {
	Data *WorkItemTypeData `form:"data" json:"data" xml:"data"`
	// An array of mixed types
	Included []interface{}      `form:"included,omitempty" json:"included,omitempty" xml:"included,omitempty"`
	Links    *WorkItemTypeLinks `form:"links,omitempty" json:"links,omitempty" xml:"links,omitempty"`
}

// CreateWorkitemtypePath computes a request path to the create action of workitemtype.
func CreateWorkitemtypePath(spaceID uuid.UUID) string {
	param0 := spaceID.String()

	return fmt.Sprintf("/api/spaces/%s/workitemtypes", param0)
}

// Create work item type.
func (c *Client) CreateWorkitemtype(ctx context.Context, path string, payload *CreateWorkitemtypePayload) (*http.Response, error) {
	req, err := c.NewCreateWorkitemtypeRequest(ctx, path, payload)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewCreateWorkitemtypeRequest create the request corresponding to the create action endpoint of the workitemtype resource.
func (c *Client) NewCreateWorkitemtypeRequest(ctx context.Context, path string, payload *CreateWorkitemtypePayload) (*http.Request, error) {
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

// ListWorkitemtypePath computes a request path to the list action of workitemtype.
func ListWorkitemtypePath(spaceID uuid.UUID) string {
	param0 := spaceID.String()

	return fmt.Sprintf("/api/spaces/%s/workitemtypes", param0)
}

// List work item types.
func (c *Client) ListWorkitemtype(ctx context.Context, path string, page *string, ifModifiedSince *string, ifNoneMatch *string) (*http.Response, error) {
	req, err := c.NewListWorkitemtypeRequest(ctx, path, page, ifModifiedSince, ifNoneMatch)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewListWorkitemtypeRequest create the request corresponding to the list action endpoint of the workitemtype resource.
func (c *Client) NewListWorkitemtypeRequest(ctx context.Context, path string, page *string, ifModifiedSince *string, ifNoneMatch *string) (*http.Request, error) {
	scheme := c.Scheme
	if scheme == "" {
		scheme = "http"
	}
	u := url.URL{Host: c.Host, Scheme: scheme, Path: path}
	values := u.Query()
	if page != nil {
		values.Set("page", *page)
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

// ShowWorkitemtypePath computes a request path to the show action of workitemtype.
func ShowWorkitemtypePath(spaceID uuid.UUID, witID uuid.UUID) string {
	param0 := spaceID.String()
	param1 := witID.String()

	return fmt.Sprintf("/api/spaces/%s/workitemtypes/%s", param0, param1)
}

// Retrieve work item type with given ID.
func (c *Client) ShowWorkitemtype(ctx context.Context, path string, ifModifiedSince *string, ifNoneMatch *string) (*http.Response, error) {
	req, err := c.NewShowWorkitemtypeRequest(ctx, path, ifModifiedSince, ifNoneMatch)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewShowWorkitemtypeRequest create the request corresponding to the show action endpoint of the workitemtype resource.
func (c *Client) NewShowWorkitemtypeRequest(ctx context.Context, path string, ifModifiedSince *string, ifNoneMatch *string) (*http.Request, error) {
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
