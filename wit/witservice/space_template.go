// Code generated by goagen v1.2.0, DO NOT EDIT.
//
// API "wit": space_template Resource Client
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
	uuid "github.com/goadesign/goa/uuid"
	"net/http"
	"net/url"
)

// ShowSpaceTemplatePath computes a request path to the show action of space_template.
func ShowSpaceTemplatePath(spaceTemplateID uuid.UUID) string {
	param0 := spaceTemplateID.String()

	return fmt.Sprintf("/api/spacetemplates/%s", param0)
}

// Retrieve space template with given ID
func (c *Client) ShowSpaceTemplate(ctx context.Context, path string) (*http.Response, error) {
	req, err := c.NewShowSpaceTemplateRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(ctx, req)
}

// NewShowSpaceTemplateRequest create the request corresponding to the show action endpoint of the space_template resource.
func (c *Client) NewShowSpaceTemplateRequest(ctx context.Context, path string) (*http.Request, error) {
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
