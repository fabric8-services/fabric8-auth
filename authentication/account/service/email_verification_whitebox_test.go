package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
)

func TestVerificationURL(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	r := &goa.RequestData{
		Request: &http.Request{Host: "example.com"},
	}

	c := EmailVerificationClient{}
	url := c.generateVerificationURL(context.Background(), r, "1234")
	assert.Equal(t, "http://example.com/api/users/verifyemail?code=1234", url)
}
