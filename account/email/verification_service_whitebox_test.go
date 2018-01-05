package email

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestVerificationURL(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	r := &goa.RequestData{
		Request: &http.Request{Host: "example.com"},
	}

	c := NewEmailVerificationClient(nil, test.NotificationChannel{})
	url := c.generateVerificationURL(context.Background(), r, "1234")
	assert.Equal(t, "http://example.com/api/users/verifyemail?code=1234", url)
}
