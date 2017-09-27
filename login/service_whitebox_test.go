package login

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/token"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGravatarURLGeneration(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)
	grURL, err := generateGravatarURL("alkazako@redhat.com")
	assert.Nil(t, err)
	assert.Equal(t, "https://www.gravatar.com/avatar/0fa6cfaa2812a200c566f671803cdf2d.jpg", grURL)
}

func TestFillUserDoesntOverwriteExistingImageURL(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	identity := &account.Identity{Username: "vaysa", User: account.User{FullName: "Vasya Pupkin", Company: "Red Hat", Email: "vpupkin@mail.io", ImageURL: "http://vpupkin.io/image.jpg"}}
	claims := &token.TokenClaims{Username: "new username", Name: "new name", Company: "new company", Email: "new email"}
	isChanged, err := fillUser(claims, identity)
	require.Nil(t, err)
	require.True(t, isChanged)
	assert.Equal(t, "new name", identity.User.FullName)
	assert.Equal(t, "new company", identity.User.Company)
	assert.Equal(t, "new email", identity.User.Email)
	assert.Equal(t, "new username", identity.Username)
	assert.Equal(t, "http://vpupkin.io/image.jpg", identity.User.ImageURL)
}
