package account_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authentication/account"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/stretchr/testify/assert"
)

func TestGenerateFullName(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	firstName := "john"
	middleName := "doe"
	lastname := "mike brown"
	name := account.GenerateFullName(&firstName, &middleName, &lastname)
	assert.Equal(t, "john doe mike brown", name)

	name = account.GenerateFullName(&firstName, nil, &lastname)
	assert.Equal(t, "john mike brown", name)

	name = account.GenerateFullName(&firstName)
	assert.Equal(t, "john", name)

	name = account.GenerateFullName(nil, &middleName, &lastname)
	assert.Equal(t, "doe mike brown", name)

	name = account.GenerateFullName(&lastname)
	assert.Equal(t, "mike brown", name)
}

func TestSplitFullName(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	fullName := "john doe"
	firstName, lastName := account.SplitFullName(fullName)
	assert.Equal(t, "john", firstName)
	assert.Equal(t, "doe", lastName)

	fullName = "john doe mike  brown"
	firstName, lastName = account.SplitFullName(fullName)
	assert.Equal(t, "john", firstName)
	assert.Equal(t, "doe mike  brown", lastName)

	fullName = "john, doe mike  brown"
	firstName, lastName = account.SplitFullName(fullName)
	assert.Equal(t, "john,", firstName)
	assert.Equal(t, "doe mike  brown", lastName)

	fullName = "john"
	firstName, lastName = account.SplitFullName(fullName)
	assert.Equal(t, "john", firstName)
	assert.Equal(t, "", lastName)

	fullName = ""
	firstName, lastName = account.SplitFullName(fullName)
	assert.Equal(t, "", firstName)
	assert.Equal(t, "", lastName)
}
