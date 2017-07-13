package space_test

import (
	"testing"

	"context"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/space"

	errs "github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var testResourceID string = uuid.NewV4().String()
var testPolicyID string = uuid.NewV4().String()
var testPermissionID string = uuid.NewV4().String()
var testResource2ID string = uuid.NewV4().String()
var testPolicyID2 string = uuid.NewV4().String()
var testPermissionID2 string = uuid.NewV4().String()

func TestRunResourceRepoBBTest(t *testing.T) {
	suite.Run(t, &resourceRepoBBTest{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

type resourceRepoBBTest struct {
	gormtestsupport.DBTestSuite
	repo  space.ResourceRepository
	clean func()
}

func (test *resourceRepoBBTest) SetupTest() {
	test.repo = space.NewResourceRepository(test.DB)
	test.clean = cleaner.DeleteCreatedEntities(test.DB)
}

func (test *resourceRepoBBTest) TearDownTest() {
	test.clean()
}

func (test *resourceRepoBBTest) TestCreate() {
	res, _ := expectResource(test.create(testResourceID, testPolicyID, testPermissionID), test.requireOk)
	require.Equal(test.T(), res.PolicyID, testPolicyID)
	require.Equal(test.T(), res.PermissionID, testPermissionID)
	require.Equal(test.T(), res.ResourceID, testResourceID)

}

func (test *resourceRepoBBTest) TestLoad() {
	expectResource(test.load(uuid.NewV4()), test.assertNotFound())
	res, _ := expectResource(test.create(testResourceID, testPolicyID, testPermissionID), test.requireOk)

	res2, _ := expectResource(test.load(res.ID), test.requireOk)
	assert.True(test.T(), (*res).Equal(*res2))
}

func (test *resourceRepoBBTest) TestExistsSpaceResource() {
	t := test.T()
	resource.Require(t, resource.Database)

	t.Run("space resource exists", func(t *testing.T) {
		// given
		expectResource(test.load(uuid.NewV4()), test.assertNotFound())
		res, _ := expectResource(test.create(testResourceID, testPolicyID, testPermissionID), test.requireOk)

		err := test.repo.CheckExists(context.Background(), res.ID.String())
		require.Nil(t, err)
	})

	t.Run("space resource doesn't exist", func(t *testing.T) {
		err := test.repo.CheckExists(context.Background(), uuid.NewV4().String())

		require.IsType(t, errors.NotFoundError{}, err)
	})
}

func (test *resourceRepoBBTest) TestSaveOk() {
	res, _ := expectResource(test.create(testResourceID, testPolicyID, testPermissionID), test.requireOk)

	newResourceID := uuid.NewV4().String()
	newPermissionID := uuid.NewV4().String()
	newPolicyID := uuid.NewV4().String()
	res.PermissionID = newPermissionID
	res.PolicyID = newPolicyID
	res.ResourceID = newResourceID
	res2, _ := expectResource(test.save(*res), test.requireOk)
	assert.Equal(test.T(), newPermissionID, res2.PermissionID)
	assert.Equal(test.T(), newPolicyID, res2.PolicyID)
	assert.Equal(test.T(), newResourceID, res2.ResourceID)
}

func (test *resourceRepoBBTest) TestSaveNew() {
	p := space.Resource{
		ID:           uuid.NewV4(),
		ResourceID:   testResourceID,
		PolicyID:     testPolicyID,
		PermissionID: testPermissionID,
	}

	expectResource(test.save(p), test.requireErrorType(errors.NotFoundError{}))
}

func (test *resourceRepoBBTest) TestDelete() {
	res, _ := expectResource(test.create(testResourceID, testPolicyID, testPermissionID), test.requireOk)
	expectResource(test.load(res.ID), test.requireOk)
	expectResource(test.delete(res.ID), func(p *space.Resource, err error) { require.Nil(test.T(), err) })
	expectResource(test.load(res.ID), test.assertNotFound())
	expectResource(test.delete(uuid.NewV4()), test.assertNotFound())
	expectResource(test.delete(uuid.Nil), test.assertNotFound())
}

func (test *resourceRepoBBTest) TestLoadBySpace() {
	expectResource(test.load(uuid.NewV4()), test.assertNotFound())
	res, _ := expectResource(test.create(testResourceID, testPolicyID, testPermissionID), test.requireOk)

	res2, _ := expectResource(test.loadBySpace(s.ID), test.requireOk)
	assert.True(test.T(), (*res).Equal(*res2))
}

func (test *resourceRepoBBTest) TestLoadByDifferentSpaceFails() {
	test.create(testResourceID, testPolicyID, testPermissionID)

	_, err := expectResource(test.loadBySpace(uuid.NewV4()), test.requireErrorType(errors.NotFoundError{}))
	assert.NotNil(test.T(), err)
}

type resourceExpectation func(p *space.Resource, err error)

func expectResource(f func() (*space.Resource, error), e resourceExpectation) (*space.Resource, error) {
	p, err := f()
	e(p, err)
	return p, errs.WithStack(err)
}

func (test *resourceRepoBBTest) requireOk(p *space.Resource, err error) {
	assert.NotNil(test.T(), p)
	require.Nil(test.T(), err)
}

func (test *resourceRepoBBTest) assertNotFound() func(p *space.Resource, err error) {
	return test.assertErrorType(errors.NotFoundError{})
}

func (test *resourceRepoBBTest) assertErrorType(e error) func(p *space.Resource, e2 error) {
	return func(p *space.Resource, err error) {
		assert.Nil(test.T(), p)
		assert.IsType(test.T(), e, err, "error was %v", err)
	}
}

func (test *resourceRepoBBTest) requireErrorType(e error) func(p *space.Resource, err error) {
	return func(p *space.Resource, err error) {
		assert.Nil(test.T(), p)
		require.IsType(test.T(), e, err)
	}
}

func (test *resourceRepoBBTest) create(resourceID string, policyID string, permissionID string) func() (*space.Resource, error) {
	newResource := space.Resource{
		ResourceID:   resourceID,
		PolicyID:     policyID,
		PermissionID: permissionID,
		SpaceID: uuid.NewV4(),
	}
	return func() (*space.Resource, error) {
		r, err := test.repo.Create(context.Background(), &newResource)
		return r, err
	}
}

func (test *resourceRepoBBTest) save(p space.Resource) func() (*space.Resource, error) {
	return func() (*space.Resource, error) {
		r, err := test.repo.Save(context.Background(), &p)
		return r, err
	}
}

func (test *resourceRepoBBTest) load(id uuid.UUID) func() (*space.Resource, error) {
	return func() (*space.Resource, error) {
		r, err := test.repo.Load(context.Background(), id)
		return r, err
	}
}

func (test *resourceRepoBBTest) loadBySpace(spaceID uuid.UUID) func() (*space.Resource, error) {
	return func() (*space.Resource, error) {
		r, err := test.repo.LoadBySpace(context.Background(), &spaceID)
		return r, err
	}
}

func (test *resourceRepoBBTest) delete(id uuid.UUID) func() (*space.Resource, error) {
	return func() (*space.Resource, error) {
		err := test.repo.Delete(context.Background(), id)
		return nil, err
	}
}
