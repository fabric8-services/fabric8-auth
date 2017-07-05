package application

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/area"
	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/codebase"

	"github.com/fabric8-services/fabric8-auth/comment"
	"github.com/fabric8-services/fabric8-auth/iteration"
	"github.com/fabric8-services/fabric8-auth/space"
	"github.com/fabric8-services/fabric8-auth/workitem"
	"github.com/fabric8-services/fabric8-auth/workitem/link"
)

//An Application stands for a particular implementation of the business logic of our application
type Application interface {
	WorkItems() workitem.WorkItemRepository
	WorkItemTypes() workitem.WorkItemTypeRepository
	Trackers() TrackerRepository
	TrackerQueries() TrackerQueryRepository
	SearchItems() SearchRepository
	Identities() account.IdentityRepository
	WorkItemLinkCategories() link.WorkItemLinkCategoryRepository
	WorkItemLinkTypes() link.WorkItemLinkTypeRepository
	WorkItemLinks() link.WorkItemLinkRepository
	Comments() comment.Repository
	Spaces() space.Repository
	SpaceResources() space.ResourceRepository
	Iterations() iteration.Repository
	Users() account.UserRepository
	Areas() area.Repository
	OauthStates() auth.OauthStateReferenceRepository
	Codebases() codebase.Repository
}

// A Transaction abstracts a database transaction. The repositories created for the transaction object make changes inside the the transaction
type Transaction interface {
	Application
	Commit() error
	Rollback() error
}

// A DB stands for a particular database (or a mock/fake thereof). It also includes "Application" for creating transactionless repositories
type DB interface {
	Application
	BeginTransaction() (Transaction, error)
}
