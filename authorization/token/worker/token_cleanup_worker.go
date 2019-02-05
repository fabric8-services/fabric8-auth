package worker

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/application"
	"time"
)

type TokenCleanupWorker interface {
	Start(ticker *time.Ticker)
	Stop()
}

func NewTokenCleanupWorker(ctx context.Context, app application.Application) TokenCleanupWorker {
	return &tokenCleanupWorker{
		ctx: ctx,
		app: app,
	}
}

type tokenCleanupWorker struct {
	ctx    context.Context
	app    application.Application
	ticker *time.Ticker
	stopCh chan bool
}

func (w *tokenCleanupWorker) Start(ticker *time.Ticker) {
	w.ticker = ticker
	w.stopCh = make(chan bool, 1)

	go w.cleanupLoop()
}

func (w *tokenCleanupWorker) cleanupLoop() {
	for {
		select {
		case <-w.ticker.C:
			w.app.TokenService().CleanupExpiredTokens(w.ctx)
		case <-w.stopCh:
			w.ticker.Stop()
			return
		}
	}
}

func (c *tokenCleanupWorker) Stop() {
	if c.stopCh != nil {
		c.stopCh <- true
	}
}
