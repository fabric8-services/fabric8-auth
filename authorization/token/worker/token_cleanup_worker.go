package worker

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/log"
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
			err := w.app.TokenService().CleanupExpiredTokens(w.ctx)
			if err != nil {
				// We will just log the error and continue
				log.Error(nil, map[string]interface{}{
					"err": err,
				}, "error in token cleanup worker")
			}
		case <-w.stopCh:
			w.ticker.Stop()
			return
		}
	}
}

func (w *tokenCleanupWorker) Stop() {
	if w.stopCh != nil {
		w.stopCh <- true
	}
}
