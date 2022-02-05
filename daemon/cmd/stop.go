package cmd

import (
	"golang.org/x/sys/unix"
	"os"
	"os/signal"
	"time"

	"tomato.com/watch-dog/internal/neo4j"
	"tomato.com/watch-dog/pkg/logger"

	gops "github.com/google/gops/agent"
	"go.uber.org/zap"
)

func stop() <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, unix.SIGQUIT, unix.SIGINT, unix.SIGHUP, unix.SIGTERM)
	interrupt := make(chan struct{})
	go func() {
		for s := range sig {
			logger.GetLogger().Debug("stop by signal", zap.String("signal", s.String()))
			break
		}
		doCleanup(0)
		close(interrupt)
	}()
	return interrupt
}

func doCleanup(exitCode int) {
	doOnce.Do(func() {
		time.Sleep(3 * time.Second)
		neo4j.Stop()
		gops.Close()
		os.Exit(exitCode)
	})
}
