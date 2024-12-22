package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/itzg/go-flagsfiller"
	"github.com/itzg/saml-auth-proxy/server"
	"github.com/itzg/zapconfigs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

var (
	version = "dev"
	commit  = "HEAD"
)

func main() {
	var serverConfig server.Config

	filler := flagsfiller.New(flagsfiller.WithEnv("SamlProxy"))
	err := filler.Fill(flag.CommandLine, &serverConfig)
	if err != nil {
		log.Fatal(err)
	}

	flag.Parse()

	if serverConfig.Version {
		fmt.Printf("%s %s (%s)\n", os.Args[0], version, commit)
		os.Exit(0)
	}

	var logger *zap.Logger
	if serverConfig.Debug {
		logger = zapconfigs.NewDebugLogger()
	} else {
		logger = zapconfigs.NewDefaultLogger()
	}
	defer logger.Sync()

	checkRequired(serverConfig.BaseUrl, "base-url")
	checkRequired(serverConfig.BackendUrl, "backend-url")
	checkRequired(serverConfig.IdpMetadataUrl, "idp-metadata-url")

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		c := make(chan os.Signal, 1) // we need to reserve to buffer size 1, so the notifier are not blocked
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)

		<-c
		cancel()
	}()

	var bindType, bind = httpBinding(serverConfig.Bind)

	listener, err := net.Listen(bindType, bind)
	if err != nil {
		log.Fatal(err)
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return server.Start(ctx, listener, logger, &serverConfig)
	})

	g.Go(func() error {
		<-gCtx.Done()
		return listener.Close()
	})

	if err := g.Wait(); err != nil {
		fmt.Printf("exit reason: %s \n", err)
	}
}

func checkRequired(value string, name string) {
	if value == "" {
		_, _ = fmt.Fprintf(os.Stderr, "%s is required\n", name)
		flag.Usage()
		os.Exit(2)
	}
}

func httpBinding(bind string) (string, string) {

	if strings.HasPrefix(bind, "unix:") {
		return "unix", strings.TrimLeft(bind, "unix:")
	} else {
		return "tcp", bind
	}

}
