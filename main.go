package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"saml-auth-proxy/server"

	"github.com/itzg/go-flagsfiller"
	"github.com/itzg/zapconfigs"
	"go.uber.org/zap"
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

	ctx := context.Background()

	// server only returns when there's an error
	log.Fatal(server.Start(ctx, logger, &serverConfig))
}

func checkRequired(value string, name string) {
	if value == "" {
		_, _ = fmt.Fprintf(os.Stderr, "%s is required\n", name)
		flag.Usage()
		os.Exit(2)
	}
}
