package main

import (
	"flag"
	"fmt"
	"github.com/itzg/go-flagsfiller"
	"github.com/itzg/saml-auth-proxy/server"
	"github.com/jamiealquiza/envy"
	"log"
	"os"
)

var (
	version = "dev"
	commit  = "HEAD"
)

func main() {
	var serverConfig server.Config

	filler := flagsfiller.New()
	err := filler.Fill(flag.CommandLine, &serverConfig)
	if err != nil {
		log.Fatal(err)
	}

	envy.Parse("SAML_PROXY")
	flag.Parse()

	if serverConfig.Version {
		fmt.Printf("%s %s (%s)\n", os.Args[0], version, commit)
		os.Exit(0)
	}

	checkRequired(serverConfig.BaseUrl, "base-url")
	checkRequired(serverConfig.BackendUrl, "backend-url")
	checkRequired(serverConfig.IdpMetadataUrl, "idp-metadata-url")

	// server only returns when there's an error
	log.Fatal(server.Start(&serverConfig))
}

func checkRequired(value string, name string) {
	if value == "" {
		_, _ = fmt.Fprintf(os.Stderr, "%s is required\n", name)
		flag.Usage()
		os.Exit(2)
	}
}
