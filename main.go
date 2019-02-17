package main

import (
	"github.com/itzg/saml-auth-proxy/cmd"
)

var (
	version = "dev"
	commit  = "HEAD"
)

func main() {
	// delegate all the init work to cobra
	cmd.Execute(version + "-" + commit)
}
