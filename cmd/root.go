package cmd

import (
	"fmt"
	"github.com/itzg/saml-auth-proxy/server"
	"github.com/jamiealquiza/envy"
	"github.com/spf13/cobra"
	"log"
	"os"
)

var serverConfig server.Config

var rootCmd = &cobra.Command{
	Use:   "saml-auth-proxy",
	Short: "Provides a SAML SP authentication proxy for backend web services",
	Run: func(cmd *cobra.Command, args []string) {
		err := server.Start(&serverConfig)
		log.Fatal(err)
	},
}

func init() {
	rootCmd.Flags().StringVar(&serverConfig.Bind, "bind", ":8080", "host:port to bind for serving HTTP")
	rootCmd.Flags().StringVar(&serverConfig.BaseUrl, "base-url", "", "External URL of this proxy")
	rootCmd.Flags().StringVar(&serverConfig.BackendUrl, "backend-url", "", "URL of the backend being proxied")
	rootCmd.Flags().StringVar(&serverConfig.NewAuthWebhookUrl, "new-auth-webhook-url", "", "URL of webhook that will get POST'ed when a new authentication is processed")
	rootCmd.Flags().StringVar(&serverConfig.IdpMetadataUrl, "idp-metadata-url", "", "URL of the IdP's metadata XML")
	rootCmd.Flags().StringVar(&serverConfig.IdpCaFile, "idp-ca-path", "",
		"Optional path to a CA certificate PEM file for the IdP")
	rootCmd.Flags().StringVar(&serverConfig.NameIdFormat, "name-id-format", "",
		"One of unspecified, transient (default), email, or persistent to use a standard format or give a full URN of the name ID format")
	rootCmd.Flags().StringVar(&serverConfig.SpKeyPath, "sp-key-path", "saml-auth-proxy.key", "Path to the X509 private key PEM file for this SP")
	rootCmd.Flags().StringVar(&serverConfig.SpCertPath, "sp-cert-path", "saml-auth-proxy.cert", "Path to the X509 public certificate PEM file for this SP")
	rootCmd.Flags().StringToStringVar(&serverConfig.AttributeHeaderMappings, "attribute-header-mappings", nil,
		"Comma separated list of attribute=header pairs mapping SAML IdP response attributes to forwarded request header")
	rootCmd.Flags().StringVar(&serverConfig.NameIdHeaderMapping, "name-id-mapping", "",
		"Name of the request header to convey the SAML nameID/subject")
	rootCmd.Flags().StringVar(&serverConfig.AuthorizeAttribute, "authorize-attribute", "",
		"Enables authorization and specifies the attribute to check for authorized values")
	rootCmd.Flags().StringSliceVar(&serverConfig.AuthorizeValues, "authorize-values", []string{},
		"Specifies the possible values that must be present in the authorize attribute")

	_ = rootCmd.MarkFlagRequired("base-url")
	_ = rootCmd.MarkFlagRequired("backend-url")
	_ = rootCmd.MarkFlagRequired("idp-metadata-url")
}

func Execute(version string) {

	rootCmd.Version = version

	cfg := envy.CobraConfig{
		Prefix: "SAML_PROXY",
	}

	envy.ParseCobra(rootCmd, cfg)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
