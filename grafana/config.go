package grafana

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

var passwordBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890%#"

func LoadGrafanaConfig() (GrafanaSamlConfig, error) {

	GRAFANA_SAML_CONFIG_LOCATION, grafana_saml_config_location_is_defined := os.LookupEnv("GRAFANA_SAML_CONFIG_LOCATION")

	if !grafana_saml_config_location_is_defined {
		GRAFANA_SAML_CONFIG_LOCATION = DEFAULT_GRAFANA_SAML_CONFIG_LOCATION
	}

	jsonFile, err := os.Open(GRAFANA_SAML_CONFIG_LOCATION)
	if err != nil {
		return GrafanaSamlConfig{}, err
	}
	defer jsonFile.Close()

	var result GrafanaSamlConfig
	if err != nil {
		var result GrafanaSamlConfig
		return result, err

	} else {
		byteValue, err := ioutil.ReadAll(jsonFile)
		if err != nil {
			return result, err
		}
		err = json.Unmarshal([]byte(byteValue), &result)
		if err != nil {
			return result, err
		}
		return result, nil
	}
}
