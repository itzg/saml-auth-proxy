package grafana

import (
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"

	sdk "github.com/grafana/grafana-api-golang-client"
	"golang.org/x/exp/slices"
)

func NewGrafanaClient() (*sdk.Client, error) {

	GRAFANA_URL, grafana_url_is_defined := os.LookupEnv("GRAFANA_URL")
	if !grafana_url_is_defined {
		return nil, errors.New("grafana api url is required")
	}

	GRAFANA_ADMIN_USER, grafana_admin_user_is_defined := os.LookupEnv("GRAFANA_ADMIN_USER")
	if !grafana_admin_user_is_defined {
		return nil, errors.New("grafana admin user is required")
	}

	GRAFANA_ADMIN_PASSWORD, grafana_admin_password_is_defined := os.LookupEnv("GRAFANA_ADMIN_PASSWORD")
	if !grafana_admin_password_is_defined {
		return nil, errors.New("grafana admin password is required")
	}

	grafanaClient, err := sdk.New(GRAFANA_URL, sdk.Config{BasicAuth: url.UserPassword(GRAFANA_ADMIN_USER, GRAFANA_ADMIN_PASSWORD), NumRetries: 2})
	if err != nil {
		fmt.Println("Error connecting to Grafana API server: " + err.Error())
		return nil, err
	}
	return grafanaClient, nil
}

func createGrafanaUser(grafanaClient *sdk.Client, loginId string) (int64, error) {
	var userId int64
	// Generating random password - https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
	password := make([]byte, 10)
	randomInt := rand.Int63()
	for i := 0; i < 10; {
		idx := int(randomInt & 63)
		password[i] = passwordBytes[idx]
		randomInt >>= 6
		i++
	}

	var userDetails = sdk.User{Email: loginId, Password: string(password)}
	user, err := grafanaClient.CreateUser(userDetails)

	if err != nil {
		fmt.Println("Couldn't create user: " + err.Error())
		return -1, err
	}

	fmt.Println("Created new User")
	userId = user

	fmt.Println("User ID: " + fmt.Sprintf("%d", userId))
	return userId, nil
}

func getGrafanaUserId(grafanaClient *sdk.Client, loginId string) (int64, error) {
	var userId int64
	user, err := grafanaClient.UserByEmail(loginId)
	if err != nil {
		return -1, err
	}

	userId = user.ID
	return userId, nil
}

func deleteGrafanaUser(grafanaClient *sdk.Client, loginId string) error {
	userId, getUserError := getGrafanaUserId(grafanaClient, loginId)
	if getUserError != nil {
		fmt.Println("Could not get user: " + getUserError.Error())
		return getUserError
	}

	deleteUserError := grafanaClient.DeleteUser(userId)
	if deleteUserError != nil {
		fmt.Println("Could not delete user: " + deleteUserError.Error())
		return deleteUserError
	}

	return nil
}

func userShouldHaveAccess(grafanaClient *sdk.Client, userGroups []string, grafanaSamlConfig GrafanaSamlConfig) bool {

	grafanaOrgs, err := grafanaClient.Orgs()
	if err != nil {
		fmt.Println("could not get orgs from api")
		return false
	}

	grafanaOrgIds := []int64{}
	for _, org := range grafanaOrgs {
		grafanaOrgIds = append(grafanaOrgIds, org.ID)
	}

	configIds := []int{}
	for orgId, _ := range grafanaSamlConfig.Organizations {
		configIds = append(configIds, orgId)
	}

	intersectedIds := []int{}
	for _, configId := range configIds {
		if slices.Contains(grafanaOrgIds, int64(configId)) {
			intersectedIds = append(intersectedIds, configId)
		}
	}

	for _, orgId := range intersectedIds {
		for _, groupName := range userGroups {
			if _, ok := grafanaSamlConfig.Organizations[orgId].GroupToRole[groupName]; ok {
				return true
			}
		}
	}

	return false
}
