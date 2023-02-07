package grafana

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"
)

var timeoutDurationString string = os.Getenv("GRAFANA_RBAC_CONTROLLER_API_TIMEOUT")
var grafanaRedirectUrl string = os.Getenv("GRAFANA_REDIRECT_URL")

type GrafanaUser struct {
	UserId         string
	AttributeName  string
	AttributeValue []string
}

func NewGrafanaUser(userId string, attributeName string, attributeValue []string) (GrafanaUser, error) {
	// validate inputs
	if false {
		return GrafanaUser{}, nil
	}

	grafanaUser := GrafanaUser{UserId: userId, AttributeName: attributeName, AttributeValue: attributeValue}
	return grafanaUser, nil
}

func CheckUserPermissions(user_id string, attribute_name string, attribute_values []string) {

	// Read the timeout duration of API from env-variable
	timeoutDuration, err := strconv.Atoi(timeoutDurationString)

	// Cancel context after 5s if the converting env-variable to int returns an error
	if err != nil {
		timeoutDuration = DEFAULT_TIMEOUT
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutDuration)*time.Second)
	defer cancel()

	grafanaConfig, err := LoadGrafanaConfig()
	if err != nil {
		fmt.Println("Error in reading org-permission config-file: " + err.Error())
		return
	}

	grafanaUser, err := NewGrafanaUser(user_id, attribute_name, attribute_values)
	if err != nil {
		fmt.Println("error creating user: " + err.Error())
		return
	}

	updateUserChannel := make(chan error, 1)
	go func() {
		updateUserChannel <- grafanaUser.updateUserPermission(grafanaConfig)
	}()

	// Wait for updateUsers to finish execution.
	// Indicate timeout error (thirdPartyAPIErrors) if the function doesn't return within 5s
	select {
	case err := <-updateUserChannel:
		if err != nil {
			fmt.Println("Updating user failed: " + err.Error())
			go func() {
				incrementRoleUpdateErrors()
			}()
		}
	case <-ctx.Done():
		// Once ctx.Done() returns after 5s, user will be redirected to Grafana
		// updateUsers will continue to finish it's processing in the background
		go func() {
			incrementTimeoutErrors()
		}()
	}
}

func getUsersHighestPrivilege(orgId int, userGroups []string, grafanaSamlConfig GrafanaSamlConfig) (string, error) {
	var highestPrivilege int = 0
	for _, groupName := range userGroups {
		if userRole, ok := grafanaSamlConfig.Organizations[orgId].GroupToRole[groupName]; ok {
			currentUserPrivilege := GrafanaPermissionToId[userRole]
			if currentUserPrivilege > highestPrivilege {
				highestPrivilege = currentUserPrivilege
			}
		}
	}

	return GrafanaIdToPermission[highestPrivilege], nil
}

func (grafanaUser *GrafanaUser) updateUserPermission(grafanaConfig GrafanaSamlConfig) error {
	grafanaClient, err := NewGrafanaClient()
	if err != nil {
		return err
	}

	loginId := grafanaUser.UserId
	groups := grafanaUser.AttributeValue

	userNeedsAccess := userShouldHaveAccess(grafanaClient, groups, grafanaConfig)

	userId, getUserError := getGrafanaUserId(grafanaClient, loginId)
	if getUserError != nil && !userNeedsAccess {
		return nil
	}

	// TODO: we need to not delete the user if they do not have any permissions
	// but we want to disable them or make them a set role
	if getUserError == nil && !userNeedsAccess && DEFAULT_DELETE_USERS_WITH_NO_PERMISSIONS {
		deleteUserError := deleteGrafanaUser(grafanaClient, loginId)
		return deleteUserError
	}

	if getUserError != nil && userNeedsAccess {
		newUserId, createUserError := createGrafanaUser(grafanaClient, loginId)
		if createUserError != nil {
			return err
		}

		userId = newUserId
	}

	for orgId := range grafanaConfig.Organizations {
		userRole, err := getUsersHighestPrivilege(orgId, groups, grafanaConfig)
		if err != nil {
			return err
		}

		if GrafanaPermissionToId[userRole] == 0 {
			err = grafanaClient.RemoveOrgUser(int64(orgId), userId)
			return err
		}

		err = grafanaClient.UpdateOrgUser(int64(orgId), userId, userRole)
		if err == nil {
			return nil
		}

		err = grafanaClient.AddOrgUser(int64(orgId), loginId, userRole)
		if err != nil {
			return err
		}
	}

	return nil
}
