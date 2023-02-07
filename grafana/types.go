package grafana

var GrafanaPermissionToId = map[string]int{
	"none":   0,
	"viewer": 1,
	"editor": 2,
	"admin":  3,
}

var GrafanaIdToPermission = map[int]string{
	0: "none",
	1: "viewer",
	2: "editor",
	3: "admin",
}

type GrafanaOrganizationConfig struct {
	GroupToRole map[string]string `json:"groupToRole"`
}

type GrafanaSamlConfig struct {
	SamlGroupAttributeName   string                            `json:"samlGroupAttributeName"`
	SamlLoginIdAttributeName string                            `json:"samlLoginIdAttributeName"`
	Organizations            map[int]GrafanaOrganizationConfig `json:"organizations"`
}
