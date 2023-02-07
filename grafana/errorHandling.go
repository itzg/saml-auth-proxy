package grafana

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var PromRoleUpdateErr = promauto.NewCounter(prometheus.CounterOpts{
	Name: "grafana_role_update_errors",
	Help: "Number of user role update error",
})

var PromTimeoutErr = promauto.NewCounter(prometheus.CounterOpts{
	Name: "timeout_errors",
	Help: "Number of user timeout error",
})

func incrementRoleUpdateErrors() {
	PromRoleUpdateErr.Inc()
}

func incrementTimeoutErrors() {
	PromTimeoutErr.Inc()
}
