package setuputils

import (
	"flag"
	"os"

	"github.com/solo-io/gloo/projects/gloo/pkg/defaults"
)

const (
	PodNamespace = "POD_NAMESPACE"
)

var (
	setupNamespace string
	setupName      string
	setupDir       string
	logLevel       string
)

// TODO (ilackarms): move to a flags package
func init() {

	// Allow for more dynamic setting of settings namespace
	// Based on article https://kubernetes.io/docs/tasks/inject-data-application/environment-variable-expose-pod-information/#the-downward-api
	defaultNamespace := os.Getenv(PodNamespace)
	if defaultNamespace == "" {
		defaultNamespace = defaults.GlooSystem
	}
	flag.StringVar(&setupNamespace, "namespace", defaultNamespace, "namespace to watch for settings crd/file")
	flag.StringVar(&setupName, "name", defaults.SettingsName, "name of settings crd/file to use")
	flag.StringVar(&setupDir, "dir", "",
		"directory to find bootstrap settings if not using kubernetes crds")
	flag.StringVar(&logLevel, "loglevel", "info", "setup zap log level")
}
