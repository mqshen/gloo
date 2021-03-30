package oauth

import (
	v1 "github.com/solo-io/gloo/projects/gloo/pkg/api/v1"
	"github.com/solo-io/gloo/projects/gloo/pkg/plugins"
)

func BuildHttpFilters(
	listener *v1.HttpListener,
	upstreams v1.UpstreamList,
) ([]plugins.StagedHttpFilter, error) {

	settings := listener.GetOptions().GetOAuth()
	if settings == nil {
		settings = globalSettings
	}
}
