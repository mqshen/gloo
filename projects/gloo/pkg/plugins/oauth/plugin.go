package oauth

import (
	"context"

	envoy_v31 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_oauth "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/oauth2/v3alpha"
	envoy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_v32 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/rotisserie/eris"
	gloo_v31 "github.com/solo-io/gloo/projects/gloo/api/external/envoy/config/core/v3"
	v3alpha "github.com/solo-io/gloo/projects/gloo/api/external/envoy/extensions/filters/http/oauth2/v3alpha"
	gloo_v3 "github.com/solo-io/gloo/projects/gloo/api/external/envoy/extensions/transport_sockets/tls/v3"
	v32 "github.com/solo-io/gloo/projects/gloo/api/external/envoy/type/matcher/v3"
	gloo_config_v3 "github.com/solo-io/gloo/projects/gloo/pkg/api/external/envoy/config/core/v3"
	gloo_type_matcher "github.com/solo-io/gloo/projects/gloo/pkg/api/external/envoy/type/matcher/v3"
	v1 "github.com/solo-io/gloo/projects/gloo/pkg/api/v1"
	"github.com/solo-io/gloo/projects/gloo/pkg/plugins"
	"github.com/solo-io/gloo/projects/gloo/pkg/plugins/pluginutils"
)

// Compile-time assertion
var (
	_ plugins.Plugin            = new(plugin)
	_ plugins.VirtualHostPlugin = new(plugin)
	_ plugins.RoutePlugin       = new(plugin)
	_ plugins.Upgradable        = new(plugin)
)

const FilterName = "envoy.filters.http.oauth2"

const (
	ErrEnterpriseOnly = "Could not load oauth plugin - this is an Enterprise feature"
	ExtensionName     = "oauth"
)

type plugin struct{}

func NewPlugin() *plugin {
	return &plugin{}
}

func (p *plugin) PluginName() string {
	return ExtensionName
}

func (p *plugin) IsUpgrade() bool {
	return false
}

func (p *plugin) Init(params plugins.InitParams) error {
	return nil
}

func (p *plugin) ProcessVirtualHost(
	params plugins.VirtualHostParams,
	in *v1.VirtualHost,
	out *envoy_config_route.VirtualHost,
) error {
	if in.GetOptions().GetJwtConfig() != nil {
		return eris.New(ErrEnterpriseOnly)
	}

	return nil
}

func (p *plugin) ProcessRoute(params plugins.RouteParams, in *v1.Route, out *envoy_config_route.Route) error {
	oauth2 := in.GetOptions().GetOauth()
	if oauth2 == nil {
		return nil
	}

	envoyCsrfConfig, err := translateOAuthConfig(params.Params.Ctx, oauth2)
	if err != nil {
		return err
	}

	return pluginutils.SetRoutePerFilterConfig(out, FilterName, envoyCsrfConfig)
}

func translateOAuthConfig(ctx context.Context, oauth *v3alpha.OAuth2) (*envoy_oauth.OAuth2, error) {
	envoyOAuth := &envoy_oauth.OAuth2{
		Config: translateConfig(ctx, oauth.GetConfig()),
	}
	return envoyOAuth, envoyOAuth.Validate()
}

func translateConfig(ctx context.Context, config *v3alpha.OAuth2Config) *envoy_oauth.OAuth2Config {

	oAuth2Credentials := &envoy_oauth.OAuth2Credentials{
		ClientId:    config.GetCredentials().ClientId,
		TokenSecret: translateTokenSecret(config.GetCredentials().GetTokenSecret()),
	}
	translateTokenFormation(config.GetCredentials(), oAuth2Credentials)
	envoyOAuth := &envoy_oauth.OAuth2Config{
		TokenEndpoint: &envoy_v31.HttpUri{
			Uri: config.GetTokenEndpoint().GetUri(),
			HttpUpstreamType: &envoy_v31.HttpUri_Cluster{
				Cluster: config.GetTokenEndpoint().GetCluster(),
			},
			Timeout: config.GetTokenEndpoint().GetTimeout(),
		},
		AuthorizationEndpoint: config.GetAuthorizationEndpoint(),
		RedirectUri:           config.GetRedirectUri(),
		Credentials:           oAuth2Credentials,
	}
	envoyOAuth.RedirectPathMatcher = translatePathMatcher(config.GetRedirectPathMatcher())
	envoyOAuth.SignoutPath = translatePathMatcher(config.GetSignoutPath())

	return envoyOAuth
}

func translatePathMatcher(in *v32.PathMatcher) *envoy_v32.PathMatcher {
	switch path := in.GetRule().(type) {
	case *v32.PathMatcher_Path:
		switch pathTyped := path.Path.GetMatchPattern().(type) {
		case *gloo_type_matcher.StringMatcher_Exact:
			return &envoy_v32.PathMatcher{
				Rule: &envoy_v32.PathMatcher_Path{
					Path: &envoy_v32.StringMatcher{
						MatchPattern: &envoy_v32.StringMatcher_Exact{
							Exact: pathTyped.Exact,
						},
						IgnoreCase: path.Path.GetIgnoreCase(),
					},
				},
			}
		case *gloo_type_matcher.StringMatcher_Prefix:
			return &envoy_v32.PathMatcher{
				Rule: &envoy_v32.PathMatcher_Path{
					Path: &envoy_v32.StringMatcher{
						MatchPattern: &envoy_v32.StringMatcher_Prefix{
							Prefix: pathTyped.Prefix,
						},
						IgnoreCase: path.Path.GetIgnoreCase(),
					},
				},
			}
		case *gloo_type_matcher.StringMatcher_Suffix:
			return &envoy_v32.PathMatcher{
				Rule: &envoy_v32.PathMatcher_Path{
					Path: &envoy_v32.StringMatcher{
						MatchPattern: &envoy_v32.StringMatcher_Suffix{
							Suffix: pathTyped.Suffix,
						},
						IgnoreCase: path.Path.GetIgnoreCase(),
					},
				},
			}
		case *gloo_type_matcher.StringMatcher_SafeRegex:
			return &envoy_v32.PathMatcher{
				Rule: &envoy_v32.PathMatcher_Path{
					Path: &envoy_v32.StringMatcher{
						MatchPattern: &envoy_v32.StringMatcher_SafeRegex{
							SafeRegex: &envoy_v32.RegexMatcher{
								EngineType: &envoy_v32.RegexMatcher_GoogleRe2{
									GoogleRe2: &envoy_v32.RegexMatcher_GoogleRE2{},
								},
								Regex: pathTyped.SafeRegex.GetRegex(),
							},
						},
						IgnoreCase: path.Path.GetIgnoreCase(),
					},
				},
			}
		}
	}
	return nil
}

func translateTokenSecret(in *gloo_v3.SdsSecretConfig) *envoy_v3.SdsSecretConfig {
	sdsConfig := &envoy_v31.ConfigSource{
		ResourceApiVersion: envoy_v31.ApiVersion_V3,
	}
	switch typed := in.SdsConfig.GetConfigSourceSpecifier().(type) {
	case *gloo_v31.ConfigSource_Path:
		sdsConfig.ConfigSourceSpecifier = &envoy_v31.ConfigSource_Path{
			Path: typed.Path,
		}
	case *gloo_v31.ConfigSource_ApiConfigSource:
		sdsConfig.ConfigSourceSpecifier = &envoy_v31.ConfigSource_ApiConfigSource{
			ApiConfigSource: &envoy_v31.ApiConfigSource{
				ApiType:             envoy_v31.ApiConfigSource_GRPC,
				TransportApiVersion: envoy_v31.ApiVersion_V3,
				GrpcServices:        translateGrpcServices(typed.ApiConfigSource.GrpcServices),
			},
		}
	}
	return &envoy_v3.SdsSecretConfig{
		Name:      in.GetName(),
		SdsConfig: sdsConfig,
	}
}

func translateTokenFormation(in *v3alpha.OAuth2Credentials, out *envoy_oauth.OAuth2Credentials) {
	switch typed := in.GetTokenFormation().(type) {
	case *v3alpha.OAuth2Credentials_HmacSecret:
		out.TokenFormation = &envoy_oauth.OAuth2Credentials_HmacSecret{
			HmacSecret: translateTokenSecret(typed.HmacSecret),
		}
	}
}

func translateGrpcServices(glooService []*gloo_config_v3.GrpcService) []*envoy_v31.GrpcService {

	var results []*envoy_v31.GrpcService

	for _, gs := range glooService {
		switch typed := gs.GetTargetSpecifier().(type) {
		case *gloo_config_v3.GrpcService_EnvoyGrpc_:
			results = append(results, &envoy_v31.GrpcService{
				TargetSpecifier: &envoy_v31.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &envoy_v31.GrpcService_EnvoyGrpc{
						ClusterName: typed.EnvoyGrpc.ClusterName,
					},
				},
			})
		}
	}
	return results
}
