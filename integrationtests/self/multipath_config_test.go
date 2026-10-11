package self_test

import (
	"errors"
	"testing"

	quic "github.com/AeonDave/mp-quic-go"

	"github.com/stretchr/testify/require"
)

// The -multipath flag configures a multipath controller on both endpoints, the client or the server.
// The setting for the server applies to the config used for every connection: the listener's config,
// the config returned by the test's GetConfigForClient, and the default config if it returns nil.
func TestConfigureMultipath(t *testing.T) {
	// serverConfig returns the config that the server uses for a new connection.
	serverConfig := func(t *testing.T, conf *quic.Config) *quic.Config {
		t.Helper()
		if conf.GetConfigForClient == nil {
			return conf
		}
		c, err := conf.GetConfigForClient(&quic.ClientInfo{})
		require.NoError(t, err)
		if c == nil {
			return &quic.Config{}
		}
		return c
	}
	testConfigs := map[string]func() *quic.Config{
		"no GetConfigForClient": func() *quic.Config { return &quic.Config{} },
		"GetConfigForClient returns nil": func() *quic.Config {
			return &quic.Config{GetConfigForClient: func(*quic.ClientInfo) (*quic.Config, error) { return nil, nil }}
		},
		"GetConfigForClient returns a config": func() *quic.Config {
			return &quic.Config{GetConfigForClient: func(*quic.ClientInfo) (*quic.Config, error) {
				return &quic.Config{EnableDatagrams: true}, nil
			}}
		},
	}
	for _, endpoints := range []string{"", "both", "client", "server"} {
		for name, newConfig := range testConfigs {
			t.Run(endpoints+"/"+name, func(t *testing.T) {
				conf := newConfig()
				configureMultipathOn(conf, endpoints)
				client := conf.MultipathControllerFactory != nil
				server := serverConfig(t, conf).MultipathControllerFactory != nil
				require.Equal(t, endpoints == "both" || endpoints == "client", client)
				require.Equal(t, endpoints == "both" || endpoints == "server", server)
				if name == "GetConfigForClient returns a config" {
					require.True(t, serverConfig(t, conf).EnableDatagrams)
				}
			})
		}
	}

	t.Run("GetConfigForClient returns an error", func(t *testing.T) {
		testErr := errors.New("test error")
		conf := &quic.Config{GetConfigForClient: func(*quic.ClientInfo) (*quic.Config, error) { return nil, testErr }}
		configureMultipathOn(conf, "server")
		_, err := conf.GetConfigForClient(&quic.ClientInfo{})
		require.ErrorIs(t, err, testErr)
	})

	t.Run("controller configured by the test", func(t *testing.T) {
		ctrl := quic.NewDefaultMultipathController(nil)
		conf := &quic.Config{MultipathController: ctrl}
		configureMultipathOn(conf, "server")
		require.Same(t, ctrl, conf.MultipathController)
		require.Nil(t, conf.MultipathControllerFactory)
		require.Nil(t, conf.GetConfigForClient)
	})
}
