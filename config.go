package quic

import (
	"fmt"
	"slices"
	"time"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
	"github.com/AeonDave/mp-quic-go/quicvarint"
)

// Clone clones a Config.
func (c *Config) Clone() *Config {
	cc := *c
	return &cc
}

func (c *Config) handshakeTimeout() time.Duration {
	return 2 * c.HandshakeIdleTimeout
}

func (c *Config) maxRetryTokenAge() time.Duration {
	return c.handshakeTimeout()
}

func validateConfig(config *Config) error {
	if config == nil {
		return nil
	}
	const maxStreams = 1 << 60
	if config.MaxIncomingStreams > maxStreams {
		config.MaxIncomingStreams = maxStreams
	}
	if config.MaxIncomingUniStreams > maxStreams {
		config.MaxIncomingUniStreams = maxStreams
	}
	if config.MaxStreamReceiveWindow > quicvarint.Max {
		config.MaxStreamReceiveWindow = quicvarint.Max
	}
	if config.MaxConnectionReceiveWindow > quicvarint.Max {
		config.MaxConnectionReceiveWindow = quicvarint.Max
	}
	if config.InitialPacketSize > 0 && config.InitialPacketSize < protocol.MinInitialPacketSize {
		config.InitialPacketSize = protocol.MinInitialPacketSize
	}
	if config.InitialPacketSize > protocol.MaxPacketBufferSize {
		config.InitialPacketSize = protocol.MaxPacketBufferSize
	}
	// check that all QUIC versions are actually supported
	for _, v := range config.Versions {
		if !protocol.IsValidVersion(v) {
			return fmt.Errorf("invalid QUIC version: %s", v)
		}
	}
	if config.InitialVersion != 0 {
		versions := config.Versions
		if len(versions) == 0 {
			versions = protocol.SupportedVersions
		}
		if !slices.Contains(versions, config.InitialVersion) {
			return fmt.Errorf("initial QUIC version %s is not one of the versions (%s)", config.InitialVersion, versions)
		}
	}
	return nil
}

// populateConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateConfig(config *Config) *Config {
	if config == nil {
		config = &Config{}
	}
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
	}
	handshakeIdleTimeout := protocol.DefaultHandshakeIdleTimeout
	if config.HandshakeIdleTimeout != 0 {
		handshakeIdleTimeout = config.HandshakeIdleTimeout
	}
	idleTimeout := protocol.DefaultIdleTimeout
	if config.MaxIdleTimeout != 0 {
		idleTimeout = config.MaxIdleTimeout
	}
	initialStreamReceiveWindow := config.InitialStreamReceiveWindow
	if initialStreamReceiveWindow == 0 {
		initialStreamReceiveWindow = protocol.DefaultInitialMaxStreamData
	}
	maxStreamReceiveWindow := config.MaxStreamReceiveWindow
	if maxStreamReceiveWindow == 0 {
		maxStreamReceiveWindow = protocol.DefaultMaxReceiveStreamFlowControlWindow
	}
	initialConnectionReceiveWindow := config.InitialConnectionReceiveWindow
	if initialConnectionReceiveWindow == 0 {
		initialConnectionReceiveWindow = protocol.DefaultInitialMaxData
	}
	maxConnectionReceiveWindow := config.MaxConnectionReceiveWindow
	if maxConnectionReceiveWindow == 0 {
		maxConnectionReceiveWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindow
	}
	maxIncomingStreams := config.MaxIncomingStreams
	if maxIncomingStreams == 0 {
		maxIncomingStreams = protocol.DefaultMaxIncomingStreams
	} else if maxIncomingStreams < 0 {
		maxIncomingStreams = 0
	}
	maxIncomingUniStreams := config.MaxIncomingUniStreams
	if maxIncomingUniStreams == 0 {
		maxIncomingUniStreams = protocol.DefaultMaxIncomingUniStreams
	} else if maxIncomingUniStreams < 0 {
		maxIncomingUniStreams = 0
	}
	initialPacketSize := config.InitialPacketSize
	if initialPacketSize == 0 {
		initialPacketSize = protocol.InitialPacketSize
	}
	// Configs returned by GetConfigForClient are not validated, so the limits are applied here.
	maxPaths := config.MaxPaths
	switch {
	case maxPaths == 0:
		maxPaths = 3 // default value
	case maxPaths < 0:
		maxPaths = 1
	case maxPaths > protocol.MaxMultipathPaths:
		maxPaths = protocol.MaxMultipathPaths
	}

	return &Config{
		GetConfigForClient:               config.GetConfigForClient,
		Versions:                         versions,
		versionsConfigured:               len(config.Versions) > 0,
		InitialVersion:                   config.InitialVersion,
		HandshakeIdleTimeout:             handshakeIdleTimeout,
		MaxIdleTimeout:                   idleTimeout,
		KeepAlivePeriod:                  config.KeepAlivePeriod,
		InitialStreamReceiveWindow:       initialStreamReceiveWindow,
		MaxStreamReceiveWindow:           maxStreamReceiveWindow,
		InitialConnectionReceiveWindow:   initialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:       maxConnectionReceiveWindow,
		AllowConnectionWindowIncrease:    config.AllowConnectionWindowIncrease,
		MaxIncomingStreams:               maxIncomingStreams,
		MaxIncomingUniStreams:            maxIncomingUniStreams,
		TokenStore:                       config.TokenStore,
		EnableDatagrams:                  config.EnableDatagrams,
		InitialPacketSize:                initialPacketSize,
		DisablePathMTUDiscovery:          config.DisablePathMTUDiscovery,
		EnableStreamResetPartialDelivery: config.EnableStreamResetPartialDelivery,
		EnableQUICBitGreasing:            config.EnableQUICBitGreasing,
		RequestObservedAddress:           config.RequestObservedAddress,
		ProvideObservedAddress:           config.ProvideObservedAddress,
		MaxPaths:                         maxPaths,
		MultipathController:              config.MultipathController,
		MultipathControllerFactory:       config.MultipathControllerFactory,
		MultipathCongestionControl:       config.MultipathCongestionControl,
		MultipathDuplicationPolicy:       config.MultipathDuplicationPolicy,
		MultipathReinjectionPolicy:       config.MultipathReinjectionPolicy,
		MultipathAutoPaths:               config.MultipathAutoPaths,
		EnableAddressAdvertisement:       config.EnableAddressAdvertisement,
		MultipathAutoAdvertise:           config.MultipathAutoAdvertise,
		MultipathAutoAddrs:               config.MultipathAutoAddrs,
		ExtensionFrameHandler:            config.ExtensionFrameHandler,
		Allow0RTT:                        config.Allow0RTT,
		ZeroRTTReplayCache:               config.ZeroRTTReplayCache,
		Tracer:                           config.Tracer,
	}
}
