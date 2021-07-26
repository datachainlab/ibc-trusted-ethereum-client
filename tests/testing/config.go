package ibctesting

import (
	connectiontypes "github.com/cosmos/ibc-go/modules/core/03-connection/types"
	ibcmocktypes "github.com/datachainlab/ibc-mock-client/modules/light-clients/xx-mock/types"

	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing/types"
)

type ClientConfig interface {
	GetClientType() string
}

type MockConfig struct {
}

func NewMockConfig() *MockConfig {
	return &MockConfig{}
}

func (cfg *MockConfig) GetClientType() string {
	return ibcmocktypes.Mock
}

type ConnectionConfig struct {
	DelayPeriod uint64
	Version     *connectiontypes.Version
}

func NewConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		DelayPeriod: types.DefaultDelayPeriod,
		Version:     types.ConnectionVersion,
	}
}

type ChannelConfig struct {
	PortID  string
	Version string
	Order   types.ChannelOrder
}

func NewChannelConfig() *ChannelConfig {
	return &ChannelConfig{
		PortID:  types.TransferPort,
		Version: types.DefaultChannelVersion,
		Order:   types.UNORDERED,
	}
}
