package ibctesting

import (
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	connectiontypes "github.com/cosmos/ibc-go/modules/core/03-connection/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	ibctmtypes "github.com/cosmos/ibc-go/modules/light-clients/07-tendermint/types"
	ibcmocktypes "github.com/datachainlab/ibc-mock-client/modules/light-clients/xx-mock/types"

	trustedethereumtypes "github.com/datachainlab/ibc-trusted-ethereum-client/modules/light-clients/trusted-ethereum/types"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing/types"
)

type ClientConfig interface {
	GetClientType() string
}

type TrustedEthereumConfig struct {
	Diversifier string
	PrivateKey  *secp256k1.PrivKey
}

func (cfg *TrustedEthereumConfig) GetClientType() string {
	return trustedethereumtypes.TrustedEthereum
}

func NewTrustedEthereumConfig(diversifier string) *TrustedEthereumConfig {
	return &TrustedEthereumConfig{
		Diversifier: diversifier,
		PrivateKey:  secp256k1.GenPrivKey(),
	}
}

type MockConfig struct {
}

func NewMockConfig() *MockConfig {
	return &MockConfig{}
}

func (cfg *MockConfig) GetClientType() string {
	return ibcmocktypes.Mock
}

type TendermintConfig struct {
	TrustLevel                   ibctmtypes.Fraction
	TrustingPeriod               time.Duration
	UnbondingPeriod              time.Duration
	MaxClockDrift                time.Duration
	AllowUpdateAfterExpiry       bool
	AllowUpdateAfterMisbehaviour bool
}

func NewTendermintConfig() *TendermintConfig {
	return &TendermintConfig{
		TrustLevel:                   types.DefaultTrustLevel,
		TrustingPeriod:               types.TrustingPeriod,
		UnbondingPeriod:              types.UnbondingPeriod,
		MaxClockDrift:                types.MaxClockDrift,
		AllowUpdateAfterExpiry:       false,
		AllowUpdateAfterMisbehaviour: false,
	}
}

func (tmcfg *TendermintConfig) GetClientType() string {
	return exported.Tendermint
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
