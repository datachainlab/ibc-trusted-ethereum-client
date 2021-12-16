package ethereum

import (
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	ethtypes "github.com/datachainlab/ibc-trusted-ethereum-client/modules/light-clients/trusted-ethereum/types"
	"github.com/hyperledger-labs/yui-relayer/core"
)

// RegisterInterfaces register the module interfaces to protobuf Any.
func RegisterInterfaces(registry codectypes.InterfaceRegistry) {
	ethtypes.RegisterInterfaces(registry)

	registry.RegisterImplementations(
		(*core.ProverConfigI)(nil),
		&ProverConfig{},
	)
}
