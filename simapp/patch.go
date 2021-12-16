package simapp

import (
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	paramtypes "github.com/cosmos/cosmos-sdk/x/params/types"
	clientkeeper "github.com/cosmos/ibc-go/modules/core/02-client/keeper"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	connectionkeeper "github.com/cosmos/ibc-go/modules/core/03-connection/keeper"
	connectiontypes "github.com/cosmos/ibc-go/modules/core/03-connection/types"
	channeltypes "github.com/cosmos/ibc-go/modules/core/04-channel/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	ibckeeper "github.com/cosmos/ibc-go/modules/core/keeper"
	ibctmtypes "github.com/cosmos/ibc-go/modules/light-clients/07-tendermint/types"
	mocktypes "github.com/datachainlab/ibc-mock-client/modules/light-clients/xx-mock/types"

	"github.com/datachainlab/ibc-trusted-ethereum-client/modules/light-clients/trusted-ethereum/types"
)

func overrideIBCClientKeeper(k ibckeeper.Keeper, cdc codec.BinaryCodec, key sdk.StoreKey, paramSpace paramtypes.Subspace, sk clienttypes.StakingKeeper) *ibckeeper.Keeper {
	clientKeeper := NewClientKeeper(k.ClientKeeper, sk)
	k.ConnectionKeeper = connectionkeeper.NewKeeper(cdc, key, paramSpace, clientKeeper)
	return &k
}

var _ connectiontypes.ClientKeeper = (*ClientKeeper)(nil)
var _ channeltypes.ClientKeeper = (*ClientKeeper)(nil)

// ClientKeeper override `GetSelfConsensusState` and `ValidateSelfClient` in the keeper of ibc-client
// original method doesn't yet support a consensus state for general client
type ClientKeeper struct {
	clientkeeper.Keeper

	stakingKeeper clienttypes.StakingKeeper
}

func NewClientKeeper(k clientkeeper.Keeper, sk clienttypes.StakingKeeper) ClientKeeper {
	return ClientKeeper{
		Keeper:        k,
		stakingKeeper: sk,
	}
}

// Just for e2e where ibc-mock-client is used for verifying a tendermint header.
// Used in combination with https://github.com/datachainlab/yui-relayer/tree/trusted-ethereum-client-e2e
func (k ClientKeeper) GetSelfConsensusState(ctx sdk.Context, height exported.Height) (exported.ConsensusState, bool) {
	return &mocktypes.ConsensusState{
		Timestamp: uint64(1),
	}, true
}

func (k ClientKeeper) ValidateSelfClient(ctx sdk.Context, clientState exported.ClientState) error {
	switch cs := clientState.(type) {
	case *ibctmtypes.ClientState:
		return k.Keeper.ValidateSelfClient(ctx, cs)
	case *types.ClientState:
		return nil
	case *mocktypes.ClientState:
		return nil
	default:
		return fmt.Errorf("unexpected client state type: %T", cs)
	}
}
