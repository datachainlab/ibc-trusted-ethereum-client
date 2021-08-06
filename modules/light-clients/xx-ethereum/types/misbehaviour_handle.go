package types

import (
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
)

// CheckMisbehaviourAndUpdateState determines whether or not two conflicting
// headers at the same height would have convinced the light client.
//
// Misbehaviour sets frozen height to {0, 1} since it is only used as a boolean value (zero or non-zero).
func (cs ClientState) CheckMisbehaviourAndUpdateState(
	ctx sdk.Context,
	cdc codec.BinaryCodec,
	clientStore sdk.KVStore,
	misbehaviour exported.Misbehaviour,
) (exported.ClientState, error) {
	ethMisbehaviour, ok := misbehaviour.(*Misbehaviour)
	if !ok {
		return nil, sdkerrors.Wrapf(
			clienttypes.ErrInvalidClientType,
			"misbehaviour type %T, expected %T", misbehaviour, &Misbehaviour{},
		)
	}

	// Get consensus bytes from clientStore
	ethConsensusState, err := GetConsensusState(clientStore, cdc, ethMisbehaviour.Header1.GetHeight())
	if err != nil {
		return nil, sdkerrors.Wrapf(err, "could not get consensus state from clientStore for Header1 at Height: %s", ethMisbehaviour.Header1)
	}

	// Check the validity of the two conflicting headers against the consensus state
	// NOTE: header height and commitment root assertions are checked in
	// misbehaviour.ValidateBasic by the client keeper and msg.ValidateBasic
	// by the base application.
	if err := checkMisbehaviourHeader(
		cdc, &cs, ethConsensusState, ethMisbehaviour.Header1, ctx.BlockTime(),
	); err != nil {
		return nil, sdkerrors.Wrap(err, "verifying Header1 in Misbehaviour failed")
	}
	if err := checkMisbehaviourHeader(
		cdc, &cs, ethConsensusState, ethMisbehaviour.Header2, ctx.BlockTime(),
	); err != nil {
		return nil, sdkerrors.Wrap(err, "verifying Header2 in Misbehaviour failed")
	}

	cs.FrozenHeight = clienttypes.NewHeight(0, 1)

	return &cs, nil
}

// checkMisbehaviourHeader checks that a Header in Misbehaviour is valid misbehaviour given
// a trusted ConsensusState
func checkMisbehaviourHeader(
	cdc codec.BinaryCodec, clientState *ClientState, consState *ConsensusState, header *Header, currentTimestamp time.Time,
) error {
	// check the header against ConsensusState
	if err := checkHeader(cdc, consState, header); err != nil {
		return err
	}
	return nil
}
