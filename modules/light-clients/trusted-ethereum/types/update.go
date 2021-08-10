package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/23-commitment/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/ethereum/go-ethereum/common"
)

// CheckHeaderAndUpdateState checks if the provided header is valid and updates
// the consensus state if appropriate. It returns an error if:
// - the header provided is not parseable to a Mock header
func (cs ClientState) CheckHeaderAndUpdateState(
	ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore,
	header exported.Header,
) (exported.ClientState, exported.ConsensusState, error) {
	teHeader, ok := header.(*Header)
	if !ok {
		return nil, nil, sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader, "header type %T, expected  %T", header, &Header{},
		)
	}

	prevConsState, err := GetConsensusState(clientStore, cdc, cs.GetLatestHeight())
	if err != nil {
		return nil, nil, err
	}

	// assert height is not less than the latest height
	if teHeader.GetHeight().LTE(cs.GetLatestHeight()) {
		return nil, nil, sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader,
			"header height is less than to the client state latest height (%d < %d)", header.GetHeight(), cs.GetLatestHeight(),
		)
	}
	if err := checkHeader(cdc, prevConsState, teHeader); err != nil {
		return nil, nil, err
	}

	proof, err := decodeRLP(teHeader.AccountProof)
	if err != nil {
		return nil, nil, sdkerrors.Wrap(ErrInvalidProof, "failed to unmarshal proof into commitment merkle proof")
	}

	_, err = VerifyEthAccountProof(proof, common.BytesToHash(teHeader.StateRoot), cs.IbcStoreAddress)
	if err != nil {
		return nil, nil, sdkerrors.Wrapf(
			ErrInvalidProof, "failed to verify storage proof")
	}

	clientState, consensusState := update(&cs, teHeader, teHeader.StateRoot)
	return clientState, consensusState, nil
}

// checkHeader checks if the Header is valid.
func checkHeader(cdc codec.BinaryCodec, consState *ConsensusState, header *Header) error {
	// assert update timestamp is not less than the consensus state timestamp
	if header.GetTimestamp() < consState.GetTimestamp() {
		return sdkerrors.Wrapf(
			clienttypes.ErrInvalidHeader,
			"header timestamp is less than to the consensus state timestamp (%d < %d)", header.Timestamp, consState.Timestamp,
		)
	}

	// assert currently registered public key signed over the new public key with correct sequence
	data, err := HeaderSignBytes(cdc, header)
	if err != nil {
		return err
	}

	publicKey, err := consState.GetPubKey()
	if err != nil {
		return err
	}
	if err := VerifySignature(publicKey, data, header.Signature); err != nil {
		return sdkerrors.Wrap(ErrInvalidHeader, err.Error())
	}

	return nil
}

// update the consensus state to the new public key and an incremented revision number
func update(clientState *ClientState, header *Header, root []byte) (*ClientState, *ConsensusState) {
	consensusState := &ConsensusState{
		PublicKey:   header.NewPublicKey,
		Diversifier: header.NewDiversifier,
		Timestamp:   header.Timestamp,
		Root:        types.MerkleRoot{Hash: root},
	}
	clientState.LatestHeight = header.Height
	return clientState, consensusState
}
