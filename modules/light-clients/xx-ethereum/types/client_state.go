package types

import (
	"strings"

	ics23 "github.com/confio/ics23/go"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	connectiontypes "github.com/cosmos/ibc-go/modules/core/03-connection/types"
	channeltypes "github.com/cosmos/ibc-go/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/modules/core/23-commitment/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	TrustedEthereum string = "trusted-ethereum"
)

// GetChainID returns the chain-id
func (cs ClientState) GetChainID() string {
	return cs.ChainId
}

// ClientType is tendermint.
func (cs ClientState) ClientType() string {
	return TrustedEthereum
}

// GetLatestHeight returns latest block height.
func (cs ClientState) GetLatestHeight() exported.Height {
	return cs.LatestHeight
}

// GetProofSpecs returns nil proof specs since client state verification uses signatures.
func (cs ClientState) GetProofSpecs() []*ics23.ProofSpec {
	return nil
}

// Status returns the status of the tendermint client.
// The client may be:
// - Active: FrozenHeight is zero and client is not expired
// - Frozen: Frozen Height is not zero
// - Expired: the latest consensus state timestamp + trusting period <= current time
//
// A frozen client will become expired, so the Frozen status
// has higher precedence.
func (cs ClientState) Status(
	ctx sdk.Context,
	clientStore sdk.KVStore,
	cdc codec.BinaryCodec,
) exported.Status {
	if !cs.FrozenHeight.IsZero() {
		return exported.Frozen
	}

	_, err := GetConsensusState(clientStore, cdc, cs.GetLatestHeight())
	if err != nil {
		return exported.Unknown
	}

	return exported.Active
}

// GetFrozenHeight returns the frozen sequence of the client.
// Return exported.Height to satisfy interface
// Revision number is always 0 for a solo-machine
func (cs ClientState) GetFrozenHeight() exported.Height {
	return cs.FrozenHeight
}

// Validate performs a basic validation of the client state fields.
func (cs ClientState) Validate() error {
	if strings.TrimSpace(cs.ChainId) == "" {
		return sdkerrors.Wrap(ErrInvalidChainID, "chain id cannot be empty string")
	}

	if cs.LatestHeight.RevisionHeight != 0 {
		return sdkerrors.Wrapf(ErrInvalidHeaderHeight, "revision height must be zero")
	}
	return nil
}

// ZeroCustomFields returns a ClientState that is a copy of the current ClientState
// with all client customizable fields zeroed out
func (cs ClientState) ZeroCustomFields() exported.ClientState {
	// copy over all chain-specified fields
	// and leave custom fields empty
	return &ClientState{
		ChainId:         cs.ChainId,
		IbcStoreAddress: cs.IbcStoreAddress,
		LatestHeight:    cs.LatestHeight,
		FrozenHeight:    clienttypes.ZeroHeight(),
	}
}

// Initialize will check that initial consensus state is a Tendermint consensus state
// and will store ProcessedTime for initial consensus state as ctx.BlockTime()
func (cs ClientState) Initialize(ctx sdk.Context, _ codec.BinaryCodec, clientStore sdk.KVStore, consState exported.ConsensusState) error {
	if _, ok := consState.(*ConsensusState); !ok {
		return sdkerrors.Wrapf(clienttypes.ErrInvalidConsensus, "invalid initial consensus state. expected type: %T, got: %T",
			&ConsensusState{}, consState)
	}
	return nil
}

// ExportMetadata is a no-op since Trusted Ethereum does not store any metadata in client store
func (cs ClientState) ExportMetadata(_ sdk.KVStore) []exported.GenesisMetadata {
	return nil
}

// VerifyUpgradeAndUpdateState returns an error since Multisig client does not support upgrades
func (cs ClientState) VerifyUpgradeAndUpdateState(
	_ sdk.Context, _ codec.BinaryCodec, _ sdk.KVStore,
	_ exported.ClientState, _ exported.ConsensusState, _, _ []byte,
) (exported.ClientState, exported.ConsensusState, error) {
	return nil, nil, sdkerrors.Wrap(clienttypes.ErrInvalidUpgradeClient, "cannot upgrade Trusted Ethereum client")
}

// VerifyClientState verifies a proof of the client state of the running chain
// stored on the target machine
func (cs ClientState) VerifyClientState(
	store sdk.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	prefix exported.Prefix,
	counterpartyClientIdentifier string,
	proof []byte,
	clientState exported.ClientState,
) error {
	merkleProof, provingConsensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}

	// TODO check if this impl is correct (about size)
	root := common.BytesToHash(provingConsensusState.Root.Hash)
	slot, err := ClientStateCommitmentSlot(counterpartyClientIdentifier)
	if err != nil {
		return err
	}

	if clientState == nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidClient, "client state cannot be empty")
	}

	bz, err := cdc.MarshalInterface(clientState)
	if err != nil {
		return err
	}

	return VerifyEthStorageProof(merkleProof, root, slot, crypto.Keccak256(bz))
}

// VerifyClientConsensusState verifies a proof of the consensus state of the
// Tendermint client stored on the target machine.
func (cs ClientState) VerifyClientConsensusState(
	store sdk.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	counterpartyClientIdentifier string,
	consensusHeight exported.Height,
	prefix exported.Prefix,
	proof []byte,
	consensusState exported.ConsensusState,
) error {
	merkleProof, provingConsensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}

	// TODO check if this impl is correct (about size)
	root := common.BytesToHash(provingConsensusState.Root.Hash)
	slot, err := ConsensusStateCommitmentSlot(counterpartyClientIdentifier, consensusHeight.GetRevisionHeight())
	if err != nil {
		return err
	}

	if consensusState == nil {
		return sdkerrors.Wrap(clienttypes.ErrInvalidConsensus, "consensus state cannot be empty")
	}

	bz, err := cdc.MarshalInterface(consensusState)
	if err != nil {
		return err
	}

	return VerifyEthStorageProof(merkleProof, root, slot, crypto.Keccak256(bz))
}

// VerifyConnectionState verifies a proof of the connection state of the
// specified connection end stored on the target machine.
func (cs ClientState) VerifyConnectionState(
	store sdk.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	prefix exported.Prefix,
	proof []byte,
	connectionID string,
	connectionEnd exported.ConnectionI,
) error {
	merkleProof, consensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}

	// TODO check if this impl is correct (about size)
	root := common.BytesToHash(consensusState.Root.Hash)
	slot, err := ConnectionCommitmentSlot(connectionID)
	if err != nil {
		return err
	}

	connection, ok := connectionEnd.(connectiontypes.ConnectionEnd)
	if !ok {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "invalid connection type %T", connectionEnd)
	}

	bz, err := cdc.Marshal(&connection)
	if err != nil {
		return err
	}

	return VerifyEthStorageProof(merkleProof, root, slot, crypto.Keccak256(bz))
}

// VerifyChannelState verifies a proof of the channel state of the specified
// channel end, under the specified port, stored on the target machine.
func (cs ClientState) VerifyChannelState(
	store sdk.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	prefix exported.Prefix,
	proof []byte,
	portID,
	channelID string,
	channel exported.ChannelI,
) error {
	merkleProof, consensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}
	root := common.BytesToHash(consensusState.Root.Hash)
	slot, err := ChannelCommitmentSlot(portID, channelID)
	if err != nil {
		return err
	}

	channelEnd, ok := channel.(channeltypes.Channel)
	if !ok {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "invalid channel type %T", channel)
	}

	bz, err := cdc.Marshal(&channelEnd)
	if err != nil {
		return err
	}

	return VerifyEthStorageProof(merkleProof, root, slot, crypto.Keccak256(bz))
}

// VerifyPacketCommitment verifies a proof of an outgoing packet commitment at
// the specified port, specified channel, and specified sequence.
func (cs ClientState) VerifyPacketCommitment(
	ctx sdk.Context,
	store sdk.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	prefix exported.Prefix,
	proof []byte,
	portID,
	channelID string,
	sequence uint64,
	commitmentBytes []byte,
) error {
	merkleProof, consensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}
	root := common.BytesToHash(consensusState.Root.Hash)
	slot, err := PacketCommitmentSlot(portID, channelID, sequence)
	if err != nil {
		return err
	}

	return VerifyEthStorageProof(merkleProof, root, slot, crypto.Keccak256(commitmentBytes))
}

// VerifyPacketAcknowledgement verifies a proof of an incoming packet
// acknowledgement at the specified port, specified channel, and specified sequence.
func (cs ClientState) VerifyPacketAcknowledgement(
	ctx sdk.Context,
	store sdk.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	prefix exported.Prefix,
	proof []byte,
	portID,
	channelID string,
	sequence uint64,
	acknowledgement []byte,
) error {
	merkleProof, consensusState, err := produceVerificationArgs(store, cdc, cs, height, prefix, proof)
	if err != nil {
		return err
	}
	root := common.BytesToHash(consensusState.Root.Hash)
	slot, err := PacketAcknowledgementCommitmentSlot(portID, channelID, sequence)
	if err != nil {
		return err
	}

	return VerifyEthStorageProof(merkleProof, root, slot, crypto.Keccak256(acknowledgement))
}

// VerifyPacketReceiptAbsence verifies a proof of the absence of an
// incoming packet receipt at the specified port, specified channel, and
// specified sequence.
func (cs ClientState) VerifyPacketReceiptAbsence(
	ctx sdk.Context,
	store sdk.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	prefix exported.Prefix,
	proof []byte,
	portID,
	channelID string,
	sequence uint64,
) error {
	return sdkerrors.Wrap(clienttypes.ErrFailedPacketReceiptVerification, "not supported")
}

// VerifyNextSequenceRecv verifies a proof of the next sequence number to be
// received of the specified channel at the specified port.
func (cs ClientState) VerifyNextSequenceRecv(
	ctx sdk.Context,
	store sdk.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	prefix exported.Prefix,
	proof []byte,
	portID,
	channelID string,
	nextSequenceRecv uint64,
) error {
	return sdkerrors.Wrap(clienttypes.ErrFailedNextSeqRecvVerification, "not supported")
}

// produceVerificationArgs perfoms the basic checks on the arguments that are
// shared between the verification functions and returns the unmarshalled
// merkle proof, the consensus state and an error if one occurred.
func produceVerificationArgs(
	store sdk.KVStore,
	cdc codec.BinaryCodec,
	cs ClientState,
	height exported.Height,
	prefix exported.Prefix,
	proof []byte,
) (merkleProof [][]byte, consensusState *ConsensusState, err error) {
	if cs.GetLatestHeight().LT(height) {
		return nil, nil, sdkerrors.Wrapf(
			sdkerrors.ErrInvalidHeight,
			"client state height < proof height (%d < %d), please ensure the client has been updated", cs.GetLatestHeight(), height,
		)
	}

	if prefix == nil {
		return nil, nil, sdkerrors.Wrap(commitmenttypes.ErrInvalidPrefix, "prefix cannot be empty")
	}

	_, ok := prefix.(*commitmenttypes.MerklePrefix)
	if !ok {
		return nil, nil, sdkerrors.Wrapf(commitmenttypes.ErrInvalidPrefix, "invalid prefix type %T, expected *MerklePrefix", prefix)
	}

	if proof == nil {
		return nil, nil, sdkerrors.Wrap(commitmenttypes.ErrInvalidProof, "proof cannot be empty")
	}

	merkleProof, err = decodeRLP(proof)
	if err != nil {
		return nil, nil, sdkerrors.Wrap(commitmenttypes.ErrInvalidProof, "failed to unmarshal proof into commitment merkle proof")
	}

	consensusState, err = GetConsensusState(store, cdc, height)
	if err != nil {
		return nil, nil, sdkerrors.Wrap(err, "please ensure the proof was constructed against a height that exists on the client")
	}

	return merkleProof, consensusState, nil
}

// decodeRLP decodes the proof according to the IBFT2.0 client proof format implemented by yui-ibc-solidity
// and formats it for Ethereum's Account/Storage Proof.
func decodeRLP(proof []byte) ([][]byte, error) {
	var val [][][]byte
	if err := rlp.DecodeBytes(proof, &val); err != nil {
		return nil, err
	}

	var res [][]byte
	for _, v := range val {
		bz, err := rlp.EncodeToBytes(v)
		if err != nil {
			return nil, err
		}
		res = append(res, bz)
	}
	return res, nil
}
