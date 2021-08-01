package ibctesting

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	capabilitykeeper "github.com/cosmos/cosmos-sdk/x/capability/keeper"
	capabilitytypes "github.com/cosmos/cosmos-sdk/x/capability/types"
	"github.com/cosmos/cosmos-sdk/x/staking/teststaking"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	connectiontypes "github.com/cosmos/ibc-go/modules/core/03-connection/types"
	channeltypes "github.com/cosmos/ibc-go/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/modules/core/23-commitment/types"
	host "github.com/cosmos/ibc-go/modules/core/24-host"
	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/cosmos/ibc-go/modules/core/types"
	ibctmtypes "github.com/cosmos/ibc-go/modules/light-clients/07-tendermint/types"
	"github.com/stretchr/testify/require"
	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto/tmhash"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmprotoversion "github.com/tendermint/tendermint/proto/tendermint/version"
	tmtypes "github.com/tendermint/tendermint/types"
	tmversion "github.com/tendermint/tendermint/version"

	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/tendermint/mock"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/tendermint/simapp"
	ibctestingtypes "github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing/types"
)

var _ ibctestingtypes.TestChainI = (*TestChain)(nil)

// TestChain is a testing struct that wraps a simapp with the last TM Header, the current ABCI
// header and the validators of the TestChain. It also contains a field called ChainID. This
// is the clientID that *other* chains use to refer to this TestChain. The SenderAccount
// is used for delivering transactions through the application state.
// NOTE: the actual application uses an empty chain-id for ease of testing.
type TestChain struct {
	t *testing.T

	App           TestingApp
	chainID       string
	LastHeader    *ibctmtypes.Header // header for last block height committed
	CurrentHeader tmproto.Header     // header for current block height
	QueryServer   types.QueryServer
	TxConfig      client.TxConfig
	Codec         codec.BinaryCodec

	Vals    *tmtypes.ValidatorSet
	Signers []tmtypes.PrivValidator

	senderPrivKey cryptotypes.PrivKey
	SenderAccount authtypes.AccountI
}

// NewTestChain initializes a new TestChain instance with a single validator set using a
// generated private key. It also creates a sender account to be used for delivering transactions.
//
// The first block height is committed to state in order to allow for client creations on
// counterparty chains. The TestChain will return with a block height starting at 2.
//
// Time management is handled by the Coordinator in order to ensure synchrony between chains.
// Each update of any chain increments the block header time for all chains by 5 seconds.
func NewTestChain(t *testing.T) *TestChain {
	// generate validator private/public key
	privVal := mock.NewPV()
	pubKey, err := privVal.GetPubKey()
	require.NoError(t, err)

	// create validator set with single validator
	validator := tmtypes.NewValidator(pubKey, 1)
	valSet := tmtypes.NewValidatorSet([]*tmtypes.Validator{validator})
	signers := []tmtypes.PrivValidator{privVal}

	// generate genesis account
	senderPrivKey := secp256k1.GenPrivKey()
	acc := authtypes.NewBaseAccount(senderPrivKey.PubKey().Address().Bytes(), senderPrivKey.PubKey(), 0, 0)
	balance := banktypes.Balance{
		Address: acc.GetAddress().String(),
		Coins:   sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(100000000000000))),
	}

	app := SetupWithGenesisValSet(t, valSet, []authtypes.GenesisAccount{acc}, balance)

	txConfig := app.GetTxConfig()

	// create an account to send transactions from
	chain := &TestChain{
		t:             t,
		App:           app,
		QueryServer:   app.GetIBCKeeper(),
		TxConfig:      txConfig,
		Codec:         app.AppCodec(),
		Vals:          valSet,
		Signers:       signers,
		senderPrivKey: senderPrivKey,
		SenderAccount: acc,
	}

	return chain
}

func (chain *TestChain) T() *testing.T {
	return chain.t
}

func (chain *TestChain) Init(chainID string) error {
	// create current header and call begin block
	header := tmproto.Header{
		ChainID: chainID,
		Height:  1,
		Time:    time.Now().UTC(),
	}

	chain.chainID = chainID
	chain.CurrentHeader = header

	chain.NextBlock()

	return nil
}

func (chain *TestChain) ChainID() string {
	return chain.chainID
}

func (chain *TestChain) GetCommitmentPrefix() []byte {
	return chain.App.GetIBCKeeper().ConnectionKeeper.GetCommitmentPrefix().Bytes()
}

func (chain *TestChain) GetSenderAddress() string {
	return chain.SenderAccount.GetAddress().String()
}

// NextBlock sets the last header to the current header and increments the current header to be
// at the next block height.
//
// CONTRACT: this function must only be called after app.Commit() occurs
func (chain *TestChain) NextBlock() {
	chain.App.Commit()
	chain.updateHeader()
}

func (chain *TestChain) updateHeader() {
	// set the last header to the current header
	// use nil trusted fields
	chain.LastHeader = chain.CurrentTMClientHeader()

	// increment the current header
	chain.CurrentHeader = tmproto.Header{
		ChainID: chain.chainID,
		Height:  chain.App.LastBlockHeight() + 1,
		AppHash: chain.App.LastCommitID().Hash,
		// NOTE: the time is increased by the coordinator to maintain time synchrony amongst
		// chains.
		Time:               time.Now().UTC(),
		ValidatorsHash:     chain.Vals.Hash(),
		NextValidatorsHash: chain.Vals.Hash(),
	}

	chain.App.BeginBlock(abci.RequestBeginBlock{Header: chain.CurrentHeader})
}

func (chain *TestChain) ConstructTendermintMsgCreateClient(
	trustLevel ibctmtypes.Fraction,
	trustingPeriod, unbondingPeriod, maxClockDrift time.Duration,
	upgradePath []string, allowUpdateAfterExpiry, allowUpdateAfterMisbehaviour bool) ibctestingtypes.MsgCreateClient {
	height, ok := chain.LastHeader.GetHeight().(clienttypes.Height)
	require.True(chain.t, ok)

	clientState := ibctmtypes.NewClientState(
		chain.chainID, trustLevel, trustingPeriod, unbondingPeriod, maxClockDrift,
		height, commitmenttypes.GetSDKSpecs(), upgradePath, allowUpdateAfterExpiry, allowUpdateAfterMisbehaviour,
	)

	consensusState := chain.LastHeader.ConsensusState()

	return ibctestingtypes.MsgCreateClient{
		ClientType:          exported.Tendermint,
		ClientStateBytes:    clienttypes.MustMarshalClientState(chain.Codec, clientState),
		ConsensusStateBytes: clienttypes.MustMarshalConsensusState(chain.Codec, consensusState),
		Height:              height,
	}
}

func (chain *TestChain) ConstructMockMsgCreateClient() ibctestingtypes.MsgCreateClient {
	panic("implement me")
}

func (chain *TestChain) CreateClient(ctx context.Context, msg ibctestingtypes.MsgCreateClient) (string, error) {
	clientState := clienttypes.MustUnmarshalClientState(chain.Codec, msg.ClientStateBytes)
	consensusState := clienttypes.MustUnmarshalConsensusState(chain.Codec, msg.ConsensusStateBytes)

	m, err := clienttypes.NewMsgCreateClient(
		clientState,
		consensusState,
		chain.GetSenderAddress(),
	)
	require.NoError(chain.t, err)

	res, err := chain.SendMsgs(m)
	if err != nil {
		return "", err
	}

	clientID, err := ParseClientIDFromEvents(res.GetEvents())
	if err != nil {
		return "", err
	}

	return clientID, nil
}

func (chain *TestChain) ConstructTendermintUpdateTMClientHeader(
	counterparty ibctestingtypes.TestChainI,
	clientID string,
) ibctestingtypes.MsgUpdateClient {
	header, err := chain.ConstructUpdateTMClientHeader(counterparty, clientID)
	require.NoError(chain.t, err)

	return ibctestingtypes.MsgUpdateClient{
		ClientID: clientID,
		Header:   clienttypes.MustMarshalHeader(chain.Codec, header),
		Signer:   counterparty.GetSenderAddress(),
	}
}

func (chain *TestChain) ConstructMockMsgUpdateClient(clientID string) ibctestingtypes.MsgUpdateClient {
	panic("implement me")
}

func (chain *TestChain) UpdateClient(ctx context.Context, msg ibctestingtypes.MsgUpdateClient) error {
	header, err := clienttypes.UnmarshalHeader(chain.Codec, msg.Header)
	require.NoError(chain.t, err)

	m, err := clienttypes.NewMsgUpdateClient(
		msg.ClientID,
		header,
		msg.Signer,
	)
	require.NoError(chain.t, err)

	return chain.sendMsgs(m)
}

func (chain *TestChain) ConnectionOpenInit(ctx context.Context, msg ibctestingtypes.MsgConnectionOpenInit) (string, error) {
	m := connectiontypes.NewMsgConnectionOpenInit(
		msg.ClientID,
		msg.CounterpartyClientID,
		commitmenttypes.NewMerklePrefix(msg.CounterpartyKeyPrefix),
		msg.Version.(*connectiontypes.Version),
		msg.DelayPeriod,
		msg.Signer,
	)
	res, err := chain.SendMsgs(m)
	if err != nil {
		return "", err
	}

	return ParseConnectionIDFromEvents(res.GetEvents())
}

func (chain *TestChain) ConnectionOpenTry(ctx context.Context, msg ibctestingtypes.MsgConnectionOpenTry) (string, error) {
	counterpartyClient := clienttypes.MustUnmarshalClientState(chain.Codec, msg.ClientStateBytes)

	m := connectiontypes.NewMsgConnectionOpenTry(
		"", msg.ClientID, // does not support handshake continuation
		msg.CounterpartyConnectionID, msg.CounterpartyClientID,
		counterpartyClient, commitmenttypes.NewMerklePrefix(msg.CounterpartyKeyPrefix),
		[]*connectiontypes.Version{connectiontypes.NewVersion(msg.Versions[0].GetIdentifier(), msg.Versions[0].GetFeatures())},
		msg.DelayPeriod,
		msg.ProofInit.Data, msg.ProofClient.Data, msg.ProofConsensus.Data,
		clienttypes.NewHeight(msg.ProofClient.Height.GetRevisionNumber(), msg.ProofClient.Height.GetRevisionHeight()),
		clienttypes.NewHeight(msg.ConsensusHeight.GetRevisionNumber(), msg.ConsensusHeight.GetRevisionHeight()),
		msg.Signer,
	)
	res, err := chain.SendMsgs(m)
	if err != nil {
		return "", err
	}

	return ParseConnectionIDFromEvents(res.GetEvents())
}

func (chain *TestChain) ConnectionOpenAck(ctx context.Context, msg ibctestingtypes.MsgConnectionOpenAck) error {
	counterpartyClient := clienttypes.MustUnmarshalClientState(chain.Codec, msg.ClientStateBytes)

	m := connectiontypes.NewMsgConnectionOpenAck(
		msg.ConnectionID, msg.CounterpartyConnectionID, counterpartyClient, // testing doesn't use flexible selection
		msg.ProofTry.Data, msg.ProofClient.Data, msg.ProofConsensus.Data,
		clienttypes.NewHeight(msg.ProofClient.Height.GetRevisionNumber(), msg.ProofClient.Height.GetRevisionHeight()),
		clienttypes.NewHeight(msg.ConsensusHeight.GetRevisionNumber(), msg.ConsensusHeight.GetRevisionHeight()),
		connectiontypes.NewVersion(msg.Version.GetIdentifier(), msg.Version.GetFeatures()),
		msg.Signer,
	)
	return chain.sendMsgs(m)
}

func (chain *TestChain) ConnectionOpenConfirm(ctx context.Context, msg ibctestingtypes.MsgConnectionOpenConfirm) error {
	m := connectiontypes.NewMsgConnectionOpenConfirm(
		msg.ConnectionID,
		msg.ProofAck.Data,
		clienttypes.NewHeight(msg.ProofAck.Height.GetRevisionNumber(), msg.ProofAck.Height.GetRevisionHeight()),
		msg.Signer,
	)
	return chain.sendMsgs(m)
}

func (chain *TestChain) ChannelOpenInit(ctx context.Context, msg ibctestingtypes.MsgChannelOpenInit) (string, error) {
	m := channeltypes.NewMsgChannelOpenInit(
		msg.PortID,
		msg.Version,
		channeltypes.Order(msg.Order),
		msg.ConnectionHops,
		msg.CounterpartyPortID,
		msg.Signer,
	)
	res, err := chain.SendMsgs(m)
	if err != nil {
		return "", err
	}

	return ParseChannelIDFromEvents(res.GetEvents())
}

func (chain *TestChain) ChannelOpenTry(ctx context.Context, msg ibctestingtypes.MsgChannelOpenTry) (string, error) {
	m := channeltypes.NewMsgChannelOpenTry(
		msg.PortID,
		msg.PreviousChannelID,
		msg.Version,
		channeltypes.Order(msg.Ordering),
		msg.ConnectionHops,
		msg.CounterpartyPortID,
		msg.CounterpartyChannelID,
		msg.CounterpartyVersion,
		msg.ProofInit.Data,
		clienttypes.NewHeight(msg.ProofInit.Height.GetRevisionNumber(), msg.ProofInit.Height.GetRevisionHeight()),
		msg.Signer,
	)
	res, err := chain.SendMsgs(m)
	if err != nil {
		return "", err
	}

	return ParseChannelIDFromEvents(res.GetEvents())
}

func (chain *TestChain) ChannelOpenAck(ctx context.Context, msg ibctestingtypes.MsgChannelOpenAck) error {
	m := channeltypes.NewMsgChannelOpenAck(
		msg.PortID, msg.ChannelID,
		msg.CounterpartyChannelID,
		msg.CounterpartyVersion,
		msg.ProofTry.Data,
		clienttypes.NewHeight(msg.ProofTry.Height.GetRevisionNumber(), msg.ProofTry.Height.GetRevisionHeight()),
		msg.Signer,
	)
	return chain.sendMsgs(m)
}

func (chain *TestChain) ChannelOpenConfirm(ctx context.Context, msg ibctestingtypes.MsgChannelOpenConfirm) error {
	m := channeltypes.NewMsgChannelOpenConfirm(
		msg.PortID,
		msg.ChannelID,
		msg.ProofAck.Data,
		clienttypes.NewHeight(msg.ProofAck.Height.GetRevisionNumber(), msg.ProofAck.Height.GetRevisionHeight()),
		msg.Signer,
	)
	return chain.sendMsgs(m)
}

func (chain *TestChain) HandlePacketRecv(ctx context.Context, packet exported.PacketI, proof *ibctestingtypes.Proof) error {
	p, ok := packet.(*channeltypes.Packet)
	require.True(chain.t, ok)

	height, ok := proof.Height.(clienttypes.Height)
	require.True(chain.t, ok)

	recvMsg := channeltypes.NewMsgRecvPacket(
		*p,
		proof.Data,
		height,
		chain.GetSenderAddress(),
	)

	return chain.sendMsgs(recvMsg)
}

func (chain *TestChain) HandlePacketAcknowledgement(ctx context.Context, packet exported.PacketI, acknowledgement []byte, proof *ibctestingtypes.Proof) error {
	p, ok := packet.(*channeltypes.Packet)
	require.True(chain.t, ok)

	height, ok := proof.Height.(clienttypes.Height)
	require.True(chain.t, ok)

	ackMsg := channeltypes.NewMsgAcknowledgement(
		*p,
		acknowledgement,
		proof.Data,
		height,
		chain.GetSenderAddress(),
	)

	return chain.sendMsgs(ackMsg)
}

func (chain *TestChain) ClientStateCommitmentKey(clientID string) []byte {
	return host.FullClientStateKey(clientID)
}

func (chain *TestChain) ConsensusStateCommitmentKey(clientID string, height exported.Height) []byte {
	return host.FullConsensusStateKey(clientID, height)
}

func (chain *TestChain) ConnectionStateCommitmentKey(connectionID string) []byte {
	return host.ConnectionKey(connectionID)
}

func (chain *TestChain) ChannelStateCommitmentKey(portID, channelID string) []byte {
	return host.ChannelKey(portID, channelID)
}

func (chain *TestChain) PacketCommitmentKey(portID, channelID string, sequence uint64) []byte {
	return host.PacketCommitmentKey(portID, channelID, sequence)
}

func (chain *TestChain) PacketAcknowledgementCommitmentKey(portID, channelID string, sequence uint64) []byte {
	return host.PacketAcknowledgementKey(portID, channelID, sequence)
}

// GetContext returns the current context for the application.
func (chain *TestChain) GetContext() sdk.Context {
	return chain.App.GetBaseApp().NewContext(false, chain.CurrentHeader)
}

// GetSimApp returns the SimApp to allow usage ofnon-interface fields.
// CONTRACT: This function should not be called by third parties implementing
// their own SimApp.
func (chain *TestChain) GetSimApp() *simapp.SimApp {
	app, ok := chain.App.(*simapp.SimApp)
	require.True(chain.t, ok)

	return app
}

// QueryProof performs an abci query with the given key and returns the proto encoded merkle proof
// for the query and the height at which the proof will succeed on a tendermint verifier.
func (chain *TestChain) QueryProofAtHeight(key []byte, height exported.Height, clientType string) (*ibctestingtypes.Proof, error) {
	res := chain.App.Query(abci.RequestQuery{
		Path:   fmt.Sprintf("store/%s/key", host.StoreKey),
		Height: int64(height.GetRevisionHeight()) - 1,
		Data:   key,
		Prove:  true,
	})

	merkleProof, err := commitmenttypes.ConvertProofs(res.ProofOps)
	require.NoError(chain.t, err)

	proof, err := chain.App.AppCodec().Marshal(&merkleProof)
	require.NoError(chain.t, err)

	revision := clienttypes.ParseChainID(chain.chainID)

	// proof height + 1 is returned as the proof created corresponds to the height the proof
	// was created in the IAVL tree. Tendermint and subsequently the clients that rely on it
	// have heights 1 above the IAVL tree. Thus we return proof height + 1
	return &ibctestingtypes.Proof{
		Data:   proof,
		Height: clienttypes.NewHeight(revision, uint64(res.Height)+1),
	}, nil
}

// sendMsgs delivers a transaction through the application without returning the result.
func (chain *TestChain) sendMsgs(msgs ...sdk.Msg) error {
	_, err := chain.SendMsgs(msgs...)
	return err
}

// SendMsgs delivers a transaction through the application. It updates the senders sequence
// number and updates the TestChain's headers. It returns the result and error if one
// occurred.
func (chain *TestChain) SendMsgs(msgs ...sdk.Msg) (*sdk.Result, error) {
	_, r, err := simapp.SignAndDeliver(
		chain.t,
		chain.TxConfig,
		chain.App.GetBaseApp(),
		chain.GetContext().BlockHeader(),
		msgs,
		chain.chainID,
		[]uint64{chain.SenderAccount.GetAccountNumber()},
		[]uint64{chain.SenderAccount.GetSequence()},
		true, true, chain.senderPrivKey,
	)
	if err != nil {
		return nil, err
	}

	// SignAndDeliver calls app.Commit()
	chain.updateHeader()

	// increment sequence for successful transaction execution
	err = chain.SenderAccount.SetSequence(chain.SenderAccount.GetSequence() + 1)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// GetClientState retrieves the client state for the provided clientID. The client is
// expected to exist otherwise testing will fail.
func (chain *TestChain) GetClientState(clientID string) ([]byte, bool, error) {
	clientState, found := chain.getClientState(clientID)
	require.True(chain.t, found)

	bz, err := chain.Codec.MarshalInterface(clientState)
	if err != nil {
		return nil, false, err
	}

	return bz, true, nil
}

func (chain *TestChain) getClientState(clientID string) (exported.ClientState, bool) {
	return chain.App.GetIBCKeeper().ClientKeeper.GetClientState(chain.GetContext(), clientID)
}

func (chain *TestChain) GetLatestHeight(clientID string, clientType string) exported.Height {
	clientState, found := chain.getClientState(clientID)
	require.True(chain.t, found)

	return clientState.GetLatestHeight()
}

// GetConsensusState retrieves the consensus state for the provided clientID and height.
// It will return a success boolean depending on if consensus state exists or not.
func (chain *TestChain) GetConsensusState(clientID string, height exported.Height) (exported.ConsensusState, bool) {
	return chain.App.GetIBCKeeper().ClientKeeper.GetClientConsensusState(chain.GetContext(), clientID, height)
}

// GetValsAtHeight will return the validator set of the chain at a given height. It will return
// a success boolean depending on if the validator set exists or not at that height.
func (chain *TestChain) GetValsAtHeight(height int64) (*tmtypes.ValidatorSet, bool) {
	histInfo, ok := chain.App.GetStakingKeeper().GetHistoricalInfo(chain.GetContext(), height)
	if !ok {
		return nil, false
	}

	valSet := stakingtypes.Validators(histInfo.Valset)

	tmValidators, err := teststaking.ToTmValidators(valSet, sdk.DefaultPowerReduction)
	if err != nil {
		panic(err)
	}
	return tmtypes.NewValidatorSet(tmValidators), true
}

// GetAcknowledgement retrieves an acknowledgement for the provided packet. If the
// acknowledgement does not exist then testing will fail.
func (chain *TestChain) GetAcknowledgement(packet exported.PacketI) []byte {
	ack, found := chain.App.GetIBCKeeper().ChannelKeeper.GetPacketAcknowledgement(chain.GetContext(), packet.GetDestPort(), packet.GetDestChannel(), packet.GetSequence())
	require.True(chain.t, found)

	return ack
}

// ConstructUpdateTMClientHeader will construct a valid 07-tendermint Header to update the
// light client on the source chain.
func (chain *TestChain) ConstructUpdateTMClientHeader(counterparty ibctestingtypes.TestChainI, clientID string) (*ibctmtypes.Header, error) {
	return chain.ConstructUpdateTMClientHeaderWithTrustedHeight(counterparty, clientID, clienttypes.ZeroHeight())
}

// ConstructUpdateTMClientHeader will construct a valid 07-tendermint Header to update the
// light client on the source chain.
func (chain *TestChain) ConstructUpdateTMClientHeaderWithTrustedHeight(counterparty ibctestingtypes.TestChainI, clientID string, trustedHeight clienttypes.Height) (*ibctmtypes.Header, error) {
	header := chain.LastHeader
	// Relayer must query for LatestHeight on client to get TrustedHeight if the trusted height is not set
	if trustedHeight.IsZero() {
		trustedHeight = counterparty.GetLatestHeight(clientID, "").(clienttypes.Height)
	}
	var (
		tmTrustedVals *tmtypes.ValidatorSet
		ok            bool
	)
	// Once we get TrustedHeight from client, we must query the validators from the counterparty chain
	// If the LatestHeight == LastHeader.Height, then TrustedValidators are current validators
	// If LatestHeight < LastHeader.Height, we can query the historical validator set from HistoricalInfo
	if trustedHeight == chain.LastHeader.GetHeight() {
		tmTrustedVals = chain.Vals
	} else {
		// NOTE: We need to get validators from counterparty at height: trustedHeight+1
		// since the last trusted validators for a header at height h
		// is the NextValidators at h+1 committed to in header h by
		// NextValidatorsHash
		tmTrustedVals, ok = chain.GetValsAtHeight(int64(trustedHeight.RevisionHeight + 1))
		if !ok {
			return nil, sdkerrors.Wrapf(ibctmtypes.ErrInvalidHeaderHeight, "could not retrieve trusted validators at trustedHeight: %d", trustedHeight)
		}
	}
	// inject trusted fields into last header
	// for now assume revision number is 0
	header.TrustedHeight = trustedHeight

	trustedVals, err := tmTrustedVals.ToProto()
	if err != nil {
		return nil, err
	}
	header.TrustedValidators = trustedVals

	return header, nil

}

// CurrentTMClientHeader creates a TM header using the current header parameters
// on the chain. The trusted fields in the header are set to nil.
func (chain *TestChain) CurrentTMClientHeader() *ibctmtypes.Header {
	return chain.CreateTMClientHeader(chain.chainID, chain.CurrentHeader.Height, clienttypes.Height{}, chain.CurrentHeader.Time, chain.Vals, nil, chain.Signers)
}

// CreateTMClientHeader creates a TM header to update the TM client. Args are passed in to allow
// caller flexibility to use params that differ from the chain.
func (chain *TestChain) CreateTMClientHeader(chainID string, blockHeight int64, trustedHeight clienttypes.Height, timestamp time.Time, tmValSet, tmTrustedVals *tmtypes.ValidatorSet, signers []tmtypes.PrivValidator) *ibctmtypes.Header {
	var (
		valSet      *tmproto.ValidatorSet
		trustedVals *tmproto.ValidatorSet
	)
	require.NotNil(chain.t, tmValSet)

	vsetHash := tmValSet.Hash()

	tmHeader := tmtypes.Header{
		Version:            tmprotoversion.Consensus{Block: tmversion.BlockProtocol, App: 2},
		ChainID:            chainID,
		Height:             blockHeight,
		Time:               timestamp,
		LastBlockID:        MakeBlockID(make([]byte, tmhash.Size), 10_000, make([]byte, tmhash.Size)),
		LastCommitHash:     chain.App.LastCommitID().Hash,
		DataHash:           tmhash.Sum([]byte("data_hash")),
		ValidatorsHash:     vsetHash,
		NextValidatorsHash: vsetHash,
		ConsensusHash:      tmhash.Sum([]byte("consensus_hash")),
		AppHash:            chain.CurrentHeader.AppHash,
		LastResultsHash:    tmhash.Sum([]byte("last_results_hash")),
		EvidenceHash:       tmhash.Sum([]byte("evidence_hash")),
		ProposerAddress:    tmValSet.Proposer.Address, //nolint:staticcheck
	}
	hhash := tmHeader.Hash()
	blockID := MakeBlockID(hhash, 3, tmhash.Sum([]byte("part_set")))
	voteSet := tmtypes.NewVoteSet(chainID, blockHeight, 1, tmproto.PrecommitType, tmValSet)

	commit, err := tmtypes.MakeCommit(blockID, blockHeight, 1, voteSet, signers, timestamp)
	require.NoError(chain.t, err)

	signedHeader := &tmproto.SignedHeader{
		Header: tmHeader.ToProto(),
		Commit: commit.ToProto(),
	}

	if tmValSet != nil {
		valSet, err = tmValSet.ToProto()
		if err != nil {
			panic(err)
		}
	}

	if tmTrustedVals != nil {
		trustedVals, err = tmTrustedVals.ToProto()
		if err != nil {
			panic(err)
		}
	}

	// The trusted fields may be nil. They may be filled before relaying messages to a client.
	// The relayer is responsible for querying client and injecting appropriate trusted fields.
	return &ibctmtypes.Header{
		SignedHeader:      signedHeader,
		ValidatorSet:      valSet,
		TrustedHeight:     trustedHeight,
		TrustedValidators: trustedVals,
	}
}

// MakeBlockID copied unimported test functions from tmtypes to use them here
func MakeBlockID(hash []byte, partSetSize uint32, partSetHash []byte) tmtypes.BlockID {
	return tmtypes.BlockID{
		Hash: hash,
		PartSetHeader: tmtypes.PartSetHeader{
			Total: partSetSize,
			Hash:  partSetHash,
		},
	}
}

// CreateSortedSignerArray takes two PrivValidators, and the corresponding Validator structs
// (including voting power). It returns a signer array of PrivValidators that matches the
// sorting of ValidatorSet.
// The sorting is first by .VotingPower (descending), with secondary index of .Address (ascending).
func CreateSortedSignerArray(altPrivVal, suitePrivVal tmtypes.PrivValidator,
	altVal, suiteVal *tmtypes.Validator) []tmtypes.PrivValidator {

	switch {
	case altVal.VotingPower > suiteVal.VotingPower:
		return []tmtypes.PrivValidator{altPrivVal, suitePrivVal}
	case altVal.VotingPower < suiteVal.VotingPower:
		return []tmtypes.PrivValidator{suitePrivVal, altPrivVal}
	default:
		if bytes.Compare(altVal.Address, suiteVal.Address) == -1 {
			return []tmtypes.PrivValidator{altPrivVal, suitePrivVal}
		}
		return []tmtypes.PrivValidator{suitePrivVal, altPrivVal}
	}
}

// CreatePortCapability binds and claims a capability for the given portID if it does not
// already exist. This function will fail testing on any resulting error.
// NOTE: only creation of a capbility for a transfer or mock port is supported
// Other applications must bind to the port in InitGenesis or modify this code.
func (chain *TestChain) CreatePortCapability(scopedKeeper capabilitykeeper.ScopedKeeper, portID string) {
	// check if the portId is already binded, if not bind it
	_, ok := chain.App.GetScopedIBCKeeper().GetCapability(chain.GetContext(), host.PortPath(portID))
	if !ok {
		// create capability using the IBC capability keeper
		cap, err := chain.App.GetScopedIBCKeeper().NewCapability(chain.GetContext(), host.PortPath(portID))
		require.NoError(chain.t, err)

		// claim capability using the scopedKeeper
		err = scopedKeeper.ClaimCapability(chain.GetContext(), cap, host.PortPath(portID))
		require.NoError(chain.t, err)
	}

	chain.NextBlock()
}

// GetPortCapability returns the port capability for the given portID. The capability must
// exist, otherwise testing will fail.
func (chain *TestChain) GetPortCapability(portID string) *capabilitytypes.Capability {
	cap, ok := chain.App.GetScopedIBCKeeper().GetCapability(chain.GetContext(), host.PortPath(portID))
	require.True(chain.t, ok)

	return cap
}

// CreateChannelCapability binds and claims a capability for the given portID and channelID
// if it does not already exist. This function will fail testing on any resulting error. The
// scoped keeper passed in will claim the new capability.
func (chain *TestChain) CreateChannelCapability(scopedKeeper capabilitykeeper.ScopedKeeper, portID, channelID string) {
	capName := host.ChannelCapabilityPath(portID, channelID)
	// check if the portId is already binded, if not bind it
	_, ok := chain.App.GetScopedIBCKeeper().GetCapability(chain.GetContext(), capName)
	if !ok {
		cap, err := chain.App.GetScopedIBCKeeper().NewCapability(chain.GetContext(), capName)
		require.NoError(chain.t, err)
		err = scopedKeeper.ClaimCapability(chain.GetContext(), cap, capName)
		require.NoError(chain.t, err)
	}

	chain.NextBlock()
}

// GetChannelCapability returns the channel capability for the given portID and channelID.
// The capability must exist, otherwise testing will fail.
func (chain *TestChain) GetChannelCapability(portID, channelID string) *capabilitytypes.Capability {
	cap, ok := chain.App.GetScopedIBCKeeper().GetCapability(chain.GetContext(), host.ChannelCapabilityPath(portID, channelID))
	require.True(chain.t, ok)

	return cap
}
