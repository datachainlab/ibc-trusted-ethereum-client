package ibctesting

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/cosmos/ibc-go/modules/core/exported"
	mocktypes "github.com/datachainlab/ibc-mock-client/modules/light-clients/xx-mock/types"
	"github.com/stretchr/testify/require"

	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum"
	ibctestingtypes "github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing/types"
)

// Endpoint is a which represents a channel endpoint and its associated
// client and connections. It contains client, connection, and channel
// configuration parameters. Endpoint functions will utilize the parameters
// set in the configuration structs when executing IBC messages.
type Endpoint struct {
	Chain        ibctestingtypes.TestChainI
	Counterparty *Endpoint
	ClientID     string
	ConnectionID string
	ChannelID    string

	ClientConfig     ClientConfig
	ConnectionConfig *ConnectionConfig
	ChannelConfig    *ChannelConfig
}

// NewEndpoint constructs a new endpoint without the counterparty.
// CONTRACT: the counterparty endpoint must be set by the caller.
func NewEndpoint(
	chain *ethereum.TestChain,
	clientConfig ClientConfig,
	connectionConfig *ConnectionConfig,
	channelConfig *ChannelConfig,
) *Endpoint {
	return &Endpoint{
		Chain:            chain,
		ClientConfig:     clientConfig,
		ConnectionConfig: connectionConfig,
		ChannelConfig:    channelConfig,
	}
}

// NewDefaultEndpoint constructs a new endpoint using default values.
// CONTRACT: the counterparty endpoint must be set by the caller.
func NewDefaultEndpoint(chain ibctestingtypes.TestChainI) *Endpoint {
	return &Endpoint{
		Chain:            chain,
		ClientConfig:     NewMockConfig(),
		ConnectionConfig: NewConnectionConfig(),
		ChannelConfig:    NewChannelConfig(),
	}
}

// CreateClient creates an IBC client on the endpoint. It will update the
// clientID for the endpoint if the message is successfully executed.
// NOTE: a solo machine client will be created with an empty diversifier.
func (endpoint *Endpoint) CreateClient(ctx context.Context) (err error) {
	// ensure counterparty has committed state
	endpoint.Counterparty.Chain.NextBlock()

	var (
		msg ibctestingtypes.MsgCreateClient
	)

	switch endpoint.ClientConfig.GetClientType() {
	case mocktypes.Mock:
		_, ok := endpoint.ClientConfig.(*MockConfig)
		require.True(endpoint.Chain.T(), ok)

		msg = endpoint.Counterparty.Chain.ConstructMockMsgCreateClient()
	case exported.Tendermint:
		tmConfig, ok := endpoint.ClientConfig.(*TendermintConfig)
		require.True(endpoint.Chain.T(), ok)

		msg = endpoint.Counterparty.Chain.ConstructTendermintMsgCreateClient(
			tmConfig.TrustLevel, tmConfig.TrustingPeriod, tmConfig.UnbondingPeriod, tmConfig.MaxClockDrift,
			ibctestingtypes.UpgradePath, tmConfig.AllowUpdateAfterExpiry, tmConfig.AllowUpdateAfterMisbehaviour,
		)
	default:
		err = fmt.Errorf("client type %s is not supported", endpoint.ClientConfig.GetClientType())
	}

	if err != nil {
		return err
	}

	endpoint.ClientID, err = endpoint.Chain.CreateClient(ctx, msg)
	require.NoError(endpoint.Chain.T(), err)

	return err
}

// UpdateClient updates the IBC client associated with the endpoint.
func (endpoint *Endpoint) UpdateClient(ctx context.Context) (err error) {
	// ensure counterparty has committed state
	endpoint.Counterparty.Chain.NextBlock()
	var (
		msg ibctestingtypes.MsgUpdateClient
	)

	switch endpoint.ClientConfig.GetClientType() {
	case mocktypes.Mock:
		msg = endpoint.Counterparty.Chain.ConstructMockMsgUpdateClient(endpoint.ClientID)
	case exported.Tendermint:
		msg = endpoint.Counterparty.Chain.ConstructTendermintUpdateTMClientHeader(endpoint.Chain, endpoint.ClientID)
	default:
		err = fmt.Errorf("client type %s is not supported", endpoint.ClientConfig.GetClientType())
	}

	if err != nil {
		return err
	}

	err = endpoint.Chain.UpdateClient(ctx, msg)

	return err

}

// ConnOpenInit will construct and execute a MsgConnectionOpenInit on the associated endpoint.
func (endpoint *Endpoint) ConnOpenInit(ctx context.Context) error {
	require.NoError(endpoint.Chain.T(), endpoint.UpdateClient(ctx))

	msg := ibctestingtypes.MsgConnectionOpenInit{
		ClientID:              endpoint.ClientID,
		CounterpartyClientID:  endpoint.Counterparty.ClientID,
		CounterpartyKeyPrefix: endpoint.Counterparty.Chain.GetCommitmentPrefix(),
		DelayPeriod:           endpoint.ConnectionConfig.DelayPeriod,
		Version:               ibctestingtypes.DefaultOpenInitVersion,
		Signer:                endpoint.Chain.GetSenderAddress(),
	}

	connectionID, err := endpoint.Chain.ConnectionOpenInit(ctx, msg)
	if err != nil {
		return err
	}

	endpoint.ConnectionID = connectionID

	return nil
}

// ConnOpenTry will construct and execute a MsgConnectionOpenTry on the associated endpoint.
func (endpoint *Endpoint) ConnOpenTry(ctx context.Context) error {
	require.NoError(endpoint.Chain.T(), endpoint.UpdateClient(ctx))

	counterpartyClient, proofClient, proofConsensus, consensusHeight, proofInit := endpoint.QueryConnectionHandshakeProof()

	msg := ibctestingtypes.MsgConnectionOpenTry{
		PreviousConnectionID:     "",
		ClientID:                 endpoint.ClientID,
		ClientStateBytes:         counterpartyClient,
		CounterpartyClientID:     endpoint.Counterparty.ClientID,
		CounterpartyConnectionID: endpoint.Counterparty.ConnectionID,
		CounterpartyKeyPrefix:    endpoint.Counterparty.Chain.GetCommitmentPrefix(),
		DelayPeriod:              endpoint.ConnectionConfig.DelayPeriod,
		Versions:                 []exported.Version{ibctestingtypes.ConnectionVersion},
		ProofInit:                proofInit,
		ProofClient:              proofClient,
		ProofConsensus:           proofConsensus,
		ConsensusHeight:          consensusHeight,
		Signer:                   endpoint.Chain.GetSenderAddress(),
	}

	connectionID, err := endpoint.Chain.ConnectionOpenTry(ctx, msg)
	if err != nil {
		return err
	}

	endpoint.ConnectionID = connectionID

	return nil
}

// ConnOpenAck will construct and execute a MsgConnectionOpenAck on the associated endpoint.
func (endpoint *Endpoint) ConnOpenAck(ctx context.Context) error {
	require.NoError(endpoint.Chain.T(), endpoint.UpdateClient(ctx))

	counterpartyClient, proofClient, proofConsensus, consensusHeight, proofTry := endpoint.QueryConnectionHandshakeProof()

	msg := ibctestingtypes.MsgConnectionOpenAck{
		ConnectionID:             endpoint.ConnectionID,
		CounterpartyConnectionID: endpoint.Counterparty.ConnectionID,
		ClientStateBytes:         counterpartyClient,
		Version:                  ibctestingtypes.ConnectionVersion,
		ProofTry:                 proofTry,
		ProofClient:              proofClient,
		ProofConsensus:           proofConsensus,
		ConsensusHeight:          consensusHeight,
		Signer:                   endpoint.Chain.GetSenderAddress(),
	}

	return endpoint.Chain.ConnectionOpenAck(ctx, msg)
}

// ConnOpenConfirm will construct and execute a MsgConnectionOpenConfirm on the associated endpoint.
func (endpoint *Endpoint) ConnOpenConfirm(ctx context.Context) error {
	require.NoError(endpoint.Chain.T(), endpoint.UpdateClient(ctx))

	_, _, _, _, proofAck := endpoint.QueryConnectionHandshakeProof()

	msg := ibctestingtypes.MsgConnectionOpenConfirm{
		ConnectionID: endpoint.ConnectionID,
		ProofAck:     proofAck,
		Signer:       endpoint.Chain.GetSenderAddress(),
	}

	return endpoint.Chain.ConnectionOpenConfirm(ctx, msg)
}

// ChanOpenInit will construct and execute a MsgChannelOpenInit on the associated endpoint.
func (endpoint *Endpoint) ChanOpenInit(ctx context.Context) error {
	require.NoError(endpoint.Chain.T(), endpoint.UpdateClient(ctx))

	msg := ibctestingtypes.MsgChannelOpenInit{
		PortID:             endpoint.ChannelConfig.PortID,
		Order:              endpoint.ChannelConfig.Order,
		CounterpartyPortID: endpoint.Counterparty.ChannelConfig.PortID,
		ConnectionHops:     []string{endpoint.ConnectionID},
		Version:            endpoint.ChannelConfig.Version,
		Signer:             endpoint.Chain.GetSenderAddress(),
	}

	channelID, err := endpoint.Chain.ChannelOpenInit(ctx, msg)
	if err != nil {
		return err
	}
	endpoint.ChannelID = channelID

	return nil
}

// ChanOpenTry will construct and execute a MsgChannelOpenTry on the associated endpoint.
func (endpoint *Endpoint) ChanOpenTry(ctx context.Context) error {
	require.NoError(endpoint.Chain.T(), endpoint.UpdateClient(ctx))

	proofInit, err := endpoint.Counterparty.QueryChannelProof()
	require.NoError(endpoint.Chain.T(), err)

	msg := ibctestingtypes.MsgChannelOpenTry{
		PortID:                endpoint.ChannelConfig.PortID,
		PreviousChannelID:     "",
		Ordering:              endpoint.ChannelConfig.Order,
		CounterpartyChannelID: endpoint.Counterparty.ChannelID,
		CounterpartyPortID:    endpoint.Counterparty.ChannelConfig.PortID,
		ConnectionHops:        []string{endpoint.ConnectionID},
		Version:               endpoint.ChannelConfig.Version,
		CounterpartyVersion:   endpoint.Counterparty.ChannelConfig.Version,
		ProofInit:             proofInit,
		Signer:                endpoint.Chain.GetSenderAddress(),
	}
	channelID, err := endpoint.Chain.ChannelOpenTry(ctx, msg)
	if err != nil {
		return err
	}

	endpoint.ChannelID = channelID

	return nil
}

// ChanOpenAck will construct and execute a MsgChannelOpenAck on the associated endpoint.
func (endpoint *Endpoint) ChanOpenAck(ctx context.Context) error {
	require.NoError(endpoint.Chain.T(), endpoint.UpdateClient(ctx))

	proofTry, err := endpoint.Counterparty.QueryChannelProof()
	require.NoError(endpoint.Chain.T(), err)

	msg := ibctestingtypes.MsgChannelOpenAck{
		PortID:                endpoint.ChannelConfig.PortID,
		ChannelID:             endpoint.ChannelID,
		CounterpartyChannelID: endpoint.Counterparty.ChannelID,
		CounterpartyVersion:   endpoint.Counterparty.ChannelConfig.Version,
		ProofTry:              proofTry,
		Signer:                endpoint.Chain.GetSenderAddress(),
	}

	return endpoint.Chain.ChannelOpenAck(ctx, msg)
}

// ChanOpenConfirm will construct and execute a MsgChannelOpenConfirm on the associated endpoint.
func (endpoint *Endpoint) ChanOpenConfirm(ctx context.Context) error {
	require.NoError(endpoint.Chain.T(), endpoint.UpdateClient(ctx))

	proofAck, err := endpoint.Counterparty.QueryChannelProof()
	require.NoError(endpoint.Chain.T(), err)

	msg := ibctestingtypes.MsgChannelOpenConfirm{
		PortID:    endpoint.ChannelConfig.PortID,
		ChannelID: endpoint.ChannelID,
		ProofAck:  proofAck,
		Signer:    endpoint.Chain.GetSenderAddress(),
	}

	return endpoint.Chain.ChannelOpenConfirm(ctx, msg)
}

// RecvPacket receives a packet on the associated endpoint.
// The counterparty client is updated.
func (endpoint *Endpoint) RecvPacket(ctx context.Context, packet exported.PacketI) error {
	// get proof of packet commitment on source
	proof, err := endpoint.Counterparty.QueryPacketProof(packet)
	if err != nil {
		return err
	}

	if err = endpoint.Chain.HandlePacketRecv(ctx, packet, proof); err != nil {
		return err
	}

	return endpoint.Counterparty.UpdateClient(ctx)
}

// AcknowledgePacket sends a MsgAcknowledgement to the channel associated with the endpoint.
func (endpoint *Endpoint) AcknowledgePacket(ctx context.Context, packet exported.PacketI, ack []byte) error {
	// get proof of acknowledgement on counterparty
	proof := endpoint.Counterparty.QueryAcknowledgePacketProof(packet, ack)

	return endpoint.Chain.HandlePacketAcknowledgement(ctx, packet, ack, proof)
}

// QueryConnectionHandshakeProof returns all the proofs necessary to execute OpenTry or Open Ack of
// the connection handshakes. It returns the counterparty client state, proof of the counterparty
// client state, proof of the counterparty consensus state, the consensus state height, proof of
// the counterparty connection, and the proof height for all the proofs returned.
func (endpoint *Endpoint) QueryConnectionHandshakeProof() (
	clientState []byte,
	proofClient *ibctestingtypes.Proof,
	proofConsensus *ibctestingtypes.Proof,
	consensusHeight exported.Height,
	proofConnection *ibctestingtypes.Proof,
) {
	// query proof for the client state on the counterparty
	clientState, proofClient = endpoint.Counterparty.QueryClientProof()

	consensusHeight = endpoint.Counterparty.Chain.GetLatestHeight(
		endpoint.Counterparty.ClientID,
		endpoint.Counterparty.ClientConfig.GetClientType(),
	)

	// query proof for the consensus state on the counterparty
	proofConsensus = endpoint.Counterparty.QueryConsensusProof(consensusHeight, proofClient.Height)

	// query proof for the connection on the counterparty
	proofConnection, err := endpoint.Counterparty.QueryConnectionProof(proofClient.Height)
	require.NoError(endpoint.Counterparty.Chain.T(), err)

	return
}

func (endpoint *Endpoint) QueryClientProof() ([]byte, *ibctestingtypes.Proof) {
	cs, found, err := endpoint.Chain.GetClientState(endpoint.ClientID)
	require.True(endpoint.Chain.T(), found)
	require.NoError(endpoint.Chain.T(), err)

	clientKey := endpoint.Chain.ClientStateCommitmentKey(endpoint.ClientID)
	proof := endpoint.QueryProof(clientKey)

	switch endpoint.Counterparty.ClientConfig.GetClientType() {
	case mocktypes.Mock:
		h := sha256.Sum256(cs)
		proof.Data = h[:]
	}

	return cs, proof
}

func (endpoint *Endpoint) QueryConsensusProof(consensusHeight exported.Height, proofHeight exported.Height) *ibctestingtypes.Proof {
	consensusKey := endpoint.Chain.ConsensusStateCommitmentKey(endpoint.ClientID, consensusHeight)
	proof := endpoint.QueryProofAtHeight(consensusKey, proofHeight)

	switch endpoint.Counterparty.ClientConfig.GetClientType() {
	case mocktypes.Mock:
		h := sha256.Sum256([]byte("dummy"))
		proof.Data = h[:]
	}

	return proof
}

func (endpoint *Endpoint) QueryConnectionProof(height exported.Height) (*ibctestingtypes.Proof, error) {
	connectionKey := endpoint.Chain.ConnectionStateCommitmentKey(endpoint.ConnectionID)
	proof := endpoint.QueryProofAtHeight(connectionKey, height)

	switch endpoint.Counterparty.ClientConfig.GetClientType() {
	case mocktypes.Mock:
		prover, ok := endpoint.Chain.(ibctestingtypes.MockProver)
		require.True(endpoint.Chain.T(), ok)

		var err error
		proof, err = prover.MockConnectionProof(endpoint.ConnectionID, proof)
		require.NoError(endpoint.Chain.T(), err)
	}

	return proof, nil
}

func (endpoint *Endpoint) QueryChannelProof() (*ibctestingtypes.Proof, error) {
	channelKey := endpoint.Chain.ChannelStateCommitmentKey(endpoint.ChannelConfig.PortID, endpoint.ChannelID)
	proof := endpoint.QueryProof(channelKey)

	switch endpoint.Counterparty.ClientConfig.GetClientType() {
	case mocktypes.Mock:
		prover, ok := endpoint.Chain.(ibctestingtypes.MockProver)
		require.True(endpoint.Chain.T(), ok)

		var err error
		proof, err = prover.MockChannelProof(endpoint.ChannelConfig.PortID, endpoint.ChannelID, proof)
		require.NoError(endpoint.Chain.T(), err)
	}
	return proof, nil
}

func (endpoint *Endpoint) QueryPacketProof(packet exported.PacketI) (*ibctestingtypes.Proof, error) {
	// get proof of packet commitment on source
	packetKey := endpoint.Chain.PacketCommitmentKey(
		packet.GetSourcePort(),
		packet.GetSourceChannel(),
		packet.GetSequence(),
	)
	proof := endpoint.QueryProof(packetKey)

	switch endpoint.ClientConfig.GetClientType() {
	case mocktypes.Mock:
		prover, ok := endpoint.Chain.(ibctestingtypes.MockProver)
		require.True(endpoint.Chain.T(), ok)

		var err error
		proof, err = prover.MockPacketProof(packet, proof)
		require.NoError(endpoint.Chain.T(), err)
	}

	return proof, nil
}

func (endpoint *Endpoint) QueryAcknowledgePacketProof(packet exported.PacketI, ack []byte) *ibctestingtypes.Proof {
	// get proof of packet commitment on source
	packetKey := endpoint.Chain.PacketAcknowledgementCommitmentKey(
		packet.GetDestPort(),
		packet.GetDestChannel(),
		packet.GetSequence(),
	)
	proof := endpoint.QueryProof(packetKey)

	switch endpoint.ClientConfig.GetClientType() {
	case mocktypes.Mock:
		prover, ok := endpoint.Chain.(ibctestingtypes.MockProver)
		require.True(endpoint.Chain.T(), ok)

		var err error
		proof, err = prover.MockAcknowledgementProof(ack, proof)
		require.NoError(endpoint.Chain.T(), err)
	}

	return proof
}

// QueryProof queries proof associated with this endpoint using the lastest client state
// height on the counterparty chain.
func (endpoint *Endpoint) QueryProof(key []byte) *ibctestingtypes.Proof {
	// obtain the counterparty client representing the chain associated with the endpoint
	height := endpoint.Counterparty.Chain.GetLatestHeight(
		endpoint.Counterparty.ClientID,
		endpoint.Counterparty.ClientConfig.GetClientType(),
	)

	// query proof on the counterparty using the latest height of the IBC client
	return endpoint.QueryProofAtHeight(key, height)
}

// QueryProofAtHeight queries proof associated with this endpoint using the proof height
// providied
func (endpoint *Endpoint) QueryProofAtHeight(key []byte, height exported.Height) *ibctestingtypes.Proof {
	// query proof on the counterparty using the latest height of the IBC client
	proof, err := endpoint.Chain.QueryProofAtHeight(
		key,
		height,
		endpoint.ClientConfig.GetClientType(),
	)
	require.NoError(endpoint.Chain.T(), err)

	return proof
}
