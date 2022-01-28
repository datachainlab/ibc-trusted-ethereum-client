package types

import (
	"context"
	"testing"
	"time"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	ibctmtypes "github.com/cosmos/ibc-go/modules/light-clients/07-tendermint/types"
)

type TestChainI interface {
	T() *testing.T

	Init(chainID string) error

	ChainID() string
	GetCommitmentPrefix() []byte
	GetSenderAddress() string

	NextBlock()

	GetClientStateBytes(counterpartyClientID string) []byte
	GetLatestHeight(counterpartyClientID string, clientType string) exported.Height

	ConstructTendermintMsgCreateClient(
		trustLevel ibctmtypes.Fraction,
		trustingPeriod, unbondingPeriod, maxClockDrift time.Duration,
		upgradePath []string, allowUpdateAfterExpiry, allowUpdateAfterMisbehaviour bool) MsgCreateClient
	ConstructMockMsgCreateClient() MsgCreateClient
	ConstructTrustedEthereumMsgCreateClient(publicKey cryptotypes.PubKey, diversifier string) MsgCreateClient

	CreateClient(ctx context.Context, msg MsgCreateClient) (string, error)

	ConstructTendermintUpdateTMClientHeader(counterparty TestChainI, clientID string) MsgUpdateClient
	ConstructMockMsgUpdateClient(clientID string) MsgUpdateClient
	ConstructTrustedEthereumMsgUpdateClient(clientID string, privateKey cryptotypes.PrivKey, divisifier string) MsgUpdateClient

	UpdateClient(ctx context.Context, msg MsgUpdateClient) error

	ConnectionOpenInit(ctx context.Context, msg MsgConnectionOpenInit) (string, error)
	ConnectionOpenTry(ctx context.Context, msg MsgConnectionOpenTry) (string, error)
	ConnectionOpenAck(ctx context.Context, msg MsgConnectionOpenAck) error
	ConnectionOpenConfirm(ctx context.Context, msg MsgConnectionOpenConfirm) error

	ChannelOpenInit(ctx context.Context, msg MsgChannelOpenInit) (string, error)
	ChannelOpenTry(ctx context.Context, msg MsgChannelOpenTry) (string, error)
	ChannelOpenAck(ctx context.Context, msg MsgChannelOpenAck) error
	ChannelOpenConfirm(ctx context.Context, msg MsgChannelOpenConfirm) error

	HandlePacketRecv(ctx context.Context, packet exported.PacketI, proof *Proof) error
	HandlePacketAcknowledgement(
		ctx context.Context,
		packet exported.PacketI,
		acknowledgement []byte,
		proof *Proof,
	) error

	ClientStateCommitmentKey(clientID string) []byte
	ConsensusStateCommitmentKey(clientID string, height exported.Height) []byte
	ConnectionStateCommitmentKey(connectionID string) []byte
	ChannelStateCommitmentKey(portID, channelID string) []byte
	PacketCommitmentKey(portID, channelID string, sequence uint64) []byte
	PacketAcknowledgementCommitmentKey(portID, channelID string, sequence uint64) []byte

	QueryProofAtHeight(key []byte, height exported.Height, clientType string) (*Proof, error)
}

type MockProver interface {
	MockConnectionProof(connectionID string, proof *Proof) (*Proof, error)
	MockChannelProof(portID string, channelID string, proof *Proof) (*Proof, error)
	MockPacketProof(packet exported.PacketI, proof *Proof) (*Proof, error)
	MockAcknowledgementProof(ack []byte, proof *Proof) (*Proof, error)
}
