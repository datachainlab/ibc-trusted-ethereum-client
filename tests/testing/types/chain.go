package types

import (
	"context"
	"testing"

	"github.com/cosmos/ibc-go/modules/core/exported"
)

type TestChainI interface {
	T() *testing.T

	Init() error

	ChainID() int64
	ChainIDString() string
	GetCommitmentPrefix() []byte
	GetSenderAddress() string

	NextBlock()

	GetClientState(counterpartyClientID string) ([]byte, bool, error)
	GetLatestHeight(counterpartyClientID string, clientType string) exported.Height

	UpdateHeader(clientType string)

	ConstructMockMsgCreateClient() MsgCreateClient
	CreateClient(ctx context.Context, msg MsgCreateClient) (string, error)
	ConstructMockMsgUpdateClient(clientID string) MsgUpdateClient
	UpdateClient(ctx context.Context, msg MsgUpdateClient) error

	ConnectionOpenInit(ctx context.Context, msg MsgConnectionOpenInit) (string, error)
	ConnectionOpenTry(ctx context.Context, msg MsgConnectionOpenTry) (string, error)
	ConnectionOpenAck(ctx context.Context, msg MsgConnectionOpenAck) error
	ConnectionOpenConfirm(ctx context.Context, msg MsgConnectionOpenConfirm) error

	ChannelOpenInit(ctx context.Context, msg MsgChannelOpenInit) (string, error)
	ChannelOpenTry(ctx context.Context, msg MsgChannelOpenTry) (string, error)
	ChannelOpenAck(ctx context.Context, msg MsgChannelOpenAck) error
	ChannelOpenConfirm(ctx context.Context, msg MsgChannelOpenConfirm) error

	SendPacket(ctx context.Context, packet exported.PacketI) error
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
