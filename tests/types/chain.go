package types

import (
	"context"

	channeltypes "github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/ibc/channel"
)

type TestChainI interface {
	Init() error

	ClientType() string
	UpdateHeader()

	AddTestConnection(clientID, counterpartyClientID string) *TestConnection
	AddTestChannel(conn *TestConnection, portID string) TestChannel

	ChainID() int64
	ChainIDString() string
	GetCommitmentPrefix() []byte

	CreateClient(
		ctx context.Context,
		counterparty TestChainI,
		clientType string,
	)(clientID string, err error)

	UpdateClient(
		ctx context.Context,
		counterparty TestChainI,
		clientID string,
	) error

	ConnectionOpenInit(
		ctx context.Context,
		counterparty TestChainI,
		connection,
		counterpartyConnection *TestConnection,
	) (string, error)

	ConnectionOpenTry(
		ctx context.Context,
		counterparty TestChainI,
		connection,
		counterpartyConnection *TestConnection,
	) (string, error)

	ConnectionOpenAck(
		ctx context.Context,
		counterparty TestChainI,
		connection, counterpartyConnection *TestConnection,
	) error

	ConnectionOpenConfirm(
		ctx context.Context,
		counterparty TestChainI,
		connection, counterpartyConnection *TestConnection,
	) error

	ChannelOpenInit(
		ctx context.Context,
		ch, counterparty TestChannel,
		order channeltypes.Channel_Order,
		connectionID string,
	) (string, error)

	ChannelOpenTry(
		ctx context.Context,
		counterparty TestChainI,
		ch, counterpartyCh TestChannel,
		order channeltypes.Channel_Order,
		connectionID string,
	) (string, error)

	ChannelOpenAck(
		ctx context.Context,
		counterparty TestChainI,
		ch, counterpartyCh TestChannel,
	) error

	ChannelOpenConfirm(
		ctx context.Context,
		counterparty TestChainI,
		ch, counterpartyCh TestChannel,
	) error

	SendPacket(
		ctx context.Context,
		packet channeltypes.Packet,
	) error

	RecvPacket(
		ctx context.Context,
		counterparty TestChainI,
		ch, counterpartyCh TestChannel,
		packet channeltypes.Packet,
	) error

	HandlePacketRecv(
		ctx context.Context,
		counterparty TestChainI,
		ch, counterpartyCh TestChannel,
		packet channeltypes.Packet,
	) error

	HandlePacketAcknowledgement(
		ctx context.Context,
		counterparty TestChainI,
		ch, counterpartyCh TestChannel,
		packet channeltypes.Packet,
		acknowledgement []byte,
	) error
}
