package ethereum

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/gogo/protobuf/proto"
	pbtypes "github.com/gogo/protobuf/types"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"

	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/client"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/contract/ibchandler"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/contract/ibchost"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/contract/ibcidentifier"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/contract/ics20bank"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/contract/ics20transferbank"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/contract/simpletoken"
	channeltypes "github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/ibc/channel"
	ibcclient "github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/ibc/client"
	mockclienttypes "github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/ibc/client/mock"
	connectiontypes "github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/ibc/connection"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/wallet"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing/types"
)

var (
	abiSendPacket,
	abiGeneratedClientIdentifier,
	abiGeneratedConnectionIdentifier,
	abiGeneratedChannelIdentifier abi.Event
)

func init() {
	parsedHandlerABI, err := abi.JSON(strings.NewReader(ibchandler.IbchandlerABI))
	if err != nil {
		panic(err)
	}
	parsedHostABI, err := abi.JSON(strings.NewReader(ibchost.IbchostABI))
	if err != nil {
		panic(err)
	}
	abiSendPacket = parsedHandlerABI.Events["SendPacket"]
	abiGeneratedClientIdentifier = parsedHostABI.Events["GeneratedClientIdentifier"]
	abiGeneratedConnectionIdentifier = parsedHostABI.Events["GeneratedConnectionIdentifier"]
	abiGeneratedChannelIdentifier = parsedHostABI.Events["GeneratedChannelIdentifier"]
}

var _ types.MockProver = (*Chain)(nil)
var _ types.TestChainI = (*Chain)(nil)

type Chain struct {
	t *testing.T

	// Core Modules
	chainClient   client.ChainClient
	IBCHandler    ibchandler.Ibchandler
	IBCHost       ibchost.Ibchost
	IBCIdentifier ibcidentifier.Ibcidentifier

	// App Modules
	SimpleToken   simpletoken.Simpletoken
	ICS20Transfer ics20transferbank.Ics20transferbank
	ICS20Bank     ics20bank.Ics20bank

	chainID int64

	ContractConfig ContractConfig

	mnemonicPhrase string
	keys           map[uint32]*ecdsa.PrivateKey

	// State
	LastContractState client.ContractState
}

type ContractConfig interface {
	GetIBCHostAddress() common.Address
	GetIBCHandlerAddress() common.Address
	GetIBCIdentifierAddress() common.Address
	GetIBFT2ClientAddress() common.Address
	GetMockClientAddress() common.Address

	GetSimpleTokenAddress() common.Address
	GetICS20TransferBankAddress() common.Address
	GetICS20BankAddress() common.Address
}

func NewChain(t *testing.T, chainID int64, chainClient client.ChainClient, config ContractConfig, mnemonicPhrase string, ibcID uint64) *Chain {
	ibcHost, err := ibchost.NewIbchost(config.GetIBCHostAddress(), chainClient)
	if err != nil {
		t.Error(err)
	}
	ibcHandler, err := ibchandler.NewIbchandler(config.GetIBCHandlerAddress(), chainClient)
	if err != nil {
		t.Error(err)
	}
	ibcIdentifier, err := ibcidentifier.NewIbcidentifier(config.GetIBCIdentifierAddress(), chainClient)
	if err != nil {
		t.Error(err)
	}
	simpletoken, err := simpletoken.NewSimpletoken(config.GetSimpleTokenAddress(), chainClient)
	if err != nil {
		t.Error(err)
	}
	ics20transfer, err := ics20transferbank.NewIcs20transferbank(config.GetICS20TransferBankAddress(), chainClient)
	if err != nil {
		t.Error(err)
	}
	ics20bank, err := ics20bank.NewIcs20bank(config.GetICS20BankAddress(), chainClient)
	if err != nil {
		t.Error(err)
	}

	return &Chain{
		t:              t,
		chainClient:    chainClient,
		chainID:        chainID,
		ContractConfig: config,
		mnemonicPhrase: mnemonicPhrase,
		keys:           make(map[uint32]*ecdsa.PrivateKey),

		IBCHost:       *ibcHost,
		IBCHandler:    *ibcHandler,
		IBCIdentifier: *ibcIdentifier,
		SimpleToken:   *simpletoken,
		ICS20Transfer: *ics20transfer,
		ICS20Bank:     *ics20bank,
	}
}

func (chain *Chain) T() *testing.T {
	return chain.t
}

func (chain *Chain) Init() error {
	return nil
}

func (chain *Chain) Client() client.ChainClient {
	return chain.chainClient
}

func (chain *Chain) TxOpts(ctx context.Context, index uint32) *bind.TransactOpts {
	return client.MakeGenTxOpts(big.NewInt(chain.chainID), chain.prvKey(index))(ctx)
}

func (chain *Chain) CallOpts(ctx context.Context, index uint32) *bind.CallOpts {
	opts := chain.TxOpts(ctx, index)
	return &bind.CallOpts{
		From:    opts.From,
		Context: opts.Context,
	}
}

func (chain *Chain) prvKey(index uint32) *ecdsa.PrivateKey {
	key, ok := chain.keys[index]
	if ok {
		return key
	}
	key, err := wallet.GetPrvKeyFromMnemonicAndHDWPath(chain.mnemonicPhrase, fmt.Sprintf("m/44'/60'/0'/0/%v", index))
	if err != nil {
		panic(err)
	}
	chain.keys[index] = key
	return key
}

func (chain *Chain) ChainID() int64 {
	return chain.chainID
}

func (chain *Chain) ChainIDString() string {
	return fmt.Sprint(chain.chainID)
}

func (chain *Chain) GetCommitmentPrefix() []byte {
	return []byte(types.DefaultPrefix)
}

func (chain *Chain) GetSenderAddress() string {
	return ""
}

func (chain *Chain) NextBlock() {

}

func (chain *Chain) GetClientState(clientID string) ([]byte, bool, error) {
	return chain.IBCHost.GetClientState(
		chain.CallOpts(context.Background(), types.RelayerKeyIndex),
		clientID,
	)
}

func (chain *Chain) GetLatestHeight(clientID string, clientType string) (height exported.Height) {
	var rh uint64
	switch clientType {
	case ibcclient.MockClient:
		rh = chain.GetMockClientState(clientID).LatestHeight
	default:
		panic(fmt.Errorf("unknown chainClient type: '%v'", clientType))
	}

	return clienttypes.Height{
		RevisionNumber: 0,
		RevisionHeight: rh,
	}
}

func (chain *Chain) UpdateHeader(clientType string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		state, err := chain.chainClient.GetContractState(
			ctx,
			chain.ContractConfig.GetIBCHostAddress(),
			nil,
			nil,
			clientType,
		)
		if err != nil {
			panic(err)
		}
		if chain.LastContractState == nil || state.Header().Number.Cmp(chain.LastHeader().Number) == 1 {
			chain.LastContractState = state
			return
		} else {
			continue
		}
	}
}

func (chain *Chain) GetConnection(connectionID string) (ibchost.ConnectionEndData, bool, error) {
	return chain.IBCHost.GetConnection(
		chain.CallOpts(context.Background(), types.RelayerKeyIndex),
		connectionID,
	)
}

func (chain *Chain) GetChannel(portID, channelID string) (ibchost.ChannelData, bool, error) {
	return chain.IBCHost.GetChannel(
		chain.CallOpts(context.Background(), types.RelayerKeyIndex),
		portID, channelID,
	)
}

func (chain *Chain) GetMockClientState(clientID string) *mockclienttypes.ClientState {
	ctx := context.Background()
	bz, found, err := chain.IBCHost.GetClientState(chain.CallOpts(ctx, types.RelayerKeyIndex), clientID)
	if err != nil {
		require.NoError(chain.t, err)
	} else if !found {
		panic("clientState not found")
	}
	var cs mockclienttypes.ClientState
	if err := UnmarshalWithAny(bz, &cs); err != nil {
		panic(err)
	}
	return &cs
}

func (chain *Chain) GetContractState(
	storageKeys [][]byte,
	height *big.Int,
	clientType string,
) (client.ContractState, error) {
	return chain.chainClient.GetContractState(
		context.Background(),
		chain.ContractConfig.GetIBCHostAddress(),
		storageKeys,
		height,
		clientType,
	)
}

func (chain *Chain) ConstructMockMsgCreateClient() types.MsgCreateClient {
	clientState := mockclienttypes.ClientState{
		LatestHeight: chain.LastHeader().Number.Uint64(),
	}
	consensusState := mockclienttypes.ConsensusState{
		Timestamp: chain.LastHeader().Time,
	}
	clientStateBytes, err := MarshalWithAny(&clientState)
	if err != nil {
		panic(err)
	}
	consensusStateBytes, err := MarshalWithAny(&consensusState)
	if err != nil {
		panic(err)
	}
	return types.MsgCreateClient{
		ClientType:          ibcclient.MockClient,
		Height:              clienttypes.NewHeight(0, clientState.LatestHeight),
		ClientStateBytes:    clientStateBytes,
		ConsensusStateBytes: consensusStateBytes,
	}
}

func (chain *Chain) CreateClient(ctx context.Context, msg types.MsgCreateClient) (string, error) {
	if err := chain.WaitIfNoError(ctx)(
		chain.IBCHandler.CreateClient(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgCreateClient{
				ClientType:          msg.ClientType,
				Height:              msg.Height.GetRevisionHeight(),
				ClientStateBytes:    msg.ClientStateBytes,
				ConsensusStateBytes: msg.ConsensusStateBytes,
			}),
	); err != nil {
		return "", err
	}
	return chain.GetLastGeneratedClientID(ctx)
}

func (chain *Chain) ConstructMockMsgUpdateClient(clientID string) types.MsgUpdateClient {
	cs := chain.LastContractState.(client.ETHContractState)
	header := mockclienttypes.Header{
		Height:    cs.Header().Number.Uint64(),
		Timestamp: cs.Header().Time,
	}
	bz, err := MarshalWithAny(&header)
	if err != nil {
		panic(err)
	}
	return types.MsgUpdateClient{
		ClientID: clientID,
		Header:   bz,
	}
}

func (chain *Chain) UpdateClient(ctx context.Context, msg types.MsgUpdateClient) error {
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.UpdateClient(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgUpdateClient{
				ClientId: msg.ClientID,
				Header:   msg.Header,
			}),
	)
}

func (chain *Chain) ConnectionOpenInit(ctx context.Context, msg types.MsgConnectionOpenInit) (string, error) {
	if err := chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ConnectionOpenInit(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgConnectionOpenInit{
				ClientId: msg.ClientID,
				Counterparty: ibchandler.CounterpartyData{
					ClientId:     msg.CounterpartyClientID,
					ConnectionId: "",
					Prefix:       ibchandler.MerklePrefixData{KeyPrefix: msg.CounterpartyKeyPrefix},
				},
				DelayPeriod: msg.DelayPeriod,
			},
		),
	); err != nil {
		return "", err
	}
	return chain.GetLastGeneratedConnectionID(ctx)
}

func (chain *Chain) ConnectionOpenTry(ctx context.Context, msg types.MsgConnectionOpenTry) (string, error) {
	if err := chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ConnectionOpenTry(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgConnectionOpenTry{
				PreviousConnectionId: "",
				Counterparty: ibchandler.CounterpartyData{
					ClientId:     msg.CounterpartyClientID,
					ConnectionId: msg.CounterpartyConnectionID,
					Prefix:       ibchandler.MerklePrefixData{KeyPrefix: msg.CounterpartyKeyPrefix},
				},
				DelayPeriod:      types.DefaultDelayPeriod,
				ClientId:         msg.ClientID,
				ClientStateBytes: msg.ClientStateBytes,
				CounterpartyVersions: []ibchandler.VersionData{{
					Identifier: msg.Versions[0].GetIdentifier(),
					Features:   msg.Versions[0].GetFeatures(),
				}},
				ProofInit:   msg.ProofInit.Data,
				ProofHeight: msg.ProofInit.Height.GetRevisionHeight(),
				ProofClient: msg.ProofClient.Data,
				// TODO
				//ProofConsensus:  msg.ProofConsensus.Data,
				//ConsensusHeight: msg.ProofConsensus.Height.RevisionHeight,
			},
		),
	); err != nil {
		return "", err
	}
	return chain.GetLastGeneratedConnectionID(ctx)
}

// ConnectionOpenAck will construct and execute a MsgConnectionOpenAck.
func (chain *Chain) ConnectionOpenAck(ctx context.Context, msg types.MsgConnectionOpenAck) error {
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ConnectionOpenAck(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgConnectionOpenAck{
				ConnectionId:             msg.ConnectionID,
				CounterpartyConnectionID: msg.CounterpartyConnectionID,
				ClientStateBytes:         msg.ClientStateBytes,
				Version: ibchandler.VersionData{
					Identifier: msg.Version.GetIdentifier(),
					Features:   msg.Version.GetFeatures(),
				},
				ProofHeight: msg.ProofClient.Height.GetRevisionHeight(),
				ProofTry:    msg.ProofTry.Data,
				ProofClient: msg.ProofClient.Data,
				// TODO
				//ProofConsensus:  msg.ProofConsensus.Data,
				//ConsensusHeight: msg.ProofConsensus.Height.GetRevisionHeight(),
			},
		),
	)
}

func (chain *Chain) ConnectionOpenConfirm(ctx context.Context, msg types.MsgConnectionOpenConfirm) error {
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ConnectionOpenConfirm(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgConnectionOpenConfirm{
				ConnectionId: msg.ConnectionID,
				ProofAck:     msg.ProofAck.Data,
				ProofHeight:  msg.ProofAck.Height.GetRevisionHeight(),
			},
		),
	)
}

func (chain *Chain) ChannelOpenInit(ctx context.Context, msg types.MsgChannelOpenInit) (string, error) {
	if err := chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ChannelOpenInit(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgChannelOpenInit{
				PortId: msg.PortID,
				Channel: ibchandler.ChannelData{
					State:    uint8(channeltypes.INIT),
					Ordering: uint8(msg.Order),
					Counterparty: ibchandler.ChannelCounterpartyData{
						PortId:    msg.CounterpartyPortID,
						ChannelId: "",
					},
					ConnectionHops: msg.ConnectionHops,
					Version:        msg.Version,
				},
			},
		),
	); err != nil {
		return "", err
	}
	return chain.GetLastGeneratedChannelID(ctx)
}

func (chain *Chain) ChannelOpenTry(ctx context.Context, msg types.MsgChannelOpenTry) (string, error) {
	if err := chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ChannelOpenTry(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgChannelOpenTry{
				PortId: msg.PortID,
				Channel: ibchandler.ChannelData{
					State:    uint8(channeltypes.TRYOPEN),
					Ordering: uint8(msg.Ordering),
					Counterparty: ibchandler.ChannelCounterpartyData{
						PortId:    msg.CounterpartyPortID,
						ChannelId: msg.CounterpartyChannelID,
					},
					ConnectionHops: msg.ConnectionHops,
					Version:        msg.Version,
				},
				CounterpartyVersion: msg.CounterpartyVersion,
				ProofInit:           msg.ProofInit.Data,
				ProofHeight:         msg.ProofInit.Height.GetRevisionHeight(),
				PreviousChannelId:   msg.PreviousChannelID,
			},
		),
	); err != nil {
		return "", err
	}
	return chain.GetLastGeneratedChannelID(ctx)
}

func (chain *Chain) ChannelOpenAck(ctx context.Context, msg types.MsgChannelOpenAck) error {
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ChannelOpenAck(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgChannelOpenAck{
				PortId:                msg.PortID,
				ChannelId:             msg.ChannelID,
				CounterpartyVersion:   msg.CounterpartyVersion,
				CounterpartyChannelId: msg.CounterpartyChannelID,
				ProofTry:              msg.ProofTry.Data,
				ProofHeight:           msg.ProofTry.Height.GetRevisionHeight(),
			},
		),
	)
}

func (chain *Chain) ChannelOpenConfirm(ctx context.Context, msg types.MsgChannelOpenConfirm) error {
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ChannelOpenConfirm(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgChannelOpenConfirm{
				PortId:      msg.PortID,
				ChannelId:   msg.ChannelID,
				ProofAck:    msg.ProofAck.Data,
				ProofHeight: msg.ProofAck.Height.GetRevisionHeight(),
			},
		),
	)
}

func (chain *Chain) SendPacket(ctx context.Context, packet exported.PacketI) error {
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.SendPacket(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			packetToCallData(packet),
		),
	)
}

func (chain *Chain) HandlePacketRecv(
	ctx context.Context,
	packet exported.PacketI,
	proof *types.Proof,
) error {
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.RecvPacket(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgPacketRecv{
				Packet:      packetToCallData(packet),
				Proof:       proof.Data,
				ProofHeight: proof.Height.GetRevisionHeight(),
			},
		),
	)
}

func (chain *Chain) HandlePacketAcknowledgement(
	ctx context.Context,
	packet exported.PacketI,
	acknowledgement []byte,
	proof *types.Proof,
) error {
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.AcknowledgePacket(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgPacketAcknowledgement{
				Packet:          packetToCallData(packet),
				Acknowledgement: acknowledgement,
				Proof:           proof.Data,
				ProofHeight:     proof.Height.GetRevisionHeight(),
			},
		),
	)
}

func (chain *Chain) GetLastGeneratedClientID(
	ctx context.Context,
) (string, error) {
	return chain.getLastID(ctx, abiGeneratedClientIdentifier)
}

func (chain *Chain) GetLastGeneratedConnectionID(
	ctx context.Context,
) (string, error) {
	return chain.getLastID(ctx, abiGeneratedConnectionIdentifier)
}

func (chain *Chain) GetLastGeneratedChannelID(
	ctx context.Context,
) (string, error) {
	return chain.getLastID(ctx, abiGeneratedChannelIdentifier)
}

func (chain *Chain) getLastID(ctx context.Context, event abi.Event) (string, error) {
	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(0),
		Addresses: []common.Address{
			chain.ContractConfig.GetIBCHostAddress(),
		},
		Topics: [][]common.Hash{{
			event.ID,
		}},
	}
	logs, err := chain.chainClient.FilterLogs(ctx, query)
	if err != nil {
		return "", err
	}
	if len(logs) == 0 {
		return "", errors.New("no items")
	}
	log := logs[len(logs)-1]
	values, err := event.Inputs.Unpack(log.Data)
	if err != nil {
		return "", err
	}
	return values[0].(string), nil
}

func (chain *Chain) GetLastSentPacket(
	ctx context.Context,
	sourcePortID string,
	sourceChannel string,
) (exported.PacketI, error) {
	seq, err := chain.IBCHost.GetNextSequenceSend(chain.CallOpts(ctx, types.RelayerKeyIndex), sourcePortID, sourceChannel)
	if err != nil {
		return nil, err
	}
	return chain.FindPacket(ctx, sourcePortID, sourceChannel, seq-1)
}

func (chain *Chain) FindPacket(
	ctx context.Context,
	sourcePortID string,
	sourceChannel string,
	sequence uint64,
) (*channeltypes.Packet, error) {
	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(0),
		Addresses: []common.Address{
			chain.ContractConfig.GetIBCHandlerAddress(),
		},
		Topics: [][]common.Hash{{
			abiSendPacket.ID,
		}},
	}
	logs, err := chain.chainClient.FilterLogs(ctx, query)
	if err != nil {
		return nil, err
	}

	for _, log := range logs {
		if values, err := abiSendPacket.Inputs.Unpack(log.Data); err != nil {
			return nil, err
		} else {
			p := values[0].(struct {
				Sequence           uint64  "json:\"sequence\""
				SourcePort         string  "json:\"source_port\""
				SourceChannel      string  "json:\"source_channel\""
				DestinationPort    string  "json:\"destination_port\""
				DestinationChannel string  "json:\"destination_channel\""
				Data               []uint8 "json:\"data\""
				TimeoutHeight      struct {
					RevisionNumber uint64 "json:\"revision_number\""
					RevisionHeight uint64 "json:\"revision_height\""
				} "json:\"timeout_height\""
				TimeoutTimestamp uint64 "json:\"timeout_timestamp\""
			})
			if p.SourcePort == sourcePortID && p.SourceChannel == sourceChannel && p.Sequence == sequence {
				return &channeltypes.Packet{
					Sequence:           p.Sequence,
					SourcePort:         p.SourcePort,
					SourceChannel:      p.SourceChannel,
					DestinationPort:    p.DestinationPort,
					DestinationChannel: p.DestinationChannel,
					Data:               p.Data,
					TimeoutHeight:      channeltypes.Height(p.TimeoutHeight),
					TimeoutTimestamp:   p.TimeoutTimestamp,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("packet not found: sourcePortID=%v sourceChannel=%v sequence=%v", sourcePortID, sourceChannel, sequence)
}

func packetToCallData(packet exported.PacketI) ibchandler.PacketData {
	return ibchandler.PacketData{
		Sequence:           packet.GetSequence(),
		SourcePort:         packet.GetSourcePort(),
		SourceChannel:      packet.GetSourceChannel(),
		DestinationPort:    packet.GetDestPort(),
		DestinationChannel: packet.GetDestChannel(),
		Data:               packet.GetData(),
		TimeoutHeight: ibchandler.HeightData{
			RevisionNumber: packet.GetTimeoutHeight().GetRevisionNumber(),
			RevisionHeight: packet.GetTimeoutHeight().GetRevisionHeight(),
		},
		TimeoutTimestamp: packet.GetTimeoutTimestamp(),
	}
}

func PackAny(msg proto.Message) (*pbtypes.Any, error) {
	var any pbtypes.Any
	any.TypeUrl = "/" + proto.MessageName(msg)

	bz, err := proto.Marshal(msg)
	if err != nil {
		return nil, err
	}
	any.Value = bz
	return &any, nil
}

func UnpackAny(bz []byte) (*pbtypes.Any, error) {
	var any pbtypes.Any
	if err := proto.Unmarshal(bz, &any); err != nil {
		return nil, err
	}
	return &any, nil
}

func MarshalWithAny(msg proto.Message) ([]byte, error) {
	any, err := PackAny(msg)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(any)
}

func UnmarshalWithAny(bz []byte, msg proto.Message) error {
	any, err := UnpackAny(bz)
	if err != nil {
		return err
	}
	if t := "/" + proto.MessageName(msg); any.TypeUrl != t {
		return fmt.Errorf("expected %v, but got %v", t, any.TypeUrl)
	}
	return proto.Unmarshal(any.Value, msg)
}

// Slot calculator

func (chain *Chain) ClientStateCommitmentKey(clientID string) []byte {
	key, err := chain.IBCIdentifier.ClientStateCommitmentSlot(chain.CallOpts(context.Background(), types.RelayerKeyIndex), clientID)
	require.NoError(chain.t, err)
	return []byte("0x" + hex.EncodeToString(key[:]))
}

func (chain *Chain) ConsensusStateCommitmentKey(clientID string, height exported.Height) []byte {
	key, err := chain.IBCIdentifier.ConsensusStateCommitmentSlot(
		chain.CallOpts(context.Background(), types.RelayerKeyIndex), clientID, height.GetRevisionHeight(),
	)
	require.NoError(chain.t, err)
	return []byte("0x" + hex.EncodeToString(key[:]))
}

func (chain *Chain) ConnectionStateCommitmentKey(connectionID string) []byte {
	key, err := chain.IBCIdentifier.ConnectionCommitmentSlot(chain.CallOpts(context.Background(), types.RelayerKeyIndex), connectionID)
	require.NoError(chain.t, err)
	return []byte("0x" + hex.EncodeToString(key[:]))
}

func (chain *Chain) ChannelStateCommitmentKey(portID, channelID string) []byte {
	key, err := chain.IBCIdentifier.ChannelCommitmentSlot(chain.CallOpts(context.Background(), types.RelayerKeyIndex), portID, channelID)
	require.NoError(chain.t, err)
	return []byte("0x" + hex.EncodeToString(key[:]))
}

func (chain *Chain) PacketCommitmentKey(portID, channelID string, sequence uint64) []byte {
	key, err := chain.IBCIdentifier.PacketCommitmentSlot(chain.CallOpts(context.Background(), types.RelayerKeyIndex), portID, channelID, sequence)
	require.NoError(chain.t, err)
	return []byte("0x" + hex.EncodeToString(key[:]))
}

func (chain *Chain) PacketAcknowledgementCommitmentKey(portID, channelID string, sequence uint64) []byte {
	key, err := chain.IBCIdentifier.PacketAcknowledgementCommitmentSlot(chain.CallOpts(context.Background(), types.RelayerKeyIndex), portID, channelID, sequence)
	require.NoError(chain.t, err)
	return []byte("0x" + hex.EncodeToString(key[:]))
}

// Querier
func (chain *Chain) QueryProofAtHeight(storageKeyBytes []byte, height exported.Height, clientType string) (*types.Proof, error) {
	storageKey := string(storageKeyBytes)
	if !strings.HasPrefix(storageKey, "0x") {
		return nil, fmt.Errorf("storageKey must be hex string")
	}
	s, err := chain.GetContractState([][]byte{[]byte(storageKey)}, big.NewInt(int64(height.GetRevisionHeight())), clientType)
	if err != nil {
		return nil, err
	}
	return &types.Proof{
		Height: height,
		Data:   s.ETHProof().StorageProofRLP[0],
	}, nil
}

func (chain *Chain) LastHeader() *gethtypes.Header {
	return chain.LastContractState.Header()
}

func (chain *Chain) WaitForReceiptAndGet(ctx context.Context, tx *gethtypes.Transaction) error {
	rc, err := chain.Client().WaitForReceiptAndGet(ctx, tx)
	if err != nil {
		return err
	}
	if rc.Status() == 1 {
		return nil
	} else {
		return fmt.Errorf("failed to call transaction: err='%v' rc='%v' reason='%v'", err, rc, rc.RevertReason())
	}
}

func (chain *Chain) WaitIfNoError(ctx context.Context) func(tx *gethtypes.Transaction, err error) error {
	return func(tx *gethtypes.Transaction, err error) error {
		if err != nil {
			return err
		}
		if err := chain.WaitForReceiptAndGet(ctx, tx); err != nil {
			return err
		}
		return nil
	}
}

func (chain *Chain) MockConnectionProof(connectionID string, proof *types.Proof) (*types.Proof, error) {
	conn, found, err := chain.GetConnection(connectionID)
	if err != nil {
		return nil, err
	} else if !found {
		return nil, fmt.Errorf("connection not found: %v", connectionID)
	}
	bz, err := proto.Marshal(connectionEndToPB(conn))
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(bz)
	proof.Data = h[:]

	return proof, nil
}

func (chain *Chain) MockChannelProof(portID string, channelID string, proof *types.Proof) (*types.Proof, error) {
	ch, found, err := chain.GetChannel(portID, channelID)
	if err != nil {
		return nil, err
	} else if !found {
		return nil, fmt.Errorf("channel not found: %v:%v", portID, channelID)
	}
	bz, err := proto.Marshal(channelToPB(ch))
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(bz)
	proof.Data = h[:]

	return proof, nil
}

func (chain *Chain) MockPacketProof(packet exported.PacketI, proof *types.Proof) (*types.Proof, error) {
	proof.Data = commitPacket(packet)
	return proof, nil
}

func (chain *Chain) MockAcknowledgementProof(ack []byte, proof *types.Proof) (*types.Proof, error) {
	proof.Data = commitAcknowledgement(ack)
	return proof, nil
}

func connectionEndToPB(conn ibchost.ConnectionEndData) *connectiontypes.ConnectionEnd {
	connpb := &connectiontypes.ConnectionEnd{
		ClientId:    conn.ClientId,
		Versions:    []*connectiontypes.Version{},
		State:       connectiontypes.ConnectionEnd_State(conn.State),
		DelayPeriod: conn.DelayPeriod,
		Counterparty: &connectiontypes.Counterparty{
			ClientId:     conn.Counterparty.ClientId,
			ConnectionId: conn.Counterparty.ConnectionId,
			Prefix:       (*connectiontypes.MerklePrefix)(&conn.Counterparty.Prefix),
		},
	}
	for _, v := range conn.Versions {
		ver := connectiontypes.Version(v)
		connpb.Versions = append(connpb.Versions, &ver)
	}
	return connpb
}

func channelToPB(ch ibchost.ChannelData) *channeltypes.Channel {
	return &channeltypes.Channel{
		State:          channeltypes.Channel_State(ch.State),
		Ordering:       channeltypes.Channel_Order(ch.Ordering),
		Counterparty:   channeltypes.Channel_Counterparty(ch.Counterparty),
		ConnectionHops: ch.ConnectionHops,
		Version:        ch.Version,
	}
}

// uint64ToBigEndian - marshals uint64 to a bigendian byte slice so it can be sorted
func uint64ToBigEndian(i uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, i)
	return b
}

// commitPacket returns the packet commitment bytes. The commitment consists of:
// sha256_hash(timeout_timestamp + timeout_height.RevisionNumber + timeout_height.RevisionHeight + sha256_hash(data))
// from a given packet. This results in a fixed length preimage.
// NOTE: uint64ToBigEndian sets the uint64 to a slice of length 8.
func commitPacket(packet exported.PacketI) []byte {
	timeoutHeight := packet.GetTimeoutHeight()

	buf := uint64ToBigEndian(packet.GetTimeoutTimestamp())

	revisionNumber := uint64ToBigEndian(timeoutHeight.GetRevisionNumber())
	buf = append(buf, revisionNumber...)

	revisionHeight := uint64ToBigEndian(timeoutHeight.GetRevisionHeight())
	buf = append(buf, revisionHeight...)

	dataHash := sha256.Sum256(packet.GetData())
	buf = append(buf, dataHash[:]...)

	hash := sha256.Sum256(buf)
	return hash[:]
}

// commitAcknowledgement returns the hash of commitment bytes
func commitAcknowledgement(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
