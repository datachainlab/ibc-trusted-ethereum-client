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
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/types"
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

//var _ types.TestChainI = (*Chain)(nil)

type Chain struct {
	t *testing.T

	// Core Modules
	client        client.Client
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

	// IBC specific helpers
	ClientIDs   []string                // ClientID's used on this chain
	Connections []*types.TestConnection // track connectionID's created for this chain
	IBCID       uint64
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

func NewChain(t *testing.T, chainID int64, client client.Client, config ContractConfig, mnemonicPhrase string, ibcID uint64) *Chain {
	ibcHost, err := ibchost.NewIbchost(config.GetIBCHostAddress(), client)
	if err != nil {
		t.Error(err)
	}
	ibcHandler, err := ibchandler.NewIbchandler(config.GetIBCHandlerAddress(), client)
	if err != nil {
		t.Error(err)
	}
	ibcIdentifier, err := ibcidentifier.NewIbcidentifier(config.GetIBCIdentifierAddress(), client)
	if err != nil {
		t.Error(err)
	}
	simpletoken, err := simpletoken.NewSimpletoken(config.GetSimpleTokenAddress(), client)
	if err != nil {
		t.Error(err)
	}
	ics20transfer, err := ics20transferbank.NewIcs20transferbank(config.GetICS20TransferBankAddress(), client)
	if err != nil {
		t.Error(err)
	}
	ics20bank, err := ics20bank.NewIcs20bank(config.GetICS20BankAddress(), client)
	if err != nil {
		t.Error(err)
	}

	return &Chain{
		t:              t,
		client:         client,
		chainID:        chainID,
		ContractConfig: config,
		mnemonicPhrase: mnemonicPhrase,
		keys:           make(map[uint32]*ecdsa.PrivateKey),
		IBCID:          ibcID,

		IBCHost:       *ibcHost,
		IBCHandler:    *ibcHandler,
		IBCIdentifier: *ibcIdentifier,
		SimpleToken:   *simpletoken,
		ICS20Transfer: *ics20transfer,
		ICS20Bank:     *ics20bank,
	}
}

func (chain *Chain) Client() client.Client {
	return chain.client
}

func (chain *Chain) ClientType() string {
	return chain.client.ClientType()
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

func (chain *Chain) GetContractState(counterparty *Chain, counterpartyClientID string, storageKeys [][]byte, height *big.Int) (client.ContractState, error) {
	if height == nil {
		switch counterparty.ClientType() {
		case ibcclient.MockClient:
			height = big.NewInt(int64(counterparty.GetMockClientState(counterpartyClientID).LatestHeight))
		default:
			return nil, fmt.Errorf("unknown client type: '%v'", counterparty.ClientType())
		}
	}
	return chain.client.GetContractState(
		context.Background(),
		chain.ContractConfig.GetIBCHostAddress(),
		storageKeys,
		height,
	)
}

func (chain *Chain) Init() error {
	//ctx := context.Background()
	//if err := chain.WaitIfNoError(ctx)(
	//	chain.IBCHost.SetIBCModule(
	//		chain.TxOpts(ctx, types.RelayerKeyIndex),
	//		chain.ContractConfig.GetIBCHandlerAddress(),
	//	),
	//); err != nil {
	//	return err
	//}
	//
	//if name, err := chain.IBCIdentifier.PortCapabilityPath(chain.CallOpts(ctx, types.RelayerKeyIndex), types.TransferPort); err != nil {
	//	return err
	//} else if _, found, err := chain.IBCHost.GetModuleOwner(chain.CallOpts(ctx, types.RelayerKeyIndex), name); err != nil {
	//	return err
	//} else if !found {
	//	if err := chain.WaitIfNoError(ctx)(
	//		chain.IBCHandler.BindPort(chain.TxOpts(ctx, types.RelayerKeyIndex), types.TransferPort, chain.ContractConfig.GetICS20TransferBankAddress()),
	//	); err != nil {
	//		return err
	//	}
	//}
	//
	//if _, found, err := chain.IBCHost.GetClientImpl(chain.CallOpts(ctx, types.RelayerKeyIndex), ibcclient.MockClient); err != nil {
	//	return err
	//} else if !found {
	//	if err := chain.WaitIfNoError(ctx)(
	//		chain.IBCHandler.RegisterClient(
	//			chain.TxOpts(ctx, types.RelayerKeyIndex),
	//			ibcclient.MockClient,
	//			chain.ContractConfig.GetMockClientAddress(),
	//		),
	//	); err != nil {
	//		return err
	//	}
	//}
	//
	//if err := chain.WaitIfNoError(ctx)(
	//	chain.ICS20Bank.SetOperator(chain.TxOpts(ctx, types.RelayerKeyIndex), chain.ContractConfig.GetICS20TransferBankAddress()),
	//); err != nil {
	//	return err
	//}

	return nil
}

func (chain *Chain) ConstructMockMsgCreateClient(counterparty *Chain) ibchandler.IBCMsgsMsgCreateClient {
	clientState := mockclienttypes.ClientState{
		LatestHeight: counterparty.LastHeader().Number.Uint64(),
	}
	consensusState := mockclienttypes.ConsensusState{
		Timestamp: counterparty.LastHeader().Time,
	}
	clientStateBytes, err := MarshalWithAny(&clientState)
	if err != nil {
		panic(err)
	}
	consensusStateBytes, err := MarshalWithAny(&consensusState)
	if err != nil {
		panic(err)
	}
	return ibchandler.IBCMsgsMsgCreateClient{
		ClientType:          ibcclient.MockClient,
		Height:              clientState.LatestHeight,
		ClientStateBytes:    clientStateBytes,
		ConsensusStateBytes: consensusStateBytes,
	}
}

func (chain *Chain) ConstructMockMsgUpdateClient(counterparty *Chain, clientID string) ibchandler.IBCMsgsMsgUpdateClient {
	cs := counterparty.LastContractState.(client.ETHContractState)
	header := mockclienttypes.Header{
		Height:    cs.Header().Number.Uint64(),
		Timestamp: cs.Header().Time,
	}
	bz, err := MarshalWithAny(&header)
	if err != nil {
		panic(err)
	}
	return ibchandler.IBCMsgsMsgUpdateClient{
		ClientId: clientID,
		Header:   bz,
	}
}

func (chain *Chain) UpdateHeader() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		state, err := chain.client.GetContractState(ctx, chain.ContractConfig.GetIBCHostAddress(), nil, nil)
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

func (chain *Chain) CreateClient(
	ctx context.Context,
	counterparty *Chain,
	clientType string,
) (clientID string, err error) {
	switch clientType {
	case ibcclient.MockClient:
		clientID, err = chain.CreateMockClient(ctx, counterparty)
	default:
		err = fmt.Errorf("client type %s is not supported", clientType)
	}

	if err != nil {
		return "", err
	}

	return clientID, nil
}

func (chain *Chain) UpdateClient(
	ctx context.Context,
	counterparty *Chain,
	clientID string,
) error {
	var err error
	switch counterparty.ClientType() {
	case ibcclient.MockClient:
		err = chain.UpdateMockClient(ctx, counterparty, clientID)
	default:
		err = fmt.Errorf("client type %s is not supported", counterparty.ClientType())
	}
	if err != nil {
		return err
	}
	return nil
}

func (chain *Chain) CreateMockClient(ctx context.Context, counterparty *Chain) (string, error) {
	msg := chain.ConstructMockMsgCreateClient(counterparty)
	if err := chain.WaitIfNoError(ctx)(
		chain.IBCHandler.CreateClient(chain.TxOpts(ctx, types.RelayerKeyIndex), msg),
	); err != nil {
		return "", err
	}
	return chain.GetLastGeneratedClientID(ctx)
}

func (chain *Chain) UpdateMockClient(ctx context.Context, counterparty *Chain, clientID string) error {
	msg := chain.ConstructMockMsgUpdateClient(counterparty, clientID)
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.UpdateClient(chain.TxOpts(ctx, types.RelayerKeyIndex), msg),
	)
}

func (chain *Chain) ConnectionOpenInit(ctx context.Context, counterparty *Chain, connection, counterpartyConnection *types.TestConnection) (string, error) {
	if err := chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ConnectionOpenInit(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgConnectionOpenInit{
				ClientId: connection.ClientID,
				Counterparty: ibchandler.CounterpartyData{
					ClientId:     connection.CounterpartyClientID,
					ConnectionId: "",
					Prefix:       ibchandler.MerklePrefixData{KeyPrefix: counterparty.GetCommitmentPrefix()},
				},
				DelayPeriod: types.DefaultDelayPeriod,
			},
		),
	); err != nil {
		return "", err
	}
	return chain.GetLastGeneratedConnectionID(ctx)
}

func (chain *Chain) ConnectionOpenTry(ctx context.Context, counterparty *Chain, connection, counterpartyConnection *types.TestConnection) (string, error) {
	proofConnection, err := counterparty.QueryConnectionProof(chain, connection.ClientID, counterpartyConnection.ID, nil)
	if err != nil {
		return "", err
	}
	clientStateBytes, proofClient, err := counterparty.QueryClientProof(chain, counterpartyConnection.ClientID, big.NewInt(int64(proofConnection.Height)))
	if err != nil {
		return "", err
	}
	if err := chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ConnectionOpenTry(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgConnectionOpenTry{
				PreviousConnectionId: "",
				Counterparty: ibchandler.CounterpartyData{
					ClientId:     counterpartyConnection.ClientID,
					ConnectionId: counterpartyConnection.ID,
					Prefix:       ibchandler.MerklePrefixData{KeyPrefix: counterparty.GetCommitmentPrefix()},
				},
				DelayPeriod:      types.DefaultDelayPeriod,
				ClientId:         connection.ClientID,
				ClientStateBytes: clientStateBytes,
				CounterpartyVersions: []ibchandler.VersionData{
					{Identifier: "1", Features: []string{"ORDER_ORDERED", "ORDER_UNORDERED"}},
				},
				ProofHeight: proofConnection.Height,
				ProofInit:   proofConnection.Data,
				ProofClient: proofClient.Data,
			},
		),
	); err != nil {
		return "", err
	}
	return chain.GetLastGeneratedConnectionID(ctx)
}

// ConnectionOpenAck will construct and execute a MsgConnectionOpenAck.
func (chain *Chain) ConnectionOpenAck(
	ctx context.Context,
	counterparty *Chain,
	connection, counterpartyConnection *types.TestConnection,
) error {
	proofConnection, err := counterparty.QueryConnectionProof(chain, connection.ClientID, counterpartyConnection.ID, nil)
	if err != nil {
		return err
	}
	clientStateBytes, proofClient, err := counterparty.QueryClientProof(chain, counterpartyConnection.ClientID, big.NewInt(int64(proofConnection.Height)))
	if err != nil {
		return err
	}
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ConnectionOpenAck(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgConnectionOpenAck{
				ConnectionId:             connection.ID,
				CounterpartyConnectionID: counterpartyConnection.ID,
				ClientStateBytes:         clientStateBytes,
				Version:                  ibchandler.VersionData{Identifier: "1", Features: []string{"ORDER_ORDERED", "ORDER_UNORDERED"}},
				ProofHeight:              proofConnection.Height,
				ProofTry:                 proofConnection.Data,
				ProofClient:              proofClient.Data,
			},
		),
	)
}

func (chain *Chain) ConnectionOpenConfirm(
	ctx context.Context,
	counterparty *Chain,
	connection, counterpartyConnection *types.TestConnection,
) error {
	proof, err := counterparty.QueryConnectionProof(chain, connection.ClientID, counterpartyConnection.ID, nil)
	if err != nil {
		return err
	}
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ConnectionOpenConfirm(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgConnectionOpenConfirm{
				ConnectionId: connection.ID,
				ProofAck:     proof.Data,
				ProofHeight:  proof.Height,
			},
		),
	)
}

func (chain *Chain) ChannelOpenInit(
	ctx context.Context,
	ch, counterparty types.TestChannel,
	order channeltypes.Channel_Order,
	connectionID string,
) (string, error) {
	if err := chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ChannelOpenInit(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgChannelOpenInit{
				PortId: ch.PortID,
				Channel: ibchandler.ChannelData{
					State:    uint8(channeltypes.INIT),
					Ordering: uint8(order),
					Counterparty: ibchandler.ChannelCounterpartyData{
						PortId:    counterparty.PortID,
						ChannelId: "",
					},
					ConnectionHops: []string{connectionID},
					Version:        ch.Version,
				},
			},
		),
	); err != nil {
		return "", err
	}
	return chain.GetLastGeneratedChannelID(ctx)
}

func (chain *Chain) ChannelOpenTry(
	ctx context.Context,
	counterparty *Chain,
	ch, counterpartyCh types.TestChannel,
	order channeltypes.Channel_Order,
	connectionID string,
) (string, error) {
	proof, err := counterparty.QueryChannelProof(chain, ch.ClientID, counterpartyCh, nil)
	if err != nil {
		return "", err
	}
	if err := chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ChannelOpenTry(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgChannelOpenTry{
				PortId: ch.PortID,
				Channel: ibchandler.ChannelData{
					State:    uint8(channeltypes.TRYOPEN),
					Ordering: uint8(order),
					Counterparty: ibchandler.ChannelCounterpartyData{
						PortId:    counterpartyCh.PortID,
						ChannelId: counterpartyCh.ID,
					},
					ConnectionHops: []string{connectionID},
					Version:        ch.Version,
				},
				CounterpartyVersion: counterpartyCh.Version,
				ProofInit:           proof.Data,
				ProofHeight:         proof.Height,
			},
		),
	); err != nil {
		return "", err
	}
	return chain.GetLastGeneratedChannelID(ctx)
}

func (chain *Chain) ChannelOpenAck(
	ctx context.Context,
	counterparty *Chain,
	ch, counterpartyCh types.TestChannel,
) error {
	proof, err := counterparty.QueryChannelProof(chain, ch.ClientID, counterpartyCh, nil)
	if err != nil {
		return err
	}
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ChannelOpenAck(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgChannelOpenAck{
				PortId:                ch.PortID,
				ChannelId:             ch.ID,
				CounterpartyVersion:   counterpartyCh.Version,
				CounterpartyChannelId: counterpartyCh.ID,
				ProofTry:              proof.Data,
				ProofHeight:           proof.Height,
			},
		),
	)
}

func (chain *Chain) ChannelOpenConfirm(
	ctx context.Context,
	counterparty *Chain,
	ch, counterpartyCh types.TestChannel,
) error {
	proof, err := counterparty.QueryChannelProof(chain, ch.ClientID, counterpartyCh, nil)
	if err != nil {
		return err
	}
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.ChannelOpenConfirm(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgChannelOpenConfirm{
				PortId:      ch.PortID,
				ChannelId:   ch.ID,
				ProofAck:    proof.Data,
				ProofHeight: proof.Height,
			},
		),
	)
}

func (chain *Chain) SendPacket(
	ctx context.Context,
	packet channeltypes.Packet,
) error {
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.SendPacket(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			packetToCallData(packet),
		),
	)
}

func (chain *Chain) HandlePacketRecv(
	ctx context.Context,
	counterparty *Chain,
	ch, counterpartyCh types.TestChannel,
	packet channeltypes.Packet,
) error {
	proof, err := counterparty.QueryProof(chain, ch.ClientID, chain.PacketCommitmentSlot(packet.SourcePort, packet.SourceChannel, packet.Sequence), nil)
	if err != nil {
		return err
	}
	switch chain.ClientType() {
	case ibcclient.MockClient:
		proof.Data = commitPacket(packet)
	}
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.RecvPacket(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgPacketRecv{
				Packet:      packetToCallData(packet),
				Proof:       proof.Data,
				ProofHeight: proof.Height,
			},
		),
	)
}

func (chain *Chain) HandlePacketAcknowledgement(
	ctx context.Context,
	counterparty *Chain,
	ch, counterpartyCh types.TestChannel,
	packet channeltypes.Packet,
	acknowledgement []byte,
) error {
	proof, err := counterparty.QueryProof(chain, ch.ClientID, chain.PacketAcknowledgementCommitmentSlot(packet.DestinationPort, packet.DestinationChannel, packet.Sequence), nil)
	if err != nil {
		return err
	}
	switch chain.ClientType() {
	case ibcclient.MockClient:
		proof.Data = commitAcknowledgement(acknowledgement)
	}
	return chain.WaitIfNoError(ctx)(
		chain.IBCHandler.AcknowledgePacket(
			chain.TxOpts(ctx, types.RelayerKeyIndex),
			ibchandler.IBCMsgsMsgPacketAcknowledgement{
				Packet:          packetToCallData(packet),
				Acknowledgement: acknowledgement,
				Proof:           proof.Data,
				ProofHeight:     proof.Height,
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
	logs, err := chain.client.FilterLogs(ctx, query)
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
) (*channeltypes.Packet, error) {
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
	logs, err := chain.client.FilterLogs(ctx, query)
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

func packetToCallData(packet channeltypes.Packet) ibchandler.PacketData {
	return ibchandler.PacketData{
		Sequence:           packet.Sequence,
		SourcePort:         packet.SourcePort,
		SourceChannel:      packet.SourceChannel,
		DestinationPort:    packet.DestinationPort,
		DestinationChannel: packet.DestinationChannel,
		Data:               packet.Data,
		TimeoutHeight:      ibchandler.HeightData(packet.TimeoutHeight),
		TimeoutTimestamp:   packet.TimeoutTimestamp,
	}
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
func commitPacket(packet channeltypes.Packet) []byte {
	timeoutHeight := packet.TimeoutHeight

	buf := uint64ToBigEndian(packet.TimeoutTimestamp)

	revisionNumber := uint64ToBigEndian(timeoutHeight.GetRevisionNumber())
	buf = append(buf, revisionNumber...)

	revisionHeight := uint64ToBigEndian(timeoutHeight.GetRevisionHeight())
	buf = append(buf, revisionHeight...)

	dataHash := sha256.Sum256(packet.Data)
	buf = append(buf, dataHash[:]...)

	hash := sha256.Sum256(buf)
	return hash[:]
}

// commitAcknowledgement returns the hash of commitment bytes
func commitAcknowledgement(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
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

func (chain *Chain) ClientStateCommitmentSlot(clientID string) string {
	key, err := chain.IBCIdentifier.ClientStateCommitmentSlot(chain.CallOpts(context.Background(), types.RelayerKeyIndex), clientID)
	require.NoError(chain.t, err)
	return "0x" + hex.EncodeToString(key[:])
}

func (chain *Chain) ConnectionStateCommitmentSlot(connectionID string) string {
	key, err := chain.IBCIdentifier.ConnectionCommitmentSlot(chain.CallOpts(context.Background(), types.RelayerKeyIndex), connectionID)
	require.NoError(chain.t, err)
	return "0x" + hex.EncodeToString(key[:])
}

func (chain *Chain) ChannelStateCommitmentSlot(portID, channelID string) string {
	key, err := chain.IBCIdentifier.ChannelCommitmentSlot(chain.CallOpts(context.Background(), types.RelayerKeyIndex), portID, channelID)
	require.NoError(chain.t, err)
	return "0x" + hex.EncodeToString(key[:])
}

func (chain *Chain) PacketCommitmentSlot(portID, channelID string, sequence uint64) string {
	key, err := chain.IBCIdentifier.PacketCommitmentSlot(chain.CallOpts(context.Background(), types.RelayerKeyIndex), portID, channelID, sequence)
	require.NoError(chain.t, err)
	return "0x" + hex.EncodeToString(key[:])
}

func (chain *Chain) PacketAcknowledgementCommitmentSlot(portID, channelID string, sequence uint64) string {
	key, err := chain.IBCIdentifier.PacketAcknowledgementCommitmentSlot(chain.CallOpts(context.Background(), types.RelayerKeyIndex), portID, channelID, sequence)
	require.NoError(chain.t, err)
	return "0x" + hex.EncodeToString(key[:])
}

// Querier

type Proof struct {
	Height uint64
	Data   []byte
}

func (chain *Chain) QueryProof(counterparty *Chain, counterpartyClientID string, storageKey string, height *big.Int) (*Proof, error) {
	if !strings.HasPrefix(storageKey, "0x") {
		return nil, fmt.Errorf("storageKey must be hex string")
	}
	s, err := chain.GetContractState(counterparty, counterpartyClientID, [][]byte{[]byte(storageKey)}, height)
	if err != nil {
		return nil, err
	}
	return &Proof{Height: s.Header().Number.Uint64(), Data: s.ETHProof().StorageProofRLP[0]}, nil
}

func (counterparty *Chain) QueryClientProof(chain *Chain, counterpartyClientID string, height *big.Int) ([]byte, *Proof, error) {
	cs, found, err := counterparty.IBCHost.GetClientState(
		counterparty.CallOpts(context.Background(), types.RelayerKeyIndex),
		counterpartyClientID,
	)
	if err != nil {
		return nil, nil, err
	} else if !found {
		return nil, nil, fmt.Errorf("client not found: %v", counterpartyClientID)
	}
	proof, err := counterparty.QueryProof(chain, counterpartyClientID, chain.ClientStateCommitmentSlot(counterpartyClientID), height)
	if err != nil {
		return nil, nil, err
	}
	switch counterparty.ClientType() {
	case ibcclient.MockClient:
		h := sha256.Sum256(cs)
		proof.Data = h[:]
	}
	return cs, proof, nil
}

func (counterparty *Chain) QueryConnectionProof(chain *Chain, counterpartyClientID string, counterpartyConnectionID string, height *big.Int) (*Proof, error) {
	proof, err := counterparty.QueryProof(chain, counterpartyClientID, chain.ConnectionStateCommitmentSlot(counterpartyConnectionID), height)
	if err != nil {
		return nil, err
	}
	switch counterparty.ClientType() {
	case ibcclient.MockClient:
		conn, found, err := counterparty.IBCHost.GetConnection(
			counterparty.CallOpts(context.Background(), types.RelayerKeyIndex),
			counterpartyConnectionID,
		)
		if err != nil {
			return nil, err
		} else if !found {
			return nil, fmt.Errorf("connection not found: %v", counterpartyConnectionID)
		}
		bz, err := proto.Marshal(connectionEndToPB(conn))
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(bz)
		proof.Data = h[:]
	}
	return proof, nil
}

func (counterparty *Chain) QueryChannelProof(chain *Chain, counterpartyClientID string, channel types.TestChannel, height *big.Int) (*Proof, error) {
	proof, err := counterparty.QueryProof(chain, counterpartyClientID, chain.ChannelStateCommitmentSlot(channel.PortID, channel.ID), height)
	if err != nil {
		return nil, err
	}
	switch counterparty.ClientType() {
	case ibcclient.MockClient:
		ch, found, err := counterparty.IBCHost.GetChannel(
			counterparty.CallOpts(context.Background(), types.RelayerKeyIndex),
			channel.PortID, channel.ID,
		)
		if err != nil {
			return nil, err
		} else if !found {
			return nil, fmt.Errorf("channel not found: %v", channel)
		}
		bz, err := proto.Marshal(channelToPB(ch))
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(bz)
		proof.Data = h[:]
	}
	return proof, nil
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

// AddTestConnection appends a new TestConnection which contains references
// to the connection id, client id and counterparty client id.
func (chain *Chain) AddTestConnection(clientID, counterpartyClientID string) *types.TestConnection {
	conn := chain.ConstructNextTestConnection(clientID, counterpartyClientID)

	chain.Connections = append(chain.Connections, conn)
	return conn
}

// ConstructNextTestConnection constructs the next test connection to be
// created given a clientID and counterparty clientID.
func (chain *Chain) ConstructNextTestConnection(clientID, counterpartyClientID string) *types.TestConnection {
	return &types.TestConnection{
		ID:                   "",
		ClientID:             clientID,
		NextChannelVersion:   types.DefaultChannelVersion,
		CounterpartyClientID: counterpartyClientID,
	}
}

// AddTestChannel appends a new types.TestChannel which contains references to the port and channel ID
// used for channel creation and interaction. See 'NextTestChannel' for channel ID naming format.
func (chain *Chain) AddTestChannel(conn *types.TestConnection, portID string) types.TestChannel {
	channel := chain.NextTestChannel(conn, portID)
	conn.Channels = append(conn.Channels, channel)
	return channel
}

// NextTestChannel returns the next test channel to be created on this connection, but does not
// add it to the list of created channels. This function is expected to be used when the caller
// has not created the associated channel in app state, but would still like to refer to the
// non-existent channel usually to test for its non-existence.
//
// The port is passed in by the caller.
func (chain *Chain) NextTestChannel(conn *types.TestConnection, portID string) types.TestChannel {
	return types.TestChannel{
		PortID:               portID,
		ID:                   "",
		ClientID:             conn.ClientID,
		CounterpartyClientID: conn.CounterpartyClientID,
		Version:              conn.NextChannelVersion,
	}
}
