package ethereum

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	conntypes "github.com/cosmos/ibc-go/modules/core/03-connection/types"
	chantypes "github.com/cosmos/ibc-go/modules/core/04-channel/types"
	committypes "github.com/cosmos/ibc-go/modules/core/23-commitment/types"
	ibcexported "github.com/cosmos/ibc-go/modules/core/exported"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	ethtypes "github.com/datachainlab/ibc-trusted-ethereum-client/modules/light-clients/trusted-ethereum/types"
	"github.com/hyperledger-labs/yui-ibc-solidity/pkg/wallet"
	"github.com/hyperledger-labs/yui-relayer/chains/ethereum"
	"github.com/hyperledger-labs/yui-relayer/core"
)

type Prover struct {
	chain        *ethereum.Chain
	client       *Client
	ethClient    *ethclient.Client
	config       ProverConfig
	proverPrvKey *ecdsa.PrivateKey
}

var _ core.ProverI = (*Prover)(nil)

func NewProver(chain *ethereum.Chain, config ProverConfig) (*Prover, error) {
	key, err := wallet.GetPrvKeyFromMnemonicAndHDWPath(config.HdwMnemonic, config.HdwPath)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(config.RpcAddr)
	if err != nil {
		return nil, err
	}
	// duplicated with chain
	ethClient, err := ethereum.NewETHClient(config.RpcAddr)
	if err != nil {
		return nil, err
	}

	return &Prover{
		chain:        chain,
		client:       client,
		ethClient:    ethClient,
		config:       config,
		proverPrvKey: key,
	}, nil
}

// GetChainID returns the chain ID
func (pr *Prover) GetChainID() string {
	return pr.chain.ChainID()
}

// QueryLatestHeader returns the latest header from the chain
func (pr *Prover) QueryLatestHeader() (out core.HeaderI, err error) {
	h, err := pr.ethClient.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return nil, err
	}

	proof, err := pr.getAccountProof(nil, h.Number)
	if err != nil {
		return nil, err
	}

	privKey := convertPrivKey(pr.proverPrvKey)
	pubKey, err := types.NewAnyWithValue(privKey.PubKey())
	if err != nil {
		return nil, err
	}

	header := &ethtypes.Header{
		Height:         clienttypes.NewHeight(0, h.Number.Uint64()),
		StateRoot:      h.Root.Bytes(),
		Timestamp:      h.Time,
		AccountProof:   proof,
		NewPublicKey:   pubKey,
		NewDiversifier: pr.config.Diversifier,
	}

	return header, nil
}

// GetLatestLightHeight returns the latest height on the light client
func (pr *Prover) GetLatestLightHeight() (int64, error) {
	h, err := pr.ethClient.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return -1, err
	}
	return h.Number.Int64(), nil
}

// CreateMsgCreateClient creates a CreateClientMsg to this chain
func (pr *Prover) CreateMsgCreateClient(clientID string, dstHeader core.HeaderI, signer sdk.AccAddress) (*clienttypes.MsgCreateClient, error) {
	h := dstHeader.(*ethtypes.Header)
	clientState := &ethtypes.ClientState{
		ChainId:         pr.GetChainID(),
		IbcStoreAddress: pr.config.IBCHostAddress().Bytes(),
		LatestHeight:    h.Height,
	}

	proof, err := decodeRLP(h.AccountProof)
	if err != nil {
		return nil, err
	}
	accountRLP, err := ethtypes.VerifyEthAccountProof(proof, common.BytesToHash(h.StateRoot), pr.config.IBCHostAddress().Bytes())
	if err != nil {
		return nil, err
	}
	storageHash, err := decodeStorageHash(accountRLP)
	if err != nil {
		return nil, err
	}

	consensusState := &ethtypes.ConsensusState{
		Timestamp: h.Timestamp,
		Root:      committypes.NewMerkleRoot(storageHash),
		PublicKey: h.NewPublicKey,
	}
	return clienttypes.NewMsgCreateClient(
		clientState,
		consensusState,
		signer.String(),
	)
}

// SetupHeader creates a new header based on a given header
func (pr *Prover) SetupHeader(dst core.LightClientIBCQueryierI, baseSrcHeader core.HeaderI) (core.HeaderI, error) {
	tmp, ok := baseSrcHeader.(*ethtypes.Header)
	if !ok {
		return nil, fmt.Errorf("invalid header type")
	}
	header := *tmp
	bz, err := ethtypes.HeaderSignBytes(pr.chain.Codec(), &header)
	if err != nil {
		return nil, err
	}
	privKey := convertPrivKey(pr.proverPrvKey)
	sig, err := privKey.Sign(bz)
	if err != nil {
		return nil, err
	}
	header.Signature = sig

	return &header, nil

}

// UpdateLightWithHeader updates a header on the light client and returns the header and height corresponding to the chain
func (pr *Prover) UpdateLightWithHeader() (header core.HeaderI, provableHeight int64, queryableHeight int64, err error) {
	h, err := pr.QueryLatestHeader()
	if err != nil {
		return nil, -1, -1, err
	}
	height := new(big.Int).SetUint64(h.GetHeight().GetRevisionHeight()).Int64()
	return h, height, height, nil
}

// QueryClientConsensusState returns the ClientConsensusState and its proof
func (pr *Prover) QueryClientConsensusStateWithProof(height int64, dstClientConsHeight ibcexported.Height) (*clienttypes.QueryConsensusStateResponse, error) {
	res, err := pr.chain.QueryClientConsensusState(height, dstClientConsHeight)
	if err != nil {
		return nil, err
	}

	key, err := ethtypes.ConsensusStateCommitmentSlot(pr.chain.Path().ClientID, dstClientConsHeight.GetRevisionHeight())
	if err != nil {
		return nil, err
	}
	proof, err := pr.getStorageProof(hexKey(key), big.NewInt(height))
	if err != nil {
		return nil, err
	}
	res.Proof = proof
	res.ProofHeight = clienttypes.NewHeight(0, uint64(height))
	return res, nil
}

// QueryClientStateWithProof returns the ClientState and its proof
func (pr *Prover) QueryClientStateWithProof(height int64) (*clienttypes.QueryClientStateResponse, error) {
	res, err := pr.chain.QueryClientState(height)
	if err != nil {
		return nil, err
	}
	key, err := ethtypes.ClientStateCommitmentSlot(pr.chain.Path().ClientID)
	if err != nil {
		return nil, err
	}
	proof, err := pr.getStorageProof(hexKey(key), big.NewInt(height))
	if err != nil {
		return nil, err
	}
	res.Proof = proof
	res.ProofHeight = clienttypes.NewHeight(0, uint64(height))
	return res, nil
}

// QueryConnectionWithProof returns the Connection and its proof
func (pr *Prover) QueryConnectionWithProof(height int64) (*conntypes.QueryConnectionResponse, error) {
	res, err := pr.chain.QueryConnection(height)
	if err != nil {
		return nil, err
	}
	key, err := ethtypes.ConnectionCommitmentSlot(pr.chain.Path().ConnectionID)
	if err != nil {
		return nil, err
	}
	proof, err := pr.getStorageProof(hexKey(key), big.NewInt(height))
	if err != nil {
		return nil, err
	}
	res.Proof = proof
	res.ProofHeight = clienttypes.NewHeight(0, uint64(height))
	return res, nil
}

// QueryChannelWithProof returns the Channel and its proof
func (pr *Prover) QueryChannelWithProof(height int64) (chanRes *chantypes.QueryChannelResponse, err error) {
	res, err := pr.chain.QueryChannel(height)
	if err != nil {
		return nil, err
	}
	path := pr.chain.Path()
	key, err := ethtypes.ChannelCommitmentSlot(path.PortID, path.ChannelID)
	if err != nil {
		return nil, err
	}
	proof, err := pr.getStorageProof(hexKey(key), big.NewInt(height))
	if err != nil {
		return nil, err
	}
	res.Proof = proof
	res.ProofHeight = clienttypes.NewHeight(0, uint64(height))
	return res, nil
}

// QueryPacketCommitmentWithProof returns the packet commitment and its proof
func (pr *Prover) QueryPacketCommitmentWithProof(height int64, seq uint64) (comRes *chantypes.QueryPacketCommitmentResponse, err error) {
	res, err := pr.chain.QueryPacketCommitment(height, seq)
	if err != nil {
		return nil, err
	}
	path := pr.chain.Path()
	key, err := ethtypes.PacketCommitmentSlot(path.PortID, path.ChannelID, seq)
	if err != nil {
		return nil, err
	}
	proof, err := pr.getStorageProof(hexKey(key), big.NewInt(height))
	if err != nil {
		return nil, err
	}
	res.Proof = proof
	res.ProofHeight = clienttypes.NewHeight(0, uint64(height))
	return res, nil
}

// QueryPacketAcknowledgementCommitmentWithProof returns the packet acknowledgement commitment and its proof
func (pr *Prover) QueryPacketAcknowledgementCommitmentWithProof(height int64, seq uint64) (ackRes *chantypes.QueryPacketAcknowledgementResponse, err error) {
	res, err := pr.chain.QueryPacketAcknowledgementCommitment(height, seq)
	if err != nil {
		return nil, err
	}
	path := pr.chain.Path()
	key, err := ethtypes.PacketAcknowledgementCommitmentSlot(path.PortID, path.ChannelID, seq)
	if err != nil {
		return nil, err
	}
	proof, err := pr.getStorageProof(hexKey(key), big.NewInt(height))
	if err != nil {
		return nil, err
	}
	res.Proof = proof
	res.ProofHeight = clienttypes.NewHeight(0, uint64(height))
	return res, nil
}

func (pr *Prover) getAccountProof(key []byte, blockNumber *big.Int) ([]byte, error) {
	ethProof, err := getETHProof(pr.client, pr.config.IBCHostAddress(), key, blockNumber)
	if err != nil {
		return nil, err
	}
	return ethProof.AccountProofRLP, nil
}

func (pr *Prover) getStorageProof(key []byte, blockNumber *big.Int) ([]byte, error) {
	ethProof, err := getETHProof(pr.client, pr.config.IBCHostAddress(), key, blockNumber)
	if err != nil {
		return nil, err
	}
	if len(ethProof.StorageProofRLP) == 0 {
		return nil, fmt.Errorf("storage proof is empty")
	}
	return ethProof.StorageProofRLP[0], nil
}

func getETHProof(client *Client, address common.Address, key []byte, blockNumber *big.Int) (*ETHProof, error) {
	var k [][]byte = nil
	if len(key) > 0 {
		k = [][]byte{key}
	}
	proof, err := client.GetETHProof(
		address,
		k,
		blockNumber,
	)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func convertPrivKey(privKey *ecdsa.PrivateKey) *secp256k1.PrivKey {
	bz := crypto.FromECDSA(privKey)
	return &secp256k1.PrivKey{Key: bz}
}

func hexKey(key []byte) []byte {
	return []byte(strings.Join([]string{"0x", hex.EncodeToString(key[:])}, ""))
}
