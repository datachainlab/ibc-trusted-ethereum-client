package client

import (
	"context"
	"fmt"
	"math/big"

	mocktypes "github.com/datachainlab/ibc-mock-client/modules/light-clients/xx-mock/types"
	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"

	trustedethereumtypes "github.com/datachainlab/ibc-trusted-ethereum-client/modules/light-clients/trusted-ethereum/types"
)

type ContractState interface {
	Header() *gethtypes.Header
	ETHProof() *ETHProof
}

func (cl ChainClient) GetContractState(ctx context.Context, address common.Address, storageKeys [][]byte, bn *big.Int, clientType string) (ContractState, error) {
	switch clientType {
	case trustedethereumtypes.TrustedEthereum:
		return cl.GetEthContractState(ctx, address, storageKeys, bn)
	case mocktypes.Mock:
		return cl.GetMockContractState(ctx, address, storageKeys, bn)
	default:
		panic(fmt.Sprintf("unknown client type '%v'", clientType))
	}
}

func (cl ChainClient) GetEthContractState(ctx context.Context, address common.Address, storageKeys [][]byte, bn *big.Int) (ContractState, error) {
	block, err := cl.BlockByNumber(ctx, bn)
	if err != nil {
		return nil, err
	}
	proof, err := cl.GetETHProof(address, storageKeys, block.Number())
	if err != nil {
		return nil, err
	}

	return ETHContractState{header: block.Header(), ethProof: proof}, nil
}

func (cl ChainClient) GetMockContractState(ctx context.Context, address common.Address, storageKeys [][]byte, bn *big.Int) (ContractState, error) {
	block, err := cl.BlockByNumber(ctx, bn)
	if err != nil {
		return nil, err
	}
	// this is dummy
	proof := &ETHProof{
		StorageProofRLP: make([][]byte, len(storageKeys)),
	}
	return ETHContractState{header: block.Header(), ethProof: proof}, nil
}

type ETHContractState struct {
	header   *gethtypes.Header
	ethProof *ETHProof
}

func (cs ETHContractState) Header() *gethtypes.Header {
	return cs.header
}

func (cs ETHContractState) ETHProof() *ETHProof {
	return cs.ethProof
}
