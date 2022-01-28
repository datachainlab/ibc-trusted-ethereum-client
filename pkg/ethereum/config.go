package ethereum

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/hyperledger-labs/yui-relayer/chains/ethereum"
	"github.com/hyperledger-labs/yui-relayer/core"
)

var _ core.ProverConfigI = (*ProverConfig)(nil)

func (c ProverConfig) Build(chain core.ChainI) (core.ProverI, error) {
	ethChain, ok := chain.(*ethereum.Chain)
	if !ok {
		return nil, fmt.Errorf("invalid chain type")
	}
	return NewProver(ethChain, c)
}

func (c ProverConfig) IBCHostAddress() common.Address {
	return common.HexToAddress(c.IbcHostAddress)
}
