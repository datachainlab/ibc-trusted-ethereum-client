package main

import (
	"log"

	ethProver "github.com/datachainlab/ibc-trusted-ethereum-client/pkg/ethereum"
	ethereum "github.com/hyperledger-labs/yui-relayer/chains/ethereum/module"
	tendermint "github.com/hyperledger-labs/yui-relayer/chains/tendermint/module"
	"github.com/hyperledger-labs/yui-relayer/cmd"
	mock "github.com/hyperledger-labs/yui-relayer/provers/mock/module"
)

func main() {
	if err := cmd.Execute(
		ethereum.Module{},
		ethProver.Module{},
		mock.Module{},
		tendermint.Module{},
	); err != nil {
		log.Fatal(err)
	}
}
