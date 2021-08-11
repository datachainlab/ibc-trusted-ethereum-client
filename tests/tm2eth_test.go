package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/client"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/consts"
	tm "github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/tendermint"
	ibctesting "github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing/types"
)

const mnemonicPhrase = "math razor capable expose worth grape metal sunset metal sudden usage scheme"

/*
NOTE: This test is intended to be run on ganache. Therefore, we are using MockClient instead of IBFT2Client.
*/
type TM2EthTestSuite struct {
	suite.Suite

	coordinator *ibctesting.Coordinator
	chainA      types.TestChainI
	chainB      types.TestChainI
}

func (suite *TM2EthTestSuite) SetupTest() {
	chainClient, err := client.NewETHClient("http://127.0.0.1:8545", 2021)
	suite.Require().NoError(err)

	suite.chainA = tm.NewTestChain(suite.T())
	suite.chainB = ethereum.NewChain(suite.T(), *chainClient, consts.Contract, mnemonicPhrase)
	suite.coordinator = ibctesting.NewCoordinator(suite.T(), suite.chainA, suite.chainB)
}

func NewTransferPath(chainA, chainB types.TestChainI) *ibctesting.Path {
	path := ibctesting.NewPath(chainA, chainB)
	return path
}

func (suite *TM2EthTestSuite) TestChannelTM2Eth() {
	ctx := context.Background()

	path := NewTransferPath(suite.chainA, suite.chainB)
	path.EndpointA.ClientConfig = ibctesting.NewTrustedEthereumConfig("chainA-chainB")
	suite.coordinator.Setup(ctx, path)
}

func (suite *TM2EthTestSuite) TestChannelEth2TM() {
	ctx := context.Background()

	path := NewTransferPath(suite.chainB, suite.chainA)
	path.EndpointB.ClientConfig = ibctesting.NewTrustedEthereumConfig("chainB-chainA")
	suite.coordinator.Setup(ctx, path)
}

func TestTM2EthTestSuite(t *testing.T) {
	suite.Run(t, new(TM2EthTestSuite))
}
