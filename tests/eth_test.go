package tests

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/client"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/ethereum/pkg/consts"
	ibctesting "github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing"
	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing/types"
)

const mnemonicPhrase = "math razor capable expose worth grape metal sunset metal sudden usage scheme"

/*
NOTE: This test is intended to be run on ganache. Therefore, we are using MockClient instead of IBFT2Client.
*/
type ContractTestSuite struct {
	suite.Suite

	coordinator ibctesting.Coordinator
	chainA      *ethereum.Chain
	chainB      *ethereum.Chain
}

func (suite *ContractTestSuite) SetupTest() {
	chainClient1, err := client.NewETHClient("http://127.0.0.1:8545")
	suite.Require().NoError(err)

	chainClient2, err := client.NewETHClient("http://127.0.0.1:8645")
	suite.Require().NoError(err)

	suite.chainA = ethereum.NewChain(suite.T(), 2021, *chainClient1, consts.Contract, mnemonicPhrase, uint64(time.Now().UnixNano()))
	suite.chainB = ethereum.NewChain(suite.T(), 2022, *chainClient2, consts.Contract, mnemonicPhrase, uint64(time.Now().UnixNano()))
	suite.coordinator = ibctesting.NewCoordinator(suite.T(), suite.chainA, suite.chainB)
}

func NewTransferPath(chainA, chainB *ethereum.Chain) *ibctesting.Path {
	path := ibctesting.NewPath(chainA, chainB)
	return path
}

func (suite *ContractTestSuite) TestChannel() {
	ctx := context.Background()

	const (
		relayer         = types.RelayerKeyIndex // the key-index of relayer on chain
		deployer        = types.RelayerKeyIndex // the key-index of contract deployer on chain
		alice    uint32 = 1                     // the key-index of alice on chain
		bob      uint32 = 2                     // the key-index of bob on chain
	)

	path := NewTransferPath(suite.chainA, suite.chainB)
	suite.coordinator.Setup(ctx, path)

	chainA, ok := path.EndpointA.Chain.(*ethereum.Chain)
	suite.Require().True(ok)

	chainB, ok := path.EndpointB.Chain.(*ethereum.Chain)
	suite.Require().True(ok)

	/////// Tests for Transfer module ///
	balance0, err := chainA.SimpleToken.BalanceOf(
		chainA.CallOpts(ctx, relayer),
		chainA.CallOpts(ctx, deployer).From,
	)
	suite.Require().NoError(err)
	suite.Require().NoError(chainA.WaitIfNoError(ctx)(
		chainA.SimpleToken.Approve(
			chainA.TxOpts(ctx, deployer),
			chainA.ContractConfig.GetICS20BankAddress(), big.NewInt(100),
		),
	))

	// deposit a simple token to the bank
	suite.Require().NoError(chainA.WaitIfNoError(ctx)(
		chainA.ICS20Bank.Deposit(
			chainA.TxOpts(ctx, deployer),
			chainA.ContractConfig.GetSimpleTokenAddress(),
			big.NewInt(100),
			chainA.CallOpts(ctx, alice).From,
		)))

	// ensure that the balance is reduced
	balance1, err := chainA.SimpleToken.BalanceOf(
		chainA.CallOpts(ctx, relayer),
		chainA.CallOpts(ctx, deployer).From,
	)
	suite.Require().NoError(err)
	suite.Require().Equal(balance0.Int64()-100, balance1.Int64())

	baseDenom := strings.ToLower(chainA.ContractConfig.GetSimpleTokenAddress().String())

	bankA, err := chainA.ICS20Bank.BalanceOf(
		chainA.CallOpts(ctx, relayer),
		chainA.CallOpts(ctx, alice).From,
		baseDenom,
	)
	suite.Require().NoError(err)
	suite.Require().GreaterOrEqual(bankA.Int64(), int64(100))

	// try to transfer the token to chainB
	suite.Require().NoError(chainA.WaitIfNoError(ctx)(
		chainA.ICS20Transfer.SendTransfer(
			chainA.TxOpts(ctx, alice),
			baseDenom,
			100,
			chainB.CallOpts(ctx, bob).From,
			path.EndpointA.ChannelConfig.PortID, path.EndpointA.ChannelID,
			uint64(chainA.LastHeader().Number.Int64())+1000,
		),
	))

	// ensure that escrow has correct balance
	escrowBalance, err := chainA.ICS20Bank.BalanceOf(
		chainA.CallOpts(ctx, alice),
		chainA.ContractConfig.GetICS20TransferBankAddress(),
		baseDenom,
	)
	suite.Require().NoError(err)
	suite.Require().GreaterOrEqual(escrowBalance.Int64(), int64(100))

	// relay the packet
	transferPacket, err := chainA.GetLastSentPacket(
		ctx, path.EndpointA.ChannelConfig.PortID,
		path.EndpointA.ChannelID,
	)
	suite.Require().NoError(err)
	suite.Require().NoError(path.EndpointB.UpdateClient(ctx))
	suite.Require().NoError(path.EndpointB.RecvPacket(ctx, transferPacket))
	suite.Require().NoError(path.EndpointA.AcknowledgePacket(ctx, transferPacket, []byte{1}))

	// ensure that chainB has correct balance
	expectedDenom := fmt.Sprintf("%v/%v/%v", path.EndpointB.ChannelConfig.PortID, path.EndpointB.ChannelID, baseDenom)
	balance, err := chainB.ICS20Bank.BalanceOf(
		chainB.CallOpts(ctx, relayer),
		chainB.CallOpts(ctx, bob).From,
		expectedDenom,
	)
	suite.Require().NoError(err)
	suite.Require().Equal(int64(100), balance.Int64())

	//// try to transfer the token to chainA
	suite.Require().NoError(chainB.WaitIfNoError(ctx)(
		chainB.ICS20Transfer.SendTransfer(
			chainB.TxOpts(ctx, bob),
			expectedDenom,
			100,
			chainA.CallOpts(ctx, alice).From,
			path.EndpointB.ChannelConfig.PortID,
			path.EndpointB.ChannelID,
			uint64(chainB.LastHeader().Number.Int64())+1000,
		),
	))

	//// relay the packet
	transferPacket, err = chainB.GetLastSentPacket(
		ctx,
		path.EndpointB.ChannelConfig.PortID,
		path.EndpointB.ChannelID,
	)
	suite.Require().NoError(err)
	suite.Require().NoError(path.EndpointA.UpdateClient(ctx))
	suite.Require().NoError(path.EndpointA.RecvPacket(ctx, transferPacket))
	suite.Require().NoError(path.EndpointB.AcknowledgePacket(ctx, transferPacket, []byte{1}))
	//// withdraw tokens from the bank
	suite.Require().NoError(chainA.WaitIfNoError(ctx)(
		chainA.ICS20Bank.Withdraw(
			chainA.TxOpts(ctx, alice),
			chainA.ContractConfig.GetSimpleTokenAddress(),
			big.NewInt(100),
			chainA.CallOpts(ctx, deployer).From,
		)))

	// ensure that token balance equals original value
	balanceA2, err := chainA.SimpleToken.BalanceOf(
		chainA.CallOpts(ctx, relayer),
		chainA.CallOpts(ctx, deployer).From,
	)
	suite.Require().NoError(err)
	suite.Require().Equal(balance0.Int64(), balanceA2.Int64())
}

func TestContractTestSuite(t *testing.T) {
	suite.Run(t, new(ContractTestSuite))
}
