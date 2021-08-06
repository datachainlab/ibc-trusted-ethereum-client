package tests

import (
	"context"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/ibc-go/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	channeltypes "github.com/cosmos/ibc-go/modules/core/04-channel/types"
	"github.com/stretchr/testify/suite"

	tm "github.com/datachainlab/ibc-trusted-ethereum-client/tests/chains/tendermint"
	ibctesting "github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing"
	ibctestingtypes "github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing/types"
)

type TendermintTestSuite struct {
	suite.Suite

	coordinator *ibctesting.Coordinator

	// testing chains used for convenience and readability
	chainA ibctestingtypes.TestChainI
	chainB ibctestingtypes.TestChainI
}

func (suite *TendermintTestSuite) SetupTest() {
	suite.chainA = tm.NewTestChain(suite.T())
	suite.chainB = tm.NewTestChain(suite.T())
	suite.coordinator = ibctesting.NewCoordinator(suite.T(), suite.chainA, suite.chainB)
}

func (suite *TendermintTestSuite) TestChannelWithMockClient() {
	ctx := context.Background()

	path := NewTransferPath(suite.chainA, suite.chainB)

	suite.coordinator.Setup(ctx, path)

	suite.testTransfer(ctx, path)
}

func (suite *TendermintTestSuite) TestChannelWithTendermintClient() {
	ctx := context.Background()

	path := NewTransferPath(suite.chainA, suite.chainB)
	path.EndpointA.ClientConfig = ibctesting.NewTendermintConfig()
	path.EndpointB.ClientConfig = ibctesting.NewTendermintConfig()

	suite.coordinator.Setup(ctx, path)

	suite.testTransfer(ctx, path)
}

func (suite *TendermintTestSuite) testTransfer(ctx context.Context, path *ibctesting.Path) {
	chainA, ok := path.EndpointA.Chain.(*tm.TestChain)
	suite.Require().True(ok)

	chainB, ok := path.EndpointB.Chain.(*tm.TestChain)
	suite.Require().True(ok)

	//	originalBalance := suite.chainA.GetSimApp().BankKeeper.GetBalance(suite.chainA.GetContext(), suite.chainA.SenderAccount.GetAddress(), sdk.DefaultBondDenom)
	timeoutHeight := clienttypes.NewHeight(0, 110)

	coinToSendToB := sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(100))

	// send from chainA to chainB
	msg := types.NewMsgTransfer(path.EndpointA.ChannelConfig.PortID, path.EndpointA.ChannelID, coinToSendToB, chainA.SenderAccount.GetAddress().String(), chainB.SenderAccount.GetAddress().String(), timeoutHeight, 0)

	_, err := chainA.SendMsgs(msg)
	suite.Require().NoError(err) // message committed

	// relay send
	fungibleTokenPacket := types.NewFungibleTokenPacketData(coinToSendToB.Denom, coinToSendToB.Amount.Uint64(), chainA.SenderAccount.GetAddress().String(), chainB.SenderAccount.GetAddress().String())
	transferPacket := channeltypes.NewPacket(fungibleTokenPacket.GetBytes(), 1, path.EndpointA.ChannelConfig.PortID, path.EndpointA.ChannelID, path.EndpointB.ChannelConfig.PortID, path.EndpointB.ChannelID, timeoutHeight, 0)
	ack := channeltypes.NewResultAcknowledgement([]byte{byte(1)})
	suite.Require().NoError(path.EndpointB.UpdateClient(ctx))
	suite.Require().NoError(path.EndpointB.RecvPacket(ctx, &transferPacket))
	suite.Require().NoError(path.EndpointA.AcknowledgePacket(ctx, &transferPacket, ack.Acknowledgement()))
	suite.Require().NoError(err) // relay committed

	// check that voucher exists on chain B
	voucherDenomTrace := types.ParseDenomTrace(types.GetPrefixedDenom(transferPacket.GetDestPort(), transferPacket.GetDestChannel(), sdk.DefaultBondDenom))
	balance := chainB.GetSimApp().BankKeeper.GetBalance(chainB.GetContext(), chainB.SenderAccount.GetAddress(), voucherDenomTrace.IBCDenom())

	coinSentFromAToB := types.GetTransferCoin(path.EndpointB.ChannelConfig.PortID, path.EndpointB.ChannelID, sdk.DefaultBondDenom, 100)
	suite.Require().Equal(coinSentFromAToB, balance)
}

func TestTendermintTestSuite(t *testing.T) {
	suite.Run(t, new(TendermintTestSuite))
}
