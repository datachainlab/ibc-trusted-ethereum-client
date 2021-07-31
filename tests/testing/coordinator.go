package ibctesting

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/datachainlab/ibc-trusted-ethereum-client/tests/testing/types"
)

type Coordinator struct {
	t *testing.T

	Chains []types.TestChainI
}

func NewCoordinator(t *testing.T, chains ...types.TestChainI) Coordinator {
	for _, chain := range chains {
		if err := chain.Init(); err != nil {
			panic(err)
		}
	}
	return Coordinator{t: t, Chains: chains}
}

func (c Coordinator) GetChain(idx int) types.TestChainI {
	return c.Chains[idx]
}

// CommitBlock commits a block on the provided indexes and then increments the global time.
//
// CONTRACT: the passed in list of indexes must not contain duplicates
func (coord *Coordinator) CommitBlock(chains ...types.TestChainI) {
	for _, chain := range chains {
		chain.NextBlock()
	}
}

// Setup constructs a TM client, connection, and channel on both Chains provided. It will
// fail if any error occurs. The clientID's, TestConnections, and TestChannels are returned
// for both Chains. The channels created are connected to the ibc-transfer application.
func (coord *Coordinator) Setup(ctx context.Context, path *Path) {
	coord.SetupConnections(ctx, path)

	// channels can also be referenced through the returned connections
	coord.CreateChannels(ctx, path)
}

// SetupClientConnections is a helper function to create clients and the appropriate
// connections on both the source and counterparty chain. It assumes the caller does not
// anticipate any errors.
func (coord *Coordinator) SetupConnections(ctx context.Context, path *Path) {
	coord.SetupClients(ctx, path)
	coord.CreateConnections(ctx, path)
}

// SetupClients is a helper function to create clients on both Chains. It assumes the
// caller does not anticipate any errors.
func (coord *Coordinator) SetupClients(ctx context.Context, path *Path) {
	err := path.EndpointA.CreateClient(ctx)
	require.NoError(coord.t, err)

	err = path.EndpointB.CreateClient(ctx)
	require.NoError(coord.t, err)
}

// CreateConnections constructs and executes connection handshake messages in order to create
// OPEN channels on chainA and chainB. The connection information of for chainA and chainB
// are returned within a TestConnection struct. The function expects the connections to be
// successfully opened otherwise testing will fail.
func (coord *Coordinator) CreateConnections(ctx context.Context, path *Path) {

	err := path.EndpointA.ConnOpenInit(ctx)
	require.NoError(coord.t, err)

	err = path.EndpointB.ConnOpenTry(ctx)
	require.NoError(coord.t, err)

	err = path.EndpointA.ConnOpenAck(ctx)
	require.NoError(coord.t, err)

	err = path.EndpointB.ConnOpenConfirm(ctx)
	require.NoError(coord.t, err)
}

// CreateChannels constructs and executes channel handshake messages in order to create
// OPEN channels on chainA and chainB. The function expects the channels to be successfully
// opened otherwise testing will fail.
func (coord *Coordinator) CreateChannels(ctx context.Context, path *Path) {
	err := path.EndpointA.ChanOpenInit(ctx)
	require.NoError(coord.t, err)

	err = path.EndpointB.ChanOpenTry(ctx)
	require.NoError(coord.t, err)

	err = path.EndpointA.ChanOpenAck(ctx)
	require.NoError(coord.t, err)

	err = path.EndpointB.ChanOpenConfirm(ctx)
	require.NoError(coord.t, err)
}
