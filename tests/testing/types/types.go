package types

import (
	"github.com/cosmos/ibc-go/modules/core/exported"
)

type Proof struct {
	Height exported.Height
	Data   []byte
}

type MsgCreateClient struct {
	ClientType          string
	Height              exported.Height
	ClientStateBytes    []byte
	ConsensusStateBytes []byte
}

type MsgUpdateClient struct {
	ClientID string
	Header   []byte
}

type MsgConnectionOpenInit struct {
	ClientID              string
	CounterpartyClientID  string
	CounterpartyKeyPrefix []byte
	DelayPeriod           uint64
	Version               exported.Version
	Signer                string
}

type MsgConnectionOpenTry struct {
	ClientID                 string
	PreviousConnectionID     string
	ClientStateBytes         []byte
	CounterpartyClientID     string
	CounterpartyConnectionID string
	CounterpartyKeyPrefix    []byte
	DelayPeriod              uint64
	Versions                 []exported.Version
	ProofInit                *Proof
	ProofClient              *Proof
	ProofConsensus           *Proof
	ConsensusHeight          exported.Height
	Signer                   string
}

type MsgConnectionOpenAck struct {
	ConnectionID             string
	CounterpartyConnectionID string
	Version                  exported.Version
	ClientStateBytes         []byte
	ProofTry                 *Proof
	ProofClient              *Proof
	ProofConsensus           *Proof
	ConsensusHeight          exported.Height
	Signer                   string
}

type MsgConnectionOpenConfirm struct {
	ConnectionID string
	ProofAck     *Proof
	Signer       string
}

type MsgChannelOpenInit struct {
	PortID             string
	Order              ChannelOrder
	CounterpartyPortID string
	ConnectionHops     []string
	Version            string
	Signer             string
}

type MsgChannelOpenTry struct {
	PortID                string
	PreviousChannelID     string
	Ordering              ChannelOrder
	CounterpartyChannelID string
	CounterpartyPortID    string
	ConnectionHops        []string
	Version               string
	CounterpartyVersion   string
	ProofInit             *Proof
	Signer                string
}

type MsgChannelOpenAck struct {
	PortID                string
	ChannelID             string
	CounterpartyChannelID string
	CounterpartyVersion   string
	ProofTry              *Proof
	Signer                string
}

type MsgChannelOpenConfirm struct {
	PortID    string
	ChannelID string
	ProofAck  *Proof
	Signer    string
}

type ChannelOrder int32

const (
	NONE      ChannelOrder = 0
	UNORDERED ChannelOrder = 1
	ORDERED   ChannelOrder = 2
)

type ChannelState int32

const (
	UNINITIALIZED ChannelState = 0
	INIT          ChannelState = 1
	TRYOPEN       ChannelState = 2
	OPEN          ChannelState = 3
	CLOSED        ChannelState = 4
)
