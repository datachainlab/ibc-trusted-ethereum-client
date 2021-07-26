package channel

import (
	clienttypes "github.com/cosmos/ibc-go/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/modules/core/exported"
)

var _ exported.PacketI = (*Packet)(nil)

func (packet *Packet) GetSequence() uint64 {
	return packet.Sequence
}

func (packet *Packet) GetTimeoutHeight() exported.Height {
	// FIXME
	return clienttypes.Height{
		RevisionNumber: packet.TimeoutHeight.GetRevisionNumber(),
		RevisionHeight: packet.TimeoutHeight.GetRevisionHeight(),
	}
}

func (packet *Packet) GetTimeoutTimestamp() uint64 {
	return packet.TimeoutTimestamp
}

func (packet *Packet) GetSourcePort() string {
	return packet.SourcePort
}

func (packet *Packet) GetSourceChannel() string {
	return packet.SourceChannel
}

func (packet *Packet) GetDestPort() string {
	return packet.DestinationPort
}

func (packet *Packet) GetDestChannel() string {
	return packet.DestinationChannel
}

func (packet *Packet) GetData() []byte {
	return packet.Data
}

func (packet *Packet) ValidateBasic() error {
	return nil
}
