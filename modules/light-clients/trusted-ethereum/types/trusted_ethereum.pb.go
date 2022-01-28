// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ibc/lightclients/trustedethereum/v1/trusted_ethereum.proto

package types

import (
	fmt "fmt"
	types2 "github.com/cosmos/cosmos-sdk/codec/types"
	types "github.com/cosmos/ibc-go/modules/core/02-client/types"
	types1 "github.com/cosmos/ibc-go/modules/core/23-commitment/types"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type ClientState struct {
	ChainId         string `protobuf:"bytes,1,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"`
	IbcStoreAddress []byte `protobuf:"bytes,2,opt,name=ibc_store_address,json=ibcStoreAddress,proto3" json:"ibc_store_address,omitempty"`
	// Latest height the client was updated to
	LatestHeight types.Height `protobuf:"bytes,3,opt,name=latest_height,json=latestHeight,proto3" json:"latest_height" yaml:"latest_height"`
	// Block height when the client was frozen due to a misbehaviour
	FrozenHeight types.Height `protobuf:"bytes,4,opt,name=frozen_height,json=frozenHeight,proto3" json:"frozen_height" yaml:"frozen_height"`
}

func (m *ClientState) Reset()         { *m = ClientState{} }
func (m *ClientState) String() string { return proto.CompactTextString(m) }
func (*ClientState) ProtoMessage()    {}
func (*ClientState) Descriptor() ([]byte, []int) {
	return fileDescriptor_637abaadfc7d4c71, []int{0}
}
func (m *ClientState) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ClientState) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ClientState.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ClientState) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientState.Merge(m, src)
}
func (m *ClientState) XXX_Size() int {
	return m.Size()
}
func (m *ClientState) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientState.DiscardUnknown(m)
}

var xxx_messageInfo_ClientState proto.InternalMessageInfo

type ConsensusState struct {
	// timestamp that corresponds to the block height in which the ConsensusState
	// was stored.
	Timestamp uint64 `protobuf:"varint,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// storage root for ibc_store_address
	Root types1.MerkleRoot `protobuf:"bytes,2,opt,name=root,proto3" json:"root"`
	// public key of the trusted submitter
	PublicKey *types2.Any `protobuf:"bytes,3,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty" yaml:"public_key"`
	// diversifier allows the same public key to be re-used across different
	// clients (potentially on different chains) without being considered
	// misbehaviour.
	Diversifier string `protobuf:"bytes,4,opt,name=diversifier,proto3" json:"diversifier,omitempty"`
}

func (m *ConsensusState) Reset()         { *m = ConsensusState{} }
func (m *ConsensusState) String() string { return proto.CompactTextString(m) }
func (*ConsensusState) ProtoMessage()    {}
func (*ConsensusState) Descriptor() ([]byte, []int) {
	return fileDescriptor_637abaadfc7d4c71, []int{1}
}
func (m *ConsensusState) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ConsensusState) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ConsensusState.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ConsensusState) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConsensusState.Merge(m, src)
}
func (m *ConsensusState) XXX_Size() int {
	return m.Size()
}
func (m *ConsensusState) XXX_DiscardUnknown() {
	xxx_messageInfo_ConsensusState.DiscardUnknown(m)
}

var xxx_messageInfo_ConsensusState proto.InternalMessageInfo

// Header defines a multisig consensus header
type Header struct {
	// height to update multisig public key at
	Height    types.Height `protobuf:"bytes,1,opt,name=height,proto3" json:"height"`
	StateRoot []byte       `protobuf:"bytes,2,opt,name=state_root,json=stateRoot,proto3" json:"state_root,omitempty"`
	Timestamp uint64       `protobuf:"varint,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// account_proof follows the proof format of IBFT2.0 client
	AccountProof   []byte      `protobuf:"bytes,4,opt,name=account_proof,json=accountProof,proto3" json:"account_proof,omitempty"`
	Signature      []byte      `protobuf:"bytes,5,opt,name=signature,proto3" json:"signature,omitempty"`
	NewPublicKey   *types2.Any `protobuf:"bytes,6,opt,name=new_public_key,json=newPublicKey,proto3" json:"new_public_key,omitempty" yaml:"new_public_key"`
	NewDiversifier string      `protobuf:"bytes,7,opt,name=new_diversifier,json=newDiversifier,proto3" json:"new_diversifier,omitempty" yaml:"new_diversifier"`
}

func (m *Header) Reset()         { *m = Header{} }
func (m *Header) String() string { return proto.CompactTextString(m) }
func (*Header) ProtoMessage()    {}
func (*Header) Descriptor() ([]byte, []int) {
	return fileDescriptor_637abaadfc7d4c71, []int{2}
}
func (m *Header) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Header) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Header.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Header) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Header.Merge(m, src)
}
func (m *Header) XXX_Size() int {
	return m.Size()
}
func (m *Header) XXX_DiscardUnknown() {
	xxx_messageInfo_Header.DiscardUnknown(m)
}

var xxx_messageInfo_Header proto.InternalMessageInfo

// Misbehaviour defines misbehaviour for a multisig which consists
// of a sequence and two signatures over different messages at that sequence.
type Misbehaviour struct {
	ClientId string  `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty" yaml:"client_id"`
	Header1  *Header `protobuf:"bytes,2,opt,name=header_1,json=header1,proto3" json:"header_1,omitempty" yaml:"header_1"`
	Header2  *Header `protobuf:"bytes,3,opt,name=header_2,json=header2,proto3" json:"header_2,omitempty" yaml:"header_2"`
}

func (m *Misbehaviour) Reset()         { *m = Misbehaviour{} }
func (m *Misbehaviour) String() string { return proto.CompactTextString(m) }
func (*Misbehaviour) ProtoMessage()    {}
func (*Misbehaviour) Descriptor() ([]byte, []int) {
	return fileDescriptor_637abaadfc7d4c71, []int{3}
}
func (m *Misbehaviour) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Misbehaviour) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Misbehaviour.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Misbehaviour) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Misbehaviour.Merge(m, src)
}
func (m *Misbehaviour) XXX_Size() int {
	return m.Size()
}
func (m *Misbehaviour) XXX_DiscardUnknown() {
	xxx_messageInfo_Misbehaviour.DiscardUnknown(m)
}

var xxx_messageInfo_Misbehaviour proto.InternalMessageInfo

func init() {
	proto.RegisterType((*ClientState)(nil), "ibc.lightclients.trustedethereum.v1.ClientState")
	proto.RegisterType((*ConsensusState)(nil), "ibc.lightclients.trustedethereum.v1.ConsensusState")
	proto.RegisterType((*Header)(nil), "ibc.lightclients.trustedethereum.v1.Header")
	proto.RegisterType((*Misbehaviour)(nil), "ibc.lightclients.trustedethereum.v1.Misbehaviour")
}

func init() {
	proto.RegisterFile("ibc/lightclients/trustedethereum/v1/trusted_ethereum.proto", fileDescriptor_637abaadfc7d4c71)
}

var fileDescriptor_637abaadfc7d4c71 = []byte{
	// 734 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x94, 0x4d, 0x6f, 0xdb, 0x36,
	0x18, 0xc7, 0x2d, 0xc7, 0xb3, 0x63, 0x5a, 0x49, 0x16, 0xc1, 0x19, 0x1c, 0x23, 0x93, 0x0c, 0xe5,
	0xb0, 0x60, 0x83, 0x25, 0xc8, 0xbb, 0x0c, 0xc1, 0x2e, 0x71, 0x76, 0x48, 0x36, 0x04, 0x08, 0x14,
	0xec, 0x52, 0xa0, 0x50, 0xf5, 0x42, 0xdb, 0x44, 0x24, 0xd1, 0x20, 0x29, 0x07, 0xee, 0xa1, 0x9f,
	0xa1, 0xed, 0xa7, 0xca, 0x31, 0xc7, 0xa2, 0x07, 0xa1, 0x75, 0xbe, 0x81, 0x3f, 0x41, 0x41, 0x51,
	0xb2, 0xe5, 0x14, 0xe8, 0xdb, 0x8d, 0xcf, 0x5f, 0xff, 0xe7, 0x85, 0x3f, 0x52, 0x04, 0xa7, 0xc8,
	0xf3, 0xcd, 0x10, 0x8d, 0x27, 0xcc, 0x0f, 0x11, 0x8c, 0x19, 0x35, 0x19, 0x49, 0x28, 0x83, 0x01,
	0x64, 0x13, 0x48, 0x60, 0x12, 0x99, 0x33, 0xab, 0x90, 0x9c, 0x42, 0x33, 0xa6, 0x04, 0x33, 0xac,
	0x1c, 0x23, 0xcf, 0x37, 0xca, 0xb9, 0xc6, 0x93, 0x5c, 0x63, 0x66, 0x75, 0xdb, 0x63, 0x3c, 0xc6,
	0x99, 0xdf, 0xe4, 0x2b, 0x91, 0xda, 0x3d, 0x1c, 0x63, 0x3c, 0x0e, 0xa1, 0x99, 0x45, 0x5e, 0x32,
	0x32, 0xdd, 0x78, 0x9e, 0x7f, 0xd2, 0xf8, 0x44, 0x3e, 0x26, 0xd0, 0x14, 0x55, 0xf9, 0x00, 0x62,
	0x95, 0x1b, 0x7e, 0x5b, 0x1b, 0x70, 0x14, 0x21, 0x16, 0x15, 0xa6, 0x55, 0x24, 0x8c, 0xfa, 0xdb,
	0x2a, 0x68, 0x9d, 0x67, 0x99, 0x37, 0xcc, 0x65, 0x50, 0x39, 0x04, 0xdb, 0xfe, 0xc4, 0x45, 0xb1,
	0x83, 0x82, 0x8e, 0xd4, 0x93, 0x4e, 0x9a, 0x76, 0x23, 0x8b, 0x2f, 0x03, 0xe5, 0x77, 0xb0, 0x8f,
	0x3c, 0xdf, 0xa1, 0x0c, 0x13, 0xe8, 0xb8, 0x41, 0x40, 0x20, 0xa5, 0x9d, 0x6a, 0x4f, 0x3a, 0x91,
	0xed, 0x3d, 0xe4, 0xf9, 0x37, 0x5c, 0x3f, 0x13, 0xb2, 0xf2, 0x1c, 0xec, 0x84, 0x2e, 0x83, 0x94,
	0x39, 0x13, 0xc8, 0x37, 0xdf, 0xd9, 0xea, 0x49, 0x27, 0xad, 0x41, 0xd7, 0xe0, 0x38, 0xf8, 0x5c,
	0x46, 0x3e, 0xee, 0xcc, 0x32, 0x2e, 0x32, 0xc7, 0xf0, 0xe8, 0x3e, 0xd5, 0x2a, 0xcb, 0x54, 0x6b,
	0xcf, 0xdd, 0x28, 0x3c, 0xd5, 0x37, 0xd2, 0x75, 0x5b, 0x16, 0xb1, 0xf0, 0xf2, 0xf2, 0x23, 0x82,
	0x5f, 0xc2, 0xb8, 0x28, 0x5f, 0xfb, 0xde, 0xf2, 0x1b, 0xe9, 0xba, 0x2d, 0x8b, 0x58, 0x78, 0xf5,
	0xf7, 0x12, 0xd8, 0x3d, 0xc7, 0x31, 0x85, 0x31, 0x4d, 0xa8, 0xe0, 0x72, 0x04, 0x9a, 0x0c, 0x45,
	0x90, 0x32, 0x37, 0x9a, 0x66, 0x60, 0x6a, 0xf6, 0x5a, 0x50, 0xfe, 0x06, 0x35, 0x82, 0x31, 0xcb,
	0x68, 0xb4, 0x06, 0x7a, 0x69, 0x8c, 0x35, 0xef, 0x99, 0x65, 0x5c, 0x41, 0x72, 0x1b, 0x42, 0x1b,
	0x63, 0x36, 0xac, 0xf1, 0x71, 0xec, 0x2c, 0x4b, 0xf9, 0x17, 0x80, 0x69, 0xe2, 0x85, 0xc8, 0x77,
	0x6e, 0xe1, 0x3c, 0x27, 0xd5, 0x36, 0xc4, 0xe9, 0x1b, 0xc5, 0xe9, 0x1b, 0x67, 0xf1, 0x7c, 0x78,
	0xb0, 0x4c, 0xb5, 0x7d, 0xb1, 0x81, 0x75, 0x86, 0x6e, 0x37, 0x45, 0xf0, 0x1f, 0x9c, 0x2b, 0x3d,
	0xd0, 0x0a, 0xd0, 0x0c, 0x12, 0x8a, 0x46, 0x08, 0x92, 0x8c, 0x4b, 0xd3, 0x2e, 0x4b, 0x7a, 0x5a,
	0x05, 0xf5, 0x0b, 0xe8, 0x06, 0x90, 0x28, 0x7f, 0x81, 0x7a, 0xce, 0x4f, 0xfa, 0x2a, 0x3f, 0x31,
	0x70, 0xee, 0x57, 0x7e, 0x05, 0x80, 0x72, 0x2e, 0xce, 0x6a, 0xdb, 0xb2, 0xdd, 0xcc, 0x14, 0xbe,
	0xbb, 0x4d, 0x5a, 0x5b, 0x4f, 0x69, 0x1d, 0x83, 0x1d, 0xd7, 0xf7, 0x71, 0x12, 0x33, 0x67, 0x4a,
	0x30, 0x1e, 0x65, 0x53, 0xca, 0xb6, 0x9c, 0x8b, 0xd7, 0x5c, 0xe3, 0x25, 0x28, 0x1a, 0xc7, 0x2e,
	0x4b, 0x08, 0xec, 0xfc, 0x94, 0x37, 0x28, 0x04, 0xe5, 0x7f, 0xb0, 0x1b, 0xc3, 0x3b, 0xa7, 0x84,
	0xad, 0xfe, 0x05, 0x6c, 0x87, 0xcb, 0x54, 0x3b, 0x10, 0xd8, 0x36, 0xb3, 0x74, 0x5b, 0x8e, 0xe1,
	0xdd, 0xf5, 0x8a, 0xde, 0x39, 0xd8, 0xe3, 0x86, 0x32, 0xc1, 0x06, 0x27, 0x38, 0xec, 0x2e, 0x53,
	0xed, 0x97, 0x75, 0x85, 0x32, 0x4f, 0x9b, 0x4f, 0xf2, 0x4f, 0x49, 0x78, 0x53, 0x05, 0xf2, 0x15,
	0xa2, 0x1e, 0x9c, 0xb8, 0x33, 0x84, 0x13, 0xa2, 0x58, 0xa0, 0x29, 0x70, 0xae, 0x7e, 0xaa, 0x61,
	0x7b, 0x99, 0x6a, 0x3f, 0x8b, 0x7a, 0xab, 0x4f, 0xba, 0xbd, 0x2d, 0xd6, 0x97, 0x81, 0x32, 0x02,
	0xdb, 0x93, 0xec, 0x8c, 0x1c, 0x2b, 0xbf, 0x54, 0x7f, 0x18, 0xdf, 0xf0, 0x92, 0x18, 0xe2, 0x60,
	0x87, 0xea, 0x22, 0xd5, 0x1a, 0x62, 0x6d, 0x2d, 0x53, 0x6d, 0x4f, 0x74, 0x2a, 0x2a, 0xea, 0x76,
	0x43, 0x2c, 0xad, 0x52, 0x9f, 0x41, 0x7e, 0xf1, 0x7e, 0xb4, 0xcf, 0xe0, 0xb3, 0x3e, 0x83, 0x55,
	0x9f, 0xc1, 0xf0, 0xd5, 0xfd, 0x47, 0xb5, 0x72, 0xbf, 0x50, 0xa5, 0x87, 0x85, 0x2a, 0x7d, 0x58,
	0xa8, 0xd2, 0xeb, 0x47, 0xb5, 0xf2, 0xf0, 0xa8, 0x56, 0xde, 0x3d, 0xaa, 0x95, 0x67, 0x2f, 0xc6,
	0x88, 0x4d, 0x12, 0x8f, 0xff, 0x2d, 0x66, 0xe0, 0x32, 0x37, 0x7b, 0x71, 0x42, 0xd7, 0x33, 0x91,
	0xe7, 0xf7, 0xf3, 0xee, 0xfd, 0xa2, 0x7d, 0x3f, 0x7f, 0xf2, 0x22, 0x1c, 0x24, 0x21, 0xa4, 0xe2,
	0x61, 0xee, 0x3f, 0x79, 0x99, 0x57, 0x6e, 0x93, 0xcd, 0xa7, 0x90, 0x7a, 0xf5, 0xec, 0x3e, 0xfc,
	0xf9, 0x29, 0x00, 0x00, 0xff, 0xff, 0xe5, 0x23, 0x11, 0xde, 0xcb, 0x05, 0x00, 0x00,
}

func (m *ClientState) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClientState) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ClientState) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	{
		size, err := m.FrozenHeight.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x22
	{
		size, err := m.LatestHeight.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x1a
	if len(m.IbcStoreAddress) > 0 {
		i -= len(m.IbcStoreAddress)
		copy(dAtA[i:], m.IbcStoreAddress)
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(len(m.IbcStoreAddress)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.ChainId) > 0 {
		i -= len(m.ChainId)
		copy(dAtA[i:], m.ChainId)
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(len(m.ChainId)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ConsensusState) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ConsensusState) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ConsensusState) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Diversifier) > 0 {
		i -= len(m.Diversifier)
		copy(dAtA[i:], m.Diversifier)
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(len(m.Diversifier)))
		i--
		dAtA[i] = 0x22
	}
	if m.PublicKey != nil {
		{
			size, err := m.PublicKey.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintTrustedEthereum(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	{
		size, err := m.Root.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	if m.Timestamp != 0 {
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(m.Timestamp))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *Header) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Header) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Header) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.NewDiversifier) > 0 {
		i -= len(m.NewDiversifier)
		copy(dAtA[i:], m.NewDiversifier)
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(len(m.NewDiversifier)))
		i--
		dAtA[i] = 0x3a
	}
	if m.NewPublicKey != nil {
		{
			size, err := m.NewPublicKey.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintTrustedEthereum(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x32
	}
	if len(m.Signature) > 0 {
		i -= len(m.Signature)
		copy(dAtA[i:], m.Signature)
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(len(m.Signature)))
		i--
		dAtA[i] = 0x2a
	}
	if len(m.AccountProof) > 0 {
		i -= len(m.AccountProof)
		copy(dAtA[i:], m.AccountProof)
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(len(m.AccountProof)))
		i--
		dAtA[i] = 0x22
	}
	if m.Timestamp != 0 {
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(m.Timestamp))
		i--
		dAtA[i] = 0x18
	}
	if len(m.StateRoot) > 0 {
		i -= len(m.StateRoot)
		copy(dAtA[i:], m.StateRoot)
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(len(m.StateRoot)))
		i--
		dAtA[i] = 0x12
	}
	{
		size, err := m.Height.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *Misbehaviour) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Misbehaviour) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Misbehaviour) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Header2 != nil {
		{
			size, err := m.Header2.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintTrustedEthereum(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.Header1 != nil {
		{
			size, err := m.Header1.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintTrustedEthereum(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.ClientId) > 0 {
		i -= len(m.ClientId)
		copy(dAtA[i:], m.ClientId)
		i = encodeVarintTrustedEthereum(dAtA, i, uint64(len(m.ClientId)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintTrustedEthereum(dAtA []byte, offset int, v uint64) int {
	offset -= sovTrustedEthereum(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *ClientState) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ChainId)
	if l > 0 {
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	l = len(m.IbcStoreAddress)
	if l > 0 {
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	l = m.LatestHeight.Size()
	n += 1 + l + sovTrustedEthereum(uint64(l))
	l = m.FrozenHeight.Size()
	n += 1 + l + sovTrustedEthereum(uint64(l))
	return n
}

func (m *ConsensusState) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Timestamp != 0 {
		n += 1 + sovTrustedEthereum(uint64(m.Timestamp))
	}
	l = m.Root.Size()
	n += 1 + l + sovTrustedEthereum(uint64(l))
	if m.PublicKey != nil {
		l = m.PublicKey.Size()
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	l = len(m.Diversifier)
	if l > 0 {
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	return n
}

func (m *Header) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.Height.Size()
	n += 1 + l + sovTrustedEthereum(uint64(l))
	l = len(m.StateRoot)
	if l > 0 {
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	if m.Timestamp != 0 {
		n += 1 + sovTrustedEthereum(uint64(m.Timestamp))
	}
	l = len(m.AccountProof)
	if l > 0 {
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	l = len(m.Signature)
	if l > 0 {
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	if m.NewPublicKey != nil {
		l = m.NewPublicKey.Size()
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	l = len(m.NewDiversifier)
	if l > 0 {
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	return n
}

func (m *Misbehaviour) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ClientId)
	if l > 0 {
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	if m.Header1 != nil {
		l = m.Header1.Size()
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	if m.Header2 != nil {
		l = m.Header2.Size()
		n += 1 + l + sovTrustedEthereum(uint64(l))
	}
	return n
}

func sovTrustedEthereum(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozTrustedEthereum(x uint64) (n int) {
	return sovTrustedEthereum(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ClientState) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTrustedEthereum
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClientState: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClientState: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ChainId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ChainId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field IbcStoreAddress", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.IbcStoreAddress = append(m.IbcStoreAddress[:0], dAtA[iNdEx:postIndex]...)
			if m.IbcStoreAddress == nil {
				m.IbcStoreAddress = []byte{}
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field LatestHeight", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.LatestHeight.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FrozenHeight", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.FrozenHeight.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTrustedEthereum(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ConsensusState) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTrustedEthereum
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ConsensusState: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ConsensusState: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Timestamp", wireType)
			}
			m.Timestamp = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Timestamp |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Root", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Root.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PublicKey", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.PublicKey == nil {
				m.PublicKey = &types2.Any{}
			}
			if err := m.PublicKey.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Diversifier", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Diversifier = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTrustedEthereum(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Header) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTrustedEthereum
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Header: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Header: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Height", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Height.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field StateRoot", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.StateRoot = append(m.StateRoot[:0], dAtA[iNdEx:postIndex]...)
			if m.StateRoot == nil {
				m.StateRoot = []byte{}
			}
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Timestamp", wireType)
			}
			m.Timestamp = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Timestamp |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AccountProof", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AccountProof = append(m.AccountProof[:0], dAtA[iNdEx:postIndex]...)
			if m.AccountProof == nil {
				m.AccountProof = []byte{}
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Signature", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Signature = append(m.Signature[:0], dAtA[iNdEx:postIndex]...)
			if m.Signature == nil {
				m.Signature = []byte{}
			}
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field NewPublicKey", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.NewPublicKey == nil {
				m.NewPublicKey = &types2.Any{}
			}
			if err := m.NewPublicKey.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field NewDiversifier", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.NewDiversifier = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTrustedEthereum(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Misbehaviour) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTrustedEthereum
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Misbehaviour: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Misbehaviour: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ClientId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ClientId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Header1", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Header1 == nil {
				m.Header1 = &Header{}
			}
			if err := m.Header1.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Header2", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Header2 == nil {
				m.Header2 = &Header{}
			}
			if err := m.Header2.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTrustedEthereum(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthTrustedEthereum
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipTrustedEthereum(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTrustedEthereum
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTrustedEthereum
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthTrustedEthereum
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupTrustedEthereum
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthTrustedEthereum
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthTrustedEthereum        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTrustedEthereum          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupTrustedEthereum = fmt.Errorf("proto: unexpected end of group")
)