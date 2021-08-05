package types

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/assert"
)

func Test_clientStateCommitSlot(t *testing.T) {
	got, err := clientStateCommitmentSlot("dummy")
	// calculated with web3.js:
	//   web3.utils.soliditySha3({t: 'bytes', v: web3.utils.soliditySha3({t: 'uint8', v: '0'}, "dummy")}, new BN(0))
	expected := hexutil.MustDecode("0x97ea163fb10e33695b64a6614153eda97be45d3091233132ffe6244a42f67167")
	assert.NoError(t, err)
	assert.Equal(t, expected, got)
}
func Test_consensusStateCommitmentSlot(t *testing.T) {
	got, err := consensusStateCommitmentSlot("dummy", uint64(100))
	// calculated with web3.js:
	//   web3.utils.soliditySha3({t: 'bytes', v: web3.utils.soliditySha3({t: 'uint8', v: '1'}, "dummy", "/", {t: 'uint64', v: '100'})}, new BN(0))
	expected := hexutil.MustDecode("0xfcfc6964a35588536ba3235ae938769b113cadde0d01a90df1a2b3385aea3f6c")
	assert.NoError(t, err)
	assert.Equal(t, expected, got)
}

func Test_connectionCommitmentSlot(t *testing.T) {
	got, err := connectionCommitmentSlot("dummy")
	// calculated with web3.js:
	//   web3.utils.soliditySha3({t: 'bytes', v: web3.utils.soliditySha3({t: 'uint8', v: '2'}, "dummy")}, new BN(0))
	expected := hexutil.MustDecode("0x18a8fa4ffca4943c10185beedf9a5213834501dcaf9663a5ff48b42c08de50dc")
	assert.NoError(t, err)
	assert.Equal(t, expected, got)
}

func Test_channelCommitmentSlot(t *testing.T) {
	got, err := channelCommitmentSlot("port", "dummy")
	// calculated with web3.js:
	//   web3.utils.soliditySha3({t: 'bytes', v: web3.utils.soliditySha3({t: 'uint8', v: '3'}, "port", "/", "dummy")}, new BN(0))
	expected := hexutil.MustDecode("0x9d8ab2aa12af57a51194c5d1a602da7935f4053bd23d42ac40df27c5937a7f20")
	assert.NoError(t, err)
	assert.Equal(t, expected, got)
}

func Test_packetCommitmentSlot(t *testing.T) {
	got, err := packetCommitmentSlot("port", "dummy", uint64(1))
	// calculated with web3.js:
	//   web3.utils.soliditySha3({t: 'bytes', v: web3.utils.soliditySha3({t: 'uint8', v: '4'}, "port", "/", "dummy", "/", {t: 'uint64', v: '1'})}, new BN(0))
	expected := hexutil.MustDecode("0x2734277411ed2d3676c2e2796d69f356a43da11f9c2ae0711e302962e5614b74")
	assert.NoError(t, err)
	assert.Equal(t, expected, got)
}

func Test_packetAcknowledgementCommitmentSlot(t *testing.T) {
	got, err := packetAcknowledgementCommitmentSlot("port", "dummy", uint64(1))
	// calculated with web3.js:
	//   web3.utils.soliditySha3({t: 'bytes', v: web3.utils.soliditySha3({t: 'uint8', v: '5'}, "port", "/", "dummy", "/", {t: 'uint64', v: '1'})}, new BN(0))
	expected := hexutil.MustDecode("0x919e9f45e9d7ea03ca371db62f537d8fd64fc21149cce6ab10511f967d1b2d32")
	assert.NoError(t, err)
	assert.Equal(t, expected, got)
}

func Test_keccak256AbiEncodePacked(t *testing.T) {
	type args struct {
		data []interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"string*2", args{data: []interface{}{"a", "bc"}},
			hexutil.MustDecode("0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"), false,
		},
		{
			"uint256", args{data: []interface{}{big.NewInt(1)}},
			hexutil.MustDecode("0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"), false,
		},
		{
			"adress string,uint256*3", args{data: []interface{}{"0x14723a09acff6d2a60dcdf7aa4aff308fddc160c", big.NewInt(1000), big.NewInt(2), big.NewInt(3)}},
			hexutil.MustDecode("0xba8d5962e0104473dd6a49779d2afa5102c737ee651e58dc159c01d3cc38b5ea"), false,
		},
		{
			"adress,uint256*3", args{data: []interface{}{common.HexToAddress("0x14723a09acff6d2a60dcdf7aa4aff308fddc160c"), big.NewInt(1000), big.NewInt(2), big.NewInt(3)}},
			hexutil.MustDecode("0xba8d5962e0104473dd6a49779d2afa5102c737ee651e58dc159c01d3cc38b5ea"), false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keccak256AbiEncodePacked(tt.args.data...)
			if (err != nil) != tt.wantErr {
				t.Errorf("keccak256AbiEncodePacked() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keccak256AbiEncodePacked() = %v, want %v", got, tt.want)
			}
		})
	}
}
