package types

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

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
			"adress,uint256*3", args{data: []interface{}{"0x14723a09acff6d2a60dcdf7aa4aff308fddc160c", big.NewInt(1000), big.NewInt(2), big.NewInt(3)}},
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
