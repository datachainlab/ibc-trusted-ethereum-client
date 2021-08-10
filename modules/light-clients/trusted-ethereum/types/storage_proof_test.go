package types_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	ethtypes "github.com/datachainlab/ibc-trusted-ethereum-client/modules/light-clients/trusted-ethereum/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
)

var (
	ibcHostAddress = "0xff77D90D6aA12db33d3Ba50A34fB25401f6e4c4F"

	connectionID        = "connection-0"
	connectionStateRoot = "0x2c5ec426ec2e9e87f8dfbcea85eb41eb18d76993cbd376bee1ccfb3d3031a322"
	connectionProofStr  = `
{
  "accountProof": [
    "0xf90171a015554a048f215b0cca2c9b333bb0e4858fbc6f0043b4cc8ce4e73f2f3d4d8b8a80a00aae3f778009d4c7262b599388e147dac73ed7720900df3d4361f0a2362e8a6080a0c8b2f0a32e327b1bd474b408dc0ef7d8cd92c681c1ffcf600dceee49b70572c0808080a02fa427b687ae26760458e91c2ed6d42fdf20528498a82ddad378435d09274d71a0978717427d115a32abff927470196068003785c44d20b65597cc79bd183ee58ea0c4ee2e6188b03b9b0b143ea5a74938152bbe7fe6194bdc91e781feb5108d61b8a036bed7c6fee0a675252a51cf343a6f5e7f68e9f6c71c0a9338506d8cc4cdfd4fa0b732cf07e5fc764f66dc3b5992f14bec0c3c8d23865ac7b092715aab9d4070c7a05fcb62014bbe37b0e5dac5d384e55562302db3b6fc85c71195bb3577d1839c17a08c00b105bbfbfe089c1e0e9e8077048d07b79d560b46b7a8b8b1b65ce5a25fd4a02e7156f0ca707a204b12cb48a1c1e914b5826b9597b5ddfc10aedc6766d42c0b80",
    "0xf85180808080a044bbbf29fa16247b5669df525d759ba83c4069937eca41c32532182ee130956280808080808080a0a4cb0f3aa0c3e9a0fbf9004307ca6f66906fc0f41c9877c2b408ddd2d05e6d8e80808080",
    "0xf869a0206090ccaa6fa9fa12360268a84aaba21af051a53bfdc84493350c840f61b79eb846f8440180a0f70348e0dd46c70eee5e8486170c7e7cb89854652a34f8de1a68824ffa68b74fa06cca14f0899a4948ed1642735e8eb09a4e370c9ee7f942e7ff0bd669321acb9d"
  ],
  "address": "0xff77D90D6aA12db33d3Ba50A34fB25401f6e4c4F",
  "balance": "0x0",
  "codeHash": "0x6cca14f0899a4948ed1642735e8eb09a4e370c9ee7f942e7ff0bd669321acb9d",
  "nonce": "0x1",
  "storageHash": "0xf70348e0dd46c70eee5e8486170c7e7cb89854652a34f8de1a68824ffa68b74f",
  "storageProof": [
    {
      "key": "101392464214429074323589656453768341800743193834298849172737608785312291407178",
      "value": "0xa3f866c2f0bceb2f1e14e5e7e4837e8bcab47361e8748733992f345f9172ade2",
      "proof": [
        "0xf901f1a07c557e403b5746ca2ddb0dfb3221fd63420cd7322bdf3d43482e5c88ea0a725ca032b9f921847abcd35c3cf02dcf19b3287426239d68cc19091bf606bfa9501a5ba0a5c9f5dcc3ea856d7ed07bb9b63fd2b048d4da37716ab3c72b821ec281f0e966a01c25983a1e4c655c8e57216b8933686e90372b38c20b76f34e8a00b916d3abeba061d542dbae7d4273a266de1ca9a1a2c2398147f456ec775105fe38ab0f043134a08fb9a463bf45d64964ad7ed90812d23974913e0092597e67118f0f1dc18f89cfa0aff38635c8f6494da20bda649e28afcde6a28ae93c5df4aebc3639adc3423352a018ab718df52f5d0f0559bf951fba6a3db3ca17a1862d5f3f8bc8052f6695066ba0d9139554563e16dcd41483cb4623303946aef3992e58c4a4bd99a250d5e7155f80a072b4347a5e778d640854003fadfd3016cd6288c761e51000c5448623b1d657e6a0d13b3f3e9586d6ba56dae2626110ba23f0bee838e32bf18878bbfbbfcec9bb83a0b6c632b7fd7015d264a3103a6cfa8c0f98e478a1ad9ecad4bf111a43311f16d0a01601cb84b3430b6d0a1649330cfbbbf7c411e88c73af305e04787ca9a6d033c5a069b88f7614eecc285df53cdd6e2bbb857a8294970c003fca965f83cc009409b7a0c1f010b8477785059395615f2ad9e8a472f5e090dd719bd17091e2b382d4c5bf80",
        "0xf89180808080808080a03f9136691ff5f9d4e131aa6979aa6e8b831057b44d9799abcf795f41862fc9218080a0859e199f39bb9759e53bc4fcdd9fc0dbf15f56d9e81a5004260c15fc5e1825428080a0586c18b485445eed041ec0e35dd928d3d2b9aca9b0b64d5a10b49224c99605f280a09c3a64ed2d8506b444b5f231a1bf2f6e3d245a44b6127b6e9426054c24dbb24080",
        "0xf87180808080a0fa0205954f19f1e5933d14d7ea2dffd9680952b9ae4ffdd5c004f047450f4511a0ceeed6afdc5c7bbc1f95d748c0694bf2e062eafd1cc626b3388d2face59a3058a0bc8109e9234fc37c81207a3012699a14d820b4e0098a32a4dc260aa49419ef2580808080808080808080",
        "0xf8429f30f1d3170b0645107a020b46a33b237e0681763473a74cdf6eb024eaec6fd0a1a0a3f866c2f0bceb2f1e14e5e7e4837e8bcab47361e8748733992f345f9172ade2"
      ]
    }
  ]
}
`
	connectionStorageHash = "0xf70348e0dd46c70eee5e8486170c7e7cb89854652a34f8de1a68824ffa68b74f"
	connectionValue       = "0xa3f866c2f0bceb2f1e14e5e7e4837e8bcab47361e8748733992f345f9172ade2"
)

type ETHProof struct {
	AccountProofRLP []byte
	StorageProofRLP [][]byte
}

// storageResult and accountResult are from ethereum/go-ethereum
type storageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

type accountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *hexutil.Big    `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []storageResult `json:"storageProof"`
}

func Test_VerifyProof_connectionProof(t *testing.T) {
	var ar accountResult
	err := json.Unmarshal([]byte(connectionProofStr), &ar)
	assert.NoError(t, err)

	ap, err := encodeRLP(ar.AccountProof)
	assert.NoError(t, err)
	sp, err := encodeRLP(ar.StorageProof[0].Proof)
	assert.NoError(t, err)

	accountProof, err := ethtypes.ExportDecoreRLP(ap)
	assert.NoError(t, err)
	stateRoot := common.HexToHash(connectionStateRoot)
	_, err = ethtypes.VerifyEthAccountProof(accountProof, stateRoot, ar.Address.Bytes())
	assert.NoError(t, err)

	storageProof, err := ethtypes.ExportDecoreRLP(sp)
	assert.NoError(t, err)
	key, err := ethtypes.ConnectionCommitmentSlot(connectionID)
	assert.NoError(t, err)
	value := hexutil.MustDecode(connectionValue)
	err = ethtypes.VerifyEthStorageProof(storageProof, ar.StorageHash, key, value)
	assert.NoError(t, err)
}

// test case for using ETHProof as input
func Test_VerifyProof_ETHProof_connectionProof(t *testing.T) {
	ap, err := encodeRLP([]string{
		"0xf90171a015554a048f215b0cca2c9b333bb0e4858fbc6f0043b4cc8ce4e73f2f3d4d8b8a80a00aae3f778009d4c7262b599388e147dac73ed7720900df3d4361f0a2362e8a6080a0c8b2f0a32e327b1bd474b408dc0ef7d8cd92c681c1ffcf600dceee49b70572c0808080a02fa427b687ae26760458e91c2ed6d42fdf20528498a82ddad378435d09274d71a0978717427d115a32abff927470196068003785c44d20b65597cc79bd183ee58ea0c4ee2e6188b03b9b0b143ea5a74938152bbe7fe6194bdc91e781feb5108d61b8a036bed7c6fee0a675252a51cf343a6f5e7f68e9f6c71c0a9338506d8cc4cdfd4fa0b732cf07e5fc764f66dc3b5992f14bec0c3c8d23865ac7b092715aab9d4070c7a05fcb62014bbe37b0e5dac5d384e55562302db3b6fc85c71195bb3577d1839c17a08c00b105bbfbfe089c1e0e9e8077048d07b79d560b46b7a8b8b1b65ce5a25fd4a02e7156f0ca707a204b12cb48a1c1e914b5826b9597b5ddfc10aedc6766d42c0b80",
		"0xf85180808080a044bbbf29fa16247b5669df525d759ba83c4069937eca41c32532182ee130956280808080808080a0a4cb0f3aa0c3e9a0fbf9004307ca6f66906fc0f41c9877c2b408ddd2d05e6d8e80808080",
		"0xf869a0206090ccaa6fa9fa12360268a84aaba21af051a53bfdc84493350c840f61b79eb846f8440180a0f70348e0dd46c70eee5e8486170c7e7cb89854652a34f8de1a68824ffa68b74fa06cca14f0899a4948ed1642735e8eb09a4e370c9ee7f942e7ff0bd669321acb9d",
	})
	assert.NoError(t, err)
	sp, err := encodeRLP([]string{
		"0xf901f1a07c557e403b5746ca2ddb0dfb3221fd63420cd7322bdf3d43482e5c88ea0a725ca032b9f921847abcd35c3cf02dcf19b3287426239d68cc19091bf606bfa9501a5ba0a5c9f5dcc3ea856d7ed07bb9b63fd2b048d4da37716ab3c72b821ec281f0e966a01c25983a1e4c655c8e57216b8933686e90372b38c20b76f34e8a00b916d3abeba061d542dbae7d4273a266de1ca9a1a2c2398147f456ec775105fe38ab0f043134a08fb9a463bf45d64964ad7ed90812d23974913e0092597e67118f0f1dc18f89cfa0aff38635c8f6494da20bda649e28afcde6a28ae93c5df4aebc3639adc3423352a018ab718df52f5d0f0559bf951fba6a3db3ca17a1862d5f3f8bc8052f6695066ba0d9139554563e16dcd41483cb4623303946aef3992e58c4a4bd99a250d5e7155f80a072b4347a5e778d640854003fadfd3016cd6288c761e51000c5448623b1d657e6a0d13b3f3e9586d6ba56dae2626110ba23f0bee838e32bf18878bbfbbfcec9bb83a0b6c632b7fd7015d264a3103a6cfa8c0f98e478a1ad9ecad4bf111a43311f16d0a01601cb84b3430b6d0a1649330cfbbbf7c411e88c73af305e04787ca9a6d033c5a069b88f7614eecc285df53cdd6e2bbb857a8294970c003fca965f83cc009409b7a0c1f010b8477785059395615f2ad9e8a472f5e090dd719bd17091e2b382d4c5bf80",
		"0xf89180808080808080a03f9136691ff5f9d4e131aa6979aa6e8b831057b44d9799abcf795f41862fc9218080a0859e199f39bb9759e53bc4fcdd9fc0dbf15f56d9e81a5004260c15fc5e1825428080a0586c18b485445eed041ec0e35dd928d3d2b9aca9b0b64d5a10b49224c99605f280a09c3a64ed2d8506b444b5f231a1bf2f6e3d245a44b6127b6e9426054c24dbb24080",
		"0xf87180808080a0fa0205954f19f1e5933d14d7ea2dffd9680952b9ae4ffdd5c004f047450f4511a0ceeed6afdc5c7bbc1f95d748c0694bf2e062eafd1cc626b3388d2face59a3058a0bc8109e9234fc37c81207a3012699a14d820b4e0098a32a4dc260aa49419ef2580808080808080808080",
		"0xf8429f30f1d3170b0645107a020b46a33b237e0681763473a74cdf6eb024eaec6fd0a1a0a3f866c2f0bceb2f1e14e5e7e4837e8bcab47361e8748733992f345f9172ade2",
	})
	assert.NoError(t, err)
	ethProof := ETHProof{
		AccountProofRLP: ap,
		StorageProofRLP: [][]byte{sp},
	}

	accountProof, err := ethtypes.ExportDecoreRLP(ethProof.AccountProofRLP)
	assert.NoError(t, err)
	stateRoot := common.HexToHash(connectionStateRoot)
	address := common.HexToAddress(ibcHostAddress)
	_, err = ethtypes.VerifyEthAccountProof(accountProof, stateRoot, address.Bytes())
	assert.NoError(t, err)

	storageProof, err := ethtypes.ExportDecoreRLP(ethProof.StorageProofRLP[0])
	assert.NoError(t, err)
	key, err := ethtypes.ConnectionCommitmentSlot(connectionID)
	assert.NoError(t, err)
	value := hexutil.MustDecode(connectionValue)
	storageHash := common.HexToHash(connectionStorageHash)
	err = ethtypes.VerifyEthStorageProof(storageProof, storageHash, key, value)
	assert.NoError(t, err)
}

func encodeRLP(proof []string) ([]byte, error) {
	var target [][][]byte
	for _, p := range proof {
		bz, err := hex.DecodeString(p[2:])
		if err != nil {
			panic(err)
		}
		var val [][]byte
		if err := rlp.DecodeBytes(bz, &val); err != nil {
			panic(err)
		}
		target = append(target, val)
	}
	bz, err := rlp.EncodeToBytes(target)
	if err != nil {
		return nil, err
	}
	return bz, nil
}
