module github.com/datachainlab/ibc-trusted-ethereum-client/e2e/relayer

go 1.16

require (
	github.com/datachainlab/ibc-trusted-ethereum-client v0.0.0-00010101000000-000000000000
	github.com/hyperledger-labs/yui-relayer v0.1.1-0.20211209032245-495b5eed40e2
)

replace (
	github.com/cosmos/ibc-go => github.com/datachainlab/ibc-go v0.0.0-20210623043207-6582d8c965f8
	github.com/datachainlab/ibc-trusted-ethereum-client => ../../
	github.com/go-kit/kit => github.com/go-kit/kit v0.8.0
	github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.2-alpha.regen.4
	// XXX patch mock prover
	github.com/hyperledger-labs/yui-relayer => github.com/datachainlab/yui-relayer v0.1.1-0.20211216063020-3a1e3bbd4915
	github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
)
