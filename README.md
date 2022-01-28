# ibc-trusted-ethereum-client

Note: For Hyperledger Besu using IBFT2 consensus, the following IBC client is recommended. See: https://github.com/hyperledger-labs/yui-ibc-solidity/blob/main/docs/ibft2-light-client.md

---

IBC Trusted Ethereum Client is an IBC Module for validating Ethereum.

This repository provides the following
- A light client that verifies the state on Ethereum under the conditions described below
- A prover for [yui-relayer](https://github.com/hyperledger-labs/yui-relayer) that provides the necessary proofs for the light client

**This client assumes the existence of a trusted Relayer that submits headers that can be confidently confirmed on Ethereum.**

The client verifies each state for its membership using Merkle-proof based on the submitted headers.

We will develop the specification of this client in the future.
