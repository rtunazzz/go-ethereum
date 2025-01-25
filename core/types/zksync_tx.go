package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

// ZKSyncTxType represents a L2 transaction type.
const ZKSyncTxType = 0x71

// ZKSyncTransaction provides support for ZKsync specific features
// such as account abstraction and paymasters.
// Smart contracts must be deployed with this transaction type.
type ZKSyncTransaction struct {
	Nonce     *big.Int        `json:"nonce"`     // Nonce to use for the transaction execution.
	GasTipCap *big.Int        `json:"gasTipCap"` // EIP-1559 tip per gas.
	GasFeeCap *big.Int        `json:"gasFeeCap"` // EIP-1559 fee cap per gas.
	Gas       *big.Int        `json:"gas"`       // Gas limit to set for the transaction execution.
	To        *common.Address `json:"to"`        // The address of the recipient.
	Value     *big.Int        `json:"value"`     // Funds to transfer along the transaction (nil = 0 = no funds).
	Data      hexutil.Bytes   `json:"data"`      // Input data, usually an ABI-encoded contract method invocation.

	ChainID *big.Int        `json:"chainID"` // Chain ID of the network.
	From    *common.Address `json:"from"`    // The address of the sender.

	// GasPerPubdata denotes the maximum amount of gas the user is willing
	// to pay for a single byte of pubdata.
	GasPerPubdata *big.Int `json:"gasPerPubdata"`
	// CustomSignature is used for the cases in which the signer's account
	// is not an EOA.
	CustomSignature hexutil.Bytes `json:"customSignature"`
	// FactoryDeps is a non-empty array of bytes. For deployment transactions,
	// it should contain the bytecode of the contract being deployed.
	// If the contract is a factory contract, i.e. it can deploy other contracts,
	// the array should also contain the bytecodes of the contracts which it can deploy.
	FactoryDeps []hexutil.Bytes `json:"factoryDeps"`
	// PaymasterParams contains parameters for configuring the custom paymaster
	// for the transaction.
	PaymasterParams *PaymasterParams `json:"paymasterParams"`
}

// Encode uses RLP encoding to transforms transaction to sequence of bytes.
func (tx *ZKSyncTransaction) Encode(sig []byte) ([]byte, error) {
	// use custom struct to get right RLP sequence and types to use default rlp encoder
	zkSyncTxRLP := struct {
		Nonce                uint64
		MaxPriorityFeePerGas *big.Int
		MaxFeePerGas         *big.Int
		GasLimit             *big.Int
		To                   *common.Address `rlp:"nil"` // nil means contract creation
		Value                *big.Int
		Data                 hexutil.Bytes
		// zkSync part
		ChainId1 *big.Int // legacy
		Empty1   string   // legacy
		Empty2   string   // legacy
		ChainId2 *big.Int
		From     *common.Address
		// Meta fields   *Meta
		GasPerPubdata   *big.Int
		FactoryDeps     []hexutil.Bytes
		CustomSignature hexutil.Bytes
		PaymasterParams *PaymasterParams
	}{
		Nonce:                tx.Nonce.Uint64(),
		MaxPriorityFeePerGas: tx.GasTipCap,
		MaxFeePerGas:         tx.GasFeeCap,
		GasLimit:             tx.Gas,
		To:                   tx.To,
		Value:                tx.Value,
		Data:                 tx.Data,
		ChainId1:             tx.ChainID,
		ChainId2:             tx.ChainID,
		From:                 tx.From,
		GasPerPubdata:        tx.GasPerPubdata,
		FactoryDeps:          tx.FactoryDeps,
		CustomSignature:      tx.CustomSignature,
		PaymasterParams:      tx.PaymasterParams,
	}
	if len(zkSyncTxRLP.CustomSignature) == 0 {
		zkSyncTxRLP.CustomSignature = sig
	}

	res, err := rlp.EncodeToBytes(zkSyncTxRLP)
	if err != nil {
		return nil, fmt.Errorf("failed to encode RLP bytes: %w", err)
	}
	return append([]byte{0x71}, res...), nil
}

// Decode creates the transaction form sequence of bytes using RLP encoding.
func (tx *ZKSyncTransaction) Decode(input []byte) error {
	type zkSyncTxRLP struct {
		Nonce                uint64
		MaxPriorityFeePerGas *big.Int
		MaxFeePerGas         *big.Int
		GasLimit             *big.Int
		To                   *common.Address `rlp:"nil"` // nil means contract creation
		Value                *big.Int
		Data                 hexutil.Bytes
		// zkSync part
		ChainId1 *big.Int // legacy
		Empty1   string   // legacy
		Empty2   string   // legacy
		ChainId2 *big.Int
		From     *common.Address
		// Meta fields   *Meta
		GasPerPubdata   *big.Int
		FactoryDeps     []hexutil.Bytes
		CustomSignature hexutil.Bytes
		PaymasterParams *PaymasterParams `rlp:"nil"`
	}
	var decodedTx zkSyncTxRLP
	err := rlp.DecodeBytes(input[1:], &decodedTx)
	if err != nil {
		return err
	}

	tx.Nonce = new(big.Int).SetUint64(decodedTx.Nonce)
	tx.GasTipCap = decodedTx.MaxPriorityFeePerGas
	tx.GasFeeCap = decodedTx.MaxFeePerGas
	tx.Gas = decodedTx.GasLimit
	tx.To = decodedTx.To
	tx.Value = decodedTx.Value
	tx.Data = decodedTx.Data
	tx.ChainID = decodedTx.ChainId2
	tx.From = decodedTx.From
	tx.GasPerPubdata = decodedTx.GasPerPubdata
	tx.CustomSignature = decodedTx.CustomSignature
	tx.FactoryDeps = decodedTx.FactoryDeps
	tx.PaymasterParams = decodedTx.PaymasterParams
	return nil
}

// Copy creates a copy of the transaction.
func (tx *ZKSyncTransaction) Copy() *ZKSyncTransaction {
	if tx == nil {
		return nil
	}

	cpy := &ZKSyncTransaction{
		Nonce:           new(big.Int),
		GasTipCap:       new(big.Int),
		GasFeeCap:       new(big.Int),
		Gas:             new(big.Int),
		Value:           new(big.Int),
		ChainID:         new(big.Int),
		To:              copyAddressPtr(tx.To),
		From:            copyAddressPtr(tx.From),
		Data:            common.CopyBytes(tx.Data),
		CustomSignature: common.CopyBytes(tx.CustomSignature),
		GasPerPubdata:   new(big.Int),
		FactoryDeps:     make([]hexutil.Bytes, len(tx.FactoryDeps)),
	}

	if tx.Nonce != nil {
		cpy.Nonce.Set(tx.Nonce)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	if tx.Gas != nil {
		cpy.Gas.Set(tx.Gas)
	}
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasPerPubdata != nil {
		cpy.GasPerPubdata.Set(tx.GasPerPubdata)
	}

	for i, dep := range tx.FactoryDeps {
		cpy.FactoryDeps[i] = common.CopyBytes(dep)
	}

	if tx.PaymasterParams != nil {
		cpy.PaymasterParams = &PaymasterParams{
			Paymaster:      *copyAddressPtr(&tx.PaymasterParams.Paymaster),
			PaymasterInput: common.CopyBytes(tx.PaymasterParams.PaymasterInput),
		}
	}

	return cpy
}

func (tx *ZKSyncTransaction) MarshalJSON() ([]byte, error) {
	type Alias ZKSyncTransaction
	fdb := make([][]uint, len(tx.FactoryDeps))
	for i, v := range tx.FactoryDeps {
		fdb[i] = make([]uint, len(v))
		for j, b := range v {
			fdb[i][j] = uint(b)
		}
	}
	return json.Marshal(&struct {
		*Alias
		FactoryDeps [][]uint `json:"factoryDeps"`
	}{
		Alias:       (*Alias)(tx),
		FactoryDeps: fdb,
	})
}

func (tx *ZKSyncTransaction) getFactoryDepsHashes() ([]interface{}, error) {
	if len(tx.FactoryDeps) == 0 {
		return []interface{}{}, nil
	}
	res := make([]interface{}, len(tx.FactoryDeps))
	for i, d := range tx.FactoryDeps {
		h, err := hashBytecode(d)
		if err != nil {
			return nil, fmt.Errorf("failed to get hash of some bytecode in FactoryDeps")
		}
		res[i] = h
	}
	return res, nil
}

// PaymasterParams contains parameters for configuring the custom paymaster for the transaction.
type PaymasterParams struct {
	Paymaster      common.Address `json:"paymaster"`      // Address of the paymaster.
	PaymasterInput []byte         `json:"paymasterInput"` // Encoded input.
}

func (p *PaymasterParams) MarshalJSON() ([]byte, error) {
	type PaymasterParams struct {
		Paymaster      common.Address `json:"paymaster"`
		PaymasterInput []int          `json:"paymasterInput"`
	}
	var input []int
	for _, b := range p.PaymasterInput {
		input = append(input, int(b))
	}
	params := PaymasterParams{
		Paymaster:      p.Paymaster,
		PaymasterInput: input,
	}

	return json.Marshal(params)
}

// TxData interface implementation methods

func (tx *ZKSyncTransaction) txType() byte { return ZKSyncTxType }

func (tx *ZKSyncTransaction) chainID() *big.Int { return tx.ChainID }

func (tx *ZKSyncTransaction) accessList() AccessList { return AccessList{} }

func (tx *ZKSyncTransaction) data() []byte { return tx.Data }

func (tx *ZKSyncTransaction) gas() uint64 { return tx.Gas.Uint64() }

func (tx *ZKSyncTransaction) gasPrice() *big.Int { return tx.GasFeeCap }

func (tx *ZKSyncTransaction) gasTipCap() *big.Int { return tx.GasTipCap }

func (tx *ZKSyncTransaction) gasFeeCap() *big.Int { return tx.GasFeeCap }

func (tx *ZKSyncTransaction) value() *big.Int { return tx.Value }

func (tx *ZKSyncTransaction) nonce() uint64 { return tx.Nonce.Uint64() }

func (tx *ZKSyncTransaction) to() *common.Address { return tx.To }

func (tx *ZKSyncTransaction) rawSignatureValues() (v, r, s *big.Int) {
	// return tx.V, tx.R, tx.S
	return nil, nil, nil
}

func (tx *ZKSyncTransaction) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID = chainID
	// tx.V = v
	// tx.R = r
	// tx.S = s
}

func (tx *ZKSyncTransaction) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return new(big.Int).Set(tx.GasFeeCap)
	}
	tip := new(big.Int).Set(tx.GasTipCap)
	if tip.Cmp(tx.GasFeeCap) > 0 {
		tip.Set(tx.GasFeeCap)
	}

	effectivePrice := new(big.Int).Add(tip, baseFee)
	if effectivePrice.Cmp(tx.GasFeeCap) > 0 {
		effectivePrice.Set(tx.GasFeeCap)
	}
	return dst.Set(effectivePrice)
}

func (tx *ZKSyncTransaction) encode(w *bytes.Buffer) error {
	encoded, err := tx.Encode(nil)
	if err != nil {
		return err
	}
	w.Write(encoded)
	return nil
}

func (tx *ZKSyncTransaction) decode(input []byte) error {
	return tx.Decode(input)
}

func (tx *ZKSyncTransaction) copy() TxData {
	return tx.Copy()
}

func hashBytecode(bytecode []byte) ([]byte, error) {
	if len(bytecode)%32 != 0 {
		return nil, errors.New("bytecode length in bytes must be divisible by 32")
	}
	bytecodeHash := sha256.Sum256(bytecode)
	// get real length of bytecode, which is presented as 32-byte words
	length := big.NewInt(int64(len(bytecode) / 32))
	if length.BitLen() > 16 {
		return nil, errors.New("bytecode length must be less than 2^16 bytes")
	}
	// replace first 2 bytes of hash with version
	version := []byte{1, 0}
	copy(bytecodeHash[0:2], version)
	// replace second 2 bytes of hash with bytecode length
	length2b := make([]byte, 2)
	length2b = length.FillBytes(length2b) // 0-padded in 2 bytes
	copy(bytecodeHash[2:4], length2b)
	return bytecodeHash[:], nil
}
