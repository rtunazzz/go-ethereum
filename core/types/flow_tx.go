package types

import (
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// flowDirectCallV is the V of a Flow EVM direct call (flow-go DirectCallTxType).
var flowDirectCallV = big.NewInt(255)

// FlowDirectCallTx is a Flow EVM direct call: a call a Cadence-owned account
// (COA) issues from Cadence, authorized by the Flow transaction's signature
// rather than ECDSA. flow-go fvm/evm/types/call.go (DirectCall.Transaction)
// encodes it as a legacy tx with V=255 (DirectCallTxType), R=the COA address
// (big endian) and S=the call subtype byte (deposit, withdraw, transfer,
// deploy, call); the Flow RPC reports it as type 0x0. It keeps that legacy
// encoding, so its hash is the one the Flow node reports.
//
// Only UnmarshalJSON (the RPC block path) classifies it, by the legacy shape
// V == 255, R ≤ 20 bytes, S ≤ 1 byte. RLP/binary-decoded direct calls stay
// *LegacyTx: there is no type id to switch on, Flow encodes them as legacy.
// Trade-off: a genuine chain-110 legacy tx with V=255 and such a tiny R and S
// would decode as a direct call; no monitored chain uses id 110.
//
// GasPrice survives JSON round trips but not RLP ones, which encode it as 0.
type FlowDirectCallTx struct {
	LegacyTx
	From    common.Address // the COA, from R
	SubType uint8          // the direct-call subtype, from S
}

func (tx *FlowDirectCallTx) copy() TxData {
	return &FlowDirectCallTx{
		LegacyTx: *tx.LegacyTx.copy().(*LegacyTx),
		From:     tx.From,
		SubType:  tx.SubType,
	}
}

// EncodeRLP writes the legacy encoding the tx hash commits to. flow-go builds
// it with GasPrice 0, while the RPC reports the block's gas price, so the
// encoding zeroes GasPrice.
func (tx *FlowDirectCallTx) EncodeRLP(w io.Writer) error {
	enc := tx.LegacyTx
	enc.GasPrice = common.Big0
	return rlp.Encode(w, &enc)
}
