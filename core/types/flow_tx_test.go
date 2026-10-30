package types

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

// Flow EVM (747) block 82828903, as eth_getTransactionByHash returns them
// (block fields dropped).
var flowDirectCalls = []struct {
	json string
	hash common.Hash
	coa  common.Address
}{
	{
		json: `{"from":"0x00000000000000000000000249250a5c27ecab3b","gas":"0xe4e1c0","gasPrice":"0x1","hash":"0x15082185860f691fee2abb2615cdfe4c62595c04bb057e6c2cc4625b9027102c","input":"0xa9059cbb000000000000000000000000000000000000000000000002dddc0646105a3fd40000000000000000000000000000000000000000000000000000000000f1dfec","nonce":"0x106584","to":"0xf1815bd50389c46847f0bda824ec8da914045d14","value":"0x0","type":"0x0","v":"0xff","r":"0x249250a5c27ecab3b","s":"0x5"}`,
		hash: common.HexToHash("0x15082185860f691fee2abb2615cdfe4c62595c04bb057e6c2cc4625b9027102c"),
		coa:  common.HexToAddress("0x00000000000000000000000249250a5c27ecab3b"),
	},
	{
		json: `{"from":"0x000000000000000000000002dddc0646105a3fd4","gas":"0xea60","gasPrice":"0x1","hash":"0xb5f025d5dfb70bacaf4b4ac34e9646e1b2fbdff466807391676d04a31e442783","input":"0x095ea7b3000000000000000000000000eedc6ff75e1b10b903d9013c358e446a73d353410000000000000000000000000000000000000000000000000000000000f1dfec","nonce":"0x21713","to":"0xf1815bd50389c46847f0bda824ec8da914045d14","value":"0x0","type":"0x0","v":"0xff","r":"0x2dddc0646105a3fd4","s":"0x5"}`,
		hash: common.HexToHash("0xb5f025d5dfb70bacaf4b4ac34e9646e1b2fbdff466807391676d04a31e442783"),
		coa:  common.HexToAddress("0x000000000000000000000002dddc0646105a3fd4"),
	},
	{
		json: `{"from":"0x000000000000000000000002dddc0646105a3fd4","gas":"0xe4e1c0","gasPrice":"0x1","hash":"0xac7e5c98ab1b015200b1c43bca9a2d08f540133140f4d10f092ca697f78389a5","input":"0x04e45aaf000000000000000000000000f1815bd50389c46847f0bda824ec8da914045d1400000000000000000000000099af3eea856556646c98c8b9b2548fe8152407500000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000002dddc0646105a3fd40000000000000000000000000000000000000000000000000000000000f1dfec00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","nonce":"0x21714","to":"0xeedc6ff75e1b10b903d9013c358e446a73d35341","value":"0x0","type":"0x0","v":"0xff","r":"0x2dddc0646105a3fd4","s":"0x5"}`,
		hash: common.HexToHash("0xac7e5c98ab1b015200b1c43bca9a2d08f540133140f4d10f092ca697f78389a5"),
		coa:  common.HexToAddress("0x000000000000000000000002dddc0646105a3fd4"),
	},
}

func TestFlowDirectCallDecode(t *testing.T) {
	signer := LatestSignerForChainID(big.NewInt(747))

	for _, tc := range flowDirectCalls {
		t.Run(tc.hash.Hex(), func(t *testing.T) {
			var fromJSON Transaction
			if err := json.Unmarshal([]byte(tc.json), &fromJSON); err != nil {
				t.Fatal(err)
			}
			reJSON, err := json.Marshal(&fromJSON)
			if err != nil {
				t.Fatal(err)
			}
			var fromReJSON Transaction
			if err := json.Unmarshal(reJSON, &fromReJSON); err != nil {
				t.Fatal(err)
			}

			for name, tx := range map[string]*Transaction{"json": &fromJSON, "json round-trip": &fromReJSON} {
				inner, ok := tx.inner.(*FlowDirectCallTx)
				if !ok {
					t.Fatalf("%s: inner = %T, want *FlowDirectCallTx", name, tx.inner)
				}
				if inner.From != tc.coa || inner.SubType != 5 {
					t.Errorf("%s: From, SubType = %s, %d, want %s, 5", name, inner.From, inner.SubType, tc.coa)
				}
				if tx.Type() != LegacyTxType {
					t.Errorf("%s: Type() = %d, want legacy", name, tx.Type())
				}
				if got := tx.Hash(); got != tc.hash {
					t.Errorf("%s: Hash() = %s, want %s", name, got, tc.hash)
				}
				from, err := Sender(signer, tx)
				if err != nil || from != tc.coa {
					t.Errorf("%s: Sender() = %s, %v, want %s", name, from, err, tc.coa)
				}
			}
		})
	}
}

func TestFlowDirectCallMarshalJSON(t *testing.T) {
	sample := flowDirectCalls[0].json
	var tx Transaction
	if err := json.Unmarshal([]byte(sample), &tx); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(&tx)
	if err != nil {
		t.Fatal(err)
	}
	var node, got map[string]any
	if err := json.Unmarshal([]byte(sample), &node); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	for k, want := range node {
		if got[k] != want {
			t.Errorf("%s = %v, node reports %v", k, got[k], want)
		}
	}
	for k, v := range got {
		if _, ok := node[k]; !ok && v != nil {
			t.Errorf("%s = %v, node omits it", k, v)
		}
	}
}

func TestFlowDirectCallShape(t *testing.T) {
	coaR := new(big.Int).SetBytes(flowDirectCalls[0].coa.Bytes())

	tests := []struct {
		name    string
		v, r, s *big.Int
		want    bool
	}{
		{name: "direct call", v: big.NewInt(255), r: coaR, s: big.NewInt(5), want: true},
		{name: "V=256", v: big.NewInt(256), r: coaR, s: big.NewInt(5)},
		{name: "V above 64 bits truncating to 255", v: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(255)), r: coaR, s: big.NewInt(5)},
		{name: "21-byte R", v: big.NewInt(255), r: new(big.Int).Lsh(big.NewInt(1), 160), s: big.NewInt(5)},
		{name: "S above one byte", v: big.NewInt(255), r: coaR, s: big.NewInt(256)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fields map[string]any
			if err := json.Unmarshal([]byte(flowDirectCalls[0].json), &fields); err != nil {
				t.Fatal(err)
			}
			fields["v"], fields["r"], fields["s"] = (*hexutil.Big)(tt.v), (*hexutil.Big)(tt.r), (*hexutil.Big)(tt.s)
			enc, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			var tx Transaction
			if err := json.Unmarshal(enc, &tx); err != nil {
				t.Fatal(err)
			}
			if _, got := tx.inner.(*FlowDirectCallTx); got != tt.want {
				t.Errorf("decoded as %T, want direct call %v", tx.inner, tt.want)
			}
		})
	}
}

func TestFlowDirectCallRLPStaysLegacy(t *testing.T) {
	var tx Transaction
	if err := json.Unmarshal([]byte(flowDirectCalls[0].json), &tx); err != nil {
		t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var fromBinary, fromRLP Transaction
	if err := fromBinary.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if err := rlp.DecodeBytes(raw, &fromRLP); err != nil {
		t.Fatal(err)
	}
	for name, dec := range map[string]*Transaction{"binary": &fromBinary, "rlp": &fromRLP} {
		if _, ok := dec.inner.(*LegacyTx); !ok {
			t.Errorf("%s: inner = %T, want *LegacyTx", name, dec.inner)
		}
		if got := dec.Hash(); got != flowDirectCalls[0].hash {
			t.Errorf("%s: Hash() = %s, want %s", name, got, flowDirectCalls[0].hash)
		}
	}
}
