package types

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Stable chain (988) blocks carry type-0x2 system transactions with a zero
// signature; the only sender source is the JSON 'from' field.
var stableSystemTxJSON = `{"type":"0x2","chainId":"0x3dc","nonce":"0x0","to":"0x0000000000000000000000000000000000009999","gas":"0x5208","maxFeePerGas":"0x0","maxPriorityFeePerGas":"0x0","value":"0x0","input":"0x","v":"0x0","r":"0x0","s":"0x0","from":"0x8888888888888888888888888888888888888888","hash":"0xcfd2634e06c2609c0a2008fb3632f4dd78d4e02332602d0b421431340c1f0671"}`

func TestZeroSignatureSystemTxSender(t *testing.T) {
	want := common.HexToAddress("0x8888888888888888888888888888888888888888")
	signer := LatestSignerForChainID(big.NewInt(988))

	var tx Transaction
	if err := json.Unmarshal([]byte(stableSystemTxJSON), &tx); err != nil {
		t.Fatalf("unmarshal system tx: %v", err)
	}
	from, err := Sender(signer, &tx)
	if err != nil {
		t.Fatalf("Sender: %v", err)
	}
	if from != want {
		t.Fatalf("sender = %s, want %s", from, want)
	}

	// The sender must survive a JSON round-trip (blocks are re-encoded when
	// cached or forwarded between services).
	enc, err := tx.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var rtx Transaction
	if err := json.Unmarshal(enc, &rtx); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	from, err = Sender(signer, &rtx)
	if err != nil {
		t.Fatalf("Sender after round-trip: %v", err)
	}
	if from != want {
		t.Fatalf("sender after round-trip = %s, want %s", from, want)
	}
}

// zkSync transactions (0x71/0xFF, e.g. Abstract) require a JSON 'from' and
// report nil signature values; decoding them must not panic, and the sender
// resolves via the embedded-sender path.
func TestZKSyncTxDecodeNoPanic(t *testing.T) {
	want := common.HexToAddress("0x1111111111111111111111111111111111111111")
	for _, typ := range []string{"0x71", "0xff"} {
		raw := `{"type":"` + typ + `","chainId":"0xab5","nonce":"0x1","to":"0x0000000000000000000000000000000000009999","gas":"0x100000","maxFeePerGas":"0x5f5e100","maxPriorityFeePerGas":"0x0","value":"0x0","input":"0x","from":"` + want.Hex() + `","hash":"0x0000000000000000000000000000000000000000000000000000000000000001"}`
		var tx Transaction
		if err := json.Unmarshal([]byte(raw), &tx); err != nil {
			t.Fatalf("type %s: unmarshal: %v", typ, err)
		}
		from, err := Sender(LatestSignerForChainID(big.NewInt(2741)), &tx)
		if err != nil {
			t.Fatalf("type %s: Sender: %v", typ, err)
		}
		if from != want {
			t.Fatalf("type %s: sender = %s, want %s", typ, from, want)
		}
	}
}

// A conflicting JSON 'from' must not override ECDSA recovery for signed txs.
func TestSignedTxIgnoresJSONFrom(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := LatestSignerForChainID(big.NewInt(1))
	to := common.HexToAddress("0x0000000000000000000000000000000000009999")
	signed, err := SignTx(NewTx(&DynamicFeeTx{
		ChainID:   big.NewInt(1),
		Nonce:     0,
		Gas:       21000,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		To:        &to,
		Value:     big.NewInt(0),
	}), signer, key)
	if err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	enc, err := signed.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	injected := strings.Replace(string(enc), `"v"`, `"from":"0x8888888888888888888888888888888888888888","v"`, 1)

	var tx Transaction
	if err := json.Unmarshal([]byte(injected), &tx); err != nil {
		t.Fatalf("unmarshal signed tx: %v", err)
	}
	if tx.jsonFrom != nil {
		t.Fatal("jsonFrom retained for a signed transaction")
	}
	from, err := Sender(signer, &tx)
	if err != nil {
		t.Fatalf("Sender: %v", err)
	}
	if want := crypto.PubkeyToAddress(key.PublicKey); from != want {
		t.Fatalf("sender = %s, want %s", from, want)
	}
}
