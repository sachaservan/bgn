package bgn

import (
	"math/big"
	"testing"
)

func TestDecryptionProofValid(t *testing.T) {

	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	pk.SetupDecryption(sk)

	r := newCryptoRandom(pk.N)
	v := newCryptoRandom(pk.N)
	ct := pk.EncryptWithRandomness(v, r)

	proof := NewDecryptionProof(v, r)

	if !pk.CheckDecryptionProof(ct, proof) {
		t.Fail()
	}
}

func TestDecryptionProofBad(t *testing.T) {

	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	pk.SetupDecryption(sk)

	r := newCryptoRandom(pk.N)
	r2 := newCryptoRandom(pk.N)
	v := newCryptoRandom(pk.N)
	ct := pk.EncryptWithRandomness(v, r)

	proof := NewDecryptionProof(v, r2)

	if pk.CheckDecryptionProof(ct, proof) {
		t.Fail()
	}
}
