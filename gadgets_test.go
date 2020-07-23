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

func TestDecryptionProofAggregateValid(t *testing.T) {

	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	pk.SetupDecryption(sk)

	r1 := newCryptoRandom(pk.N)
	v1 := newCryptoRandom(pk.N)
	r2 := newCryptoRandom(pk.N)
	v2 := newCryptoRandom(pk.N)

	ct1 := pk.EncryptWithRandomness(v1, r1)
	ct2 := pk.EncryptWithRandomness(v2, r2)

	v3 := big.NewInt(0).Add(v1, v2)
	r3 := big.NewInt(0).Add(r1, r2)
	ct3 := pk.Add(ct1, ct2)

	proof := NewDecryptionProof(v3, r3)

	if !pk.CheckDecryptionProof(ct3, proof) {
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

	proof := NewDecryptionProof(v, r2) // wrong randomness

	if pk.CheckDecryptionProof(ct, proof) {
		t.Fail()
	}

	proof = NewDecryptionProof(r2, r) // wrong value

	if pk.CheckDecryptionProof(ct, proof) {
		t.Fail()
	}
}

func TestProofOfPlaintextKnowledgeValid(t *testing.T) {

	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	pk.SetupDecryption(sk)

	r := newCryptoRandom(pk.N)
	v := newCryptoRandom(pk.N)
	ct := pk.EncryptWithRandomness(v, r)

	proof := pk.NewProofOfPlaintextKnowledge(sk, v, r)

	if !pk.CheckProofOfPlaintextKnoewledge(ct, proof) {
		t.Fail()
	}

}
func TestProofOfPlaintextKnowledgeBad(t *testing.T) {

	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	pk.SetupDecryption(sk)

	r := newCryptoRandom(pk.N)
	r2 := newCryptoRandom(pk.N)
	v := newCryptoRandom(pk.N)
	ct := pk.EncryptWithRandomness(v, r)

	proof := pk.NewProofOfPlaintextKnowledge(sk, v, r2) // wrong randomness

	if pk.CheckProofOfPlaintextKnoewledge(ct, proof) {
		t.Fail()
	}

	proof = pk.NewProofOfPlaintextKnowledge(sk, r2, r) // wrong value

	if pk.CheckProofOfPlaintextKnoewledge(ct, proof) {
		t.Fail()
	}
}

func BenchmarkProofOfPlaintextKnowledgeGen(b *testing.B) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	r := newCryptoRandom(pk.N)
	v := newCryptoRandom(pk.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.NewProofOfPlaintextKnowledge(sk, v, r)
	}
}

func BenchmarkProofOfPlaintextKnowledgeVerify(b *testing.B) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	r := newCryptoRandom(pk.N)
	v := newCryptoRandom(pk.N)
	ct := pk.EncryptWithRandomness(v, r)
	proof := pk.NewProofOfPlaintextKnowledge(sk, v, r)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.CheckProofOfPlaintextKnoewledge(ct, proof)
	}
}
