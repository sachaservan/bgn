package bgn

import (
	"math/big"
	"testing"
)

const KEYBITS = 512
const POLYBASE = 3
const MSGSPACE = 1021 // message space for polynomial coefficients
const FPSCALEBASE = 3
const FPPREC = 0.0001
const DET = true // deterministic ops

func TestMarshalUnmarshalPublicKey(t *testing.T) {

	// THere is a bug with the PBC lib that prevents this test from playing nice
	// with the other tests (something about generating a pairing from string)
	// the test works fine on its own but not when running `go test`
	t.SkipNow()

	pk, _, err := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	if err != nil {
		t.Fatalf("%v", err)
	}

	bytes, _ := pk.MarshalBinary()

	pk = &PublicKey{}
	pk.UnmarshalBinary(bytes)
}

func TestMarshalUnmarshalCiphertext(t *testing.T) {
	pk, _, err := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	if err != nil {
		t.Fatalf("%v", err)
	}

	ct := pk.encryptZero()
	tct := &TransportableCiphertext{ct, pk.PairingParams}

	bytes, _ := tct.MarshalBinary()

	tct = &TransportableCiphertext{}
	tct.UnmarshalBinary(bytes)
}

func TestMarshalUnmarshalPolyCiphertext(t *testing.T) {
	pk, _, err := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	if err != nil {
		t.Fatalf("%v", err)
	}

	m := pk.NewPolyPlaintext(big.NewFloat(2.99))
	ct := pk.EncryptPoly(m)
	tct := &TransportablePolyCiphertext{ct, pk.PairingParams}

	bytes, _ := tct.MarshalBinary()

	tct = &TransportablePolyCiphertext{}
	tct.UnmarshalBinary(bytes)
}

func TestMarshalUnmarshalPublicKeyNil(t *testing.T) {
	pk := &PublicKey{}
	bytes, _ := pk.MarshalBinary()
	pk.UnmarshalBinary(bytes)

}

func TestMarshalUnmarshalCiphertextNil(t *testing.T) {

	ct := &TransportableCiphertext{}
	bytes, _ := ct.MarshalBinary()
	ct.UnmarshalBinary(bytes)
}

func TestMarshalUnmarshalPolyCiphertextNil(t *testing.T) {

	ct := &TransportablePolyCiphertext{}
	bytes, _ := ct.MarshalBinary()
	ct.UnmarshalBinary(bytes)
}

func BenchmarkKeyGen(b *testing.B) {

	for i := 0; i < b.N; i++ {
		_, _, err := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkAdd(b *testing.B) {
	pk, _, err := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	if err != nil {
		panic(err)
	}

	c := pk.Encrypt(big.NewInt(1))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pk.Add(c, c)
	}
}

func BenchmarkMultConstant(b *testing.B) {
	pk, _, err := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	if err != nil {
		panic(err)
	}

	c := pk.Encrypt(big.NewInt(1))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pk.MultConst(c, big.NewInt(1))
	}
}

func BenchmarkMult(b *testing.B) {
	pk, _, err := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	if err != nil {
		panic(err)
	}

	c := pk.Encrypt(big.NewInt(1))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pk.Mult(c, c)
	}
}
