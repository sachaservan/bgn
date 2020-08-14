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

	pk, _, err := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	if err != nil {
		t.Fatalf("%v", err)
	}

	bytes, _ := pk.MarshalBinary()

	pk = &PublicKey{}
	pk.UnmarshalBinary(bytes)
}

func TestMarshalUnmarshalPublicKeyNil(t *testing.T) {
	pk := &PublicKey{}
	bytes, _ := pk.MarshalBinary()
	err := pk.UnmarshalBinary(bytes)
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestCiphertextToFromBytes(t *testing.T) {

	pk, _, err := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	if err != nil {
		t.Fatalf("%v", err)
	}

	expected := pk.Encrypt(big.NewInt(1))
	bytes, err := expected.Bytes()
	if err != nil {
		t.Fatalf("Error when encoding ciphertext to bytes %v\n", err.Error())
	}

	recovered, err := pk.NewCiphertextFromBytes(bytes)

	if err != nil {
		t.Fatalf("Error when recovering ciphertext from bytes %v\n", err.Error())
	}

	if expected.String() != recovered.String() {
		t.Fatalf("Incorrect recovery.Expected %v, got %v\n", expected, recovered)
	}
}

func TestPolyCiphertextToFromBytes(t *testing.T) {

	pk, _, err := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	if err != nil {
		t.Fatalf("%v", err)
	}

	m := pk.NewPolyPlaintext(big.NewFloat(2.99))

	expected := pk.EncryptPoly(m)
	bytes, err := expected.Bytes()
	if err != nil {
		t.Fatalf("Error when encoding ciphertext to bytes %v\n", err.Error())
	}

	recovered, err := pk.NewPolyCiphertextFromBytes(bytes)

	if err != nil {
		t.Fatalf("Error when recovering ciphertext from bytes %v\n", err.Error())
	}

	if expected.String() != recovered.String() {
		t.Fatalf("Incorrect recovery.Expected %v, got %v\n", expected, recovered)
	}
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
