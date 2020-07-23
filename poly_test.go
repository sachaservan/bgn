package bgn

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

func BenchmarkEncryptPoly(b *testing.B) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	plaintext := pk.NewPolyPlaintext(big.NewFloat(100.1))
	for i := 0; i < b.N; i++ {
		pk.EncryptPoly(plaintext)
	}
}

func BenchmarkDecryptPoly(b *testing.B) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)

	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)

	zero := pk.EncryptPoly(pk.NewPolyPlaintext(big.NewFloat(0.0)))

	for i := 0; i < b.N; i++ {
		sk.DecryptPoly(zero, pk)
	}
}

func BenchmarkAddPoly(b *testing.B) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	plaintext := pk.NewPolyPlaintext(big.NewFloat(100.1))
	ciphertext := pk.EncryptPoly(plaintext)

	for i := 0; i < b.N; i++ {
		pk.AddPoly(ciphertext, ciphertext)
	}
}

func BenchmarkMultConstantPoly(b *testing.B) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	plaintext := pk.NewPolyPlaintext(big.NewFloat(100.1))
	ciphertext := pk.EncryptPoly(plaintext)

	for i := 0; i < b.N; i++ {
		pk.MultConstPoly(ciphertext, big.NewFloat(1.0))
	}
}

func BenchmarkMultPoly(b *testing.B) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	plaintext := pk.NewPolyPlaintext(big.NewFloat(100.1))
	ciphertext := pk.EncryptPoly(plaintext)

	for i := 0; i < b.N; i++ {
		pk.MultPoly(ciphertext, ciphertext)
	}
}

func TestEncodeBalancedPoly(t *testing.T) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	f1 := big.NewFloat(9.123)
	p1 := pk.NewPolyPlaintext(f1)
	actual := p1.PolyEval()
	expected := f1
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestEncodeUnbalancedPoly(t *testing.T) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	f1 := big.NewFloat(9.123)
	p1 := pk.NewUnbalancedPlaintext(f1)
	actual := p1.PolyEval()
	expected := f1
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestEncodeEncryptDecryptPoly(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	pk.SetupDecryption(sk)

	f1 := big.NewFloat(9.123)
	p1 := pk.NewPolyPlaintext(f1)
	c1 := pk.EncryptPoly(p1)
	actual := sk.DecryptPoly(c1, pk).PolyEval()
	expected := f1
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestAddPoly(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	pk.SetupDecryption(sk)

	f1 := big.NewFloat(0.1)
	f2 := big.NewFloat(4.2)
	p1 := pk.NewPolyPlaintext(f1)
	p2 := pk.NewPolyPlaintext(f2)
	c1 := pk.EncryptPoly(p1)
	c2 := pk.EncryptPoly(p2)

	r1 := pk.AddPoly(c1, c2)
	actual := sk.DecryptPoly(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Add(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestAddPolyL2(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	pk.SetupDecryption(sk)

	f1 := big.NewFloat(50.1)
	f2 := big.NewFloat(41.2)
	p1 := pk.NewPolyPlaintext(f1)
	p2 := pk.NewPolyPlaintext(f2)
	c1 := pk.EncryptPoly(p1)
	c2 := pk.EncryptPoly(p2)
	c1 = pk.MakePolyL2(c1)
	c2 = pk.MakePolyL2(c2)

	r1 := pk.AddPoly(c1, c2)
	actual := sk.DecryptPoly(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Add(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestMultConstPoly(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	pk.SetupDecryption(sk)

	f1 := big.NewFloat(9.13)
	f2 := big.NewFloat(4.12)
	p1 := pk.NewPolyPlaintext(f1)
	p2 := pk.NewPolyPlaintext(f2)
	c1 := pk.EncryptPoly(p1)

	r1 := pk.MultConstPoly(c1, f2)
	actual := sk.DecryptPoly(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Mul(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("[L1] Expected: " + expected.String() + " got: " + actual.String())
	}

	c1 = pk.MakePolyL2(c1)
	r1 = pk.MultConstPoly(c1, f2)
	actual = sk.DecryptPoly(r1, pk).PolyEval()
	expected = big.NewFloat(0.0).Mul(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("[L2] Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestMultPoly(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)
	pk.SetupDecryption(sk)

	f1 := big.NewFloat(1.1)
	f2 := big.NewFloat(40.2)
	p1 := pk.NewPolyPlaintext(f1)
	p2 := pk.NewPolyPlaintext(f2)
	c1 := pk.EncryptPoly(p1)
	c2 := pk.EncryptPoly(p2)

	r1 := pk.MultPoly(c1, c2)
	actual := sk.DecryptPoly(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Mul(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}
