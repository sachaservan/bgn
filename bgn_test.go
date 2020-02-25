package bgn

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

const KEYBITS = 512
const POLYBASE = 3
const MSGSPACE = 1021 // message space for polynomial coefficients
const FPSCALEBASE = 3
const FPPREC = 0.0001
const DET = true // deterministic ops

func BenchmarkDecrypt(b *testing.B) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)

	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)

	zero := pk.Encrypt(pk.NewPlaintext(big.NewFloat(0.0)))

	for i := 0; i < b.N; i++ {
		sk.Decrypt(zero, pk)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	plaintext := pk.NewPlaintext(big.NewFloat(100.1))
	for i := 0; i < b.N; i++ {
		pk.Encrypt(plaintext)
	}
}

func BenchmarkAdd(b *testing.B) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	plaintext := pk.NewPlaintext(big.NewFloat(100.1))
	ciphertext := pk.Encrypt(plaintext)

	for i := 0; i < b.N; i++ {
		pk.EAdd(ciphertext, ciphertext)
	}
}

func BenchmarkMultConstant(b *testing.B) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	plaintext := pk.NewPlaintext(big.NewFloat(100.1))
	ciphertext := pk.Encrypt(plaintext)

	for i := 0; i < b.N; i++ {
		pk.EMultC(ciphertext, big.NewFloat(1.0))
	}
}

func BenchmarkMult(b *testing.B) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	plaintext := pk.NewPlaintext(big.NewFloat(100.1))
	ciphertext := pk.Encrypt(plaintext)

	for i := 0; i < b.N; i++ {
		pk.EMult(ciphertext, ciphertext)
	}
}

func TestEncodeBalancedPoly(t *testing.T) {
	pk, _, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	f1 := big.NewFloat(9.123)
	p1 := pk.NewPlaintext(f1)
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

func TestEncodeEncryptDecrypt(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)
	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)

	f1 := big.NewFloat(9.123)
	p1 := pk.NewPlaintext(f1)
	c1 := pk.Encrypt(p1)
	actual := sk.Decrypt(c1, pk).PolyEval()
	expected := f1
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestAdd(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)
	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)

	f1 := big.NewFloat(0.1)
	f2 := big.NewFloat(4.2)
	p1 := pk.NewPlaintext(f1)
	p2 := pk.NewPlaintext(f2)
	c1 := pk.Encrypt(p1)
	c2 := pk.Encrypt(p2)

	r1 := pk.EAdd(c1, c2)
	actual := sk.Decrypt(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Add(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestAddL2(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)
	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)

	f1 := big.NewFloat(50.1)
	f2 := big.NewFloat(41.2)
	p1 := pk.NewPlaintext(f1)
	p2 := pk.NewPlaintext(f2)
	c1 := pk.Encrypt(p1)
	c2 := pk.Encrypt(p2)
	c1 = pk.MakeL2(c1)
	c2 = pk.MakeL2(c2)

	r1 := pk.EAdd(c1, c2)
	actual := sk.Decrypt(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Add(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestAInverse(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)
	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)

	f1 := big.NewFloat(100.1)
	f2 := big.NewFloat(4.212)
	p1 := pk.NewPlaintext(f1)
	p2 := pk.NewPlaintext(f2)
	c1 := pk.Encrypt(p1)
	c2 := pk.Encrypt(p2)
	c2 = pk.AInv(c2)

	r1 := pk.EAdd(c1, c2)
	actual := sk.Decrypt(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Sub(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestAInverseL2(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)
	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)

	f1 := big.NewFloat(100.1)
	f2 := big.NewFloat(42.22)
	p1 := pk.NewPlaintext(f1)
	p2 := pk.NewPlaintext(f2)
	c1 := pk.Encrypt(p1)
	c2 := pk.Encrypt(p2)
	c1 = pk.MakeL2(c1)
	c2 = pk.MakeL2(c2)
	c2 = pk.AInv(c2)

	r1 := pk.EAdd(c1, c2)
	actual := sk.Decrypt(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Sub(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestMultC(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)
	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)

	f1 := big.NewFloat(9.13)
	f2 := big.NewFloat(4.12)
	p1 := pk.NewPlaintext(f1)
	p2 := pk.NewPlaintext(f2)
	c1 := pk.Encrypt(p1)

	r1 := pk.EMultC(c1, f2)
	actual := sk.Decrypt(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Mul(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestMultCL2(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)
	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)

	f1 := big.NewFloat(10.21)
	f2 := big.NewFloat(12.21)
	p1 := pk.NewPlaintext(f1)
	p2 := pk.NewPlaintext(f2)
	c1 := pk.Encrypt(p1)
	c1 = pk.MakeL2(c1)

	r1 := pk.EMultC(c1, f2)
	actual := sk.Decrypt(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Mul(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}

func TestMult(t *testing.T) {
	pk, sk, _ := NewKeyGen(KEYBITS, big.NewInt(MSGSPACE), POLYBASE, FPSCALEBASE, FPPREC, DET)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)
	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)

	f1 := big.NewFloat(100.1)
	f2 := big.NewFloat(41.2)
	p1 := pk.NewPlaintext(f1)
	p2 := pk.NewPlaintext(f2)
	c1 := pk.Encrypt(p1)
	c2 := pk.Encrypt(p2)

	r1 := pk.EMult(c1, c2)
	actual := sk.Decrypt(r1, pk).PolyEval()
	expected := big.NewFloat(0.0).Mul(p1.PolyEval(), p2.PolyEval())
	if !reflect.DeepEqual(fmt.Sprintf("%.1f\n", expected), fmt.Sprintf("%.1f\n", actual)) {
		t.Error("Expected: " + expected.String() + " got: " + actual.String())
	}
}
