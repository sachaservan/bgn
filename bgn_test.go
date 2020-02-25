package bgn

import (
	"math/big"
	"testing"
)

const KEYBITS = 512
const POLYBASE = 3
const MSGSPACE = 1021 // message space for polynomial coefficients
const FPSCALEBASE = 1021
const FPPREC = 2
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
