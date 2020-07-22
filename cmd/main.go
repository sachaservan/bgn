package main

import (
	"fmt"
	"math/big"

	"github.com/sachaservan/bgn"
)

func main() {

	printWelcome()

	keyBits := 512 // length of q1 and q2
	messageSpace := big.NewInt(1021)
	polyBase := 3 // base for the ciphertext polynomial
	fpScaleBase := 3
	fpPrecision := 0.0001

	runSimpleCheck(keyBits, polyBase)
	runPolyArithmeticCheck(keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision)
}

func runPolyArithmeticCheck(keyBits int, messageSpace *big.Int, polyBase int, fpScaleBase int, fpPrecision float64) {

	pk, sk, _ := bgn.NewKeyGen(keyBits, messageSpace, polyBase, fpScaleBase, fpPrecision, true)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)

	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)

	m1 := pk.NewPolyPlaintext(big.NewFloat(0.0111))
	m2 := pk.NewPolyPlaintext(big.NewFloat(9.1))
	m3 := pk.NewPolyPlaintext(big.NewFloat(2.75))
	m4 := pk.NewPolyPlaintext(big.NewFloat(2.99))

	c1 := pk.EncryptPoly(m1)
	c2 := pk.EncryptPoly(m2)
	c3 := pk.EncryptPoly(m3)
	c4 := pk.EncryptPoly(m4)
	c6 := pk.NegPoly(c4)

	print("\n----------RUNNING ARITHMETIC TEST----------\n\n")

	fmt.Printf("c1 = E(%s)\n", sk.DecryptPoly(c1, pk).String())
	fmt.Printf("c2 = E(%s)\n", sk.DecryptPoly(c2, pk).String())
	fmt.Printf("c3 = E(%s)\n", sk.DecryptPoly(c3, pk).String())
	fmt.Printf("c4 = E(%s)\n", sk.DecryptPoly(c4, pk).String())
	fmt.Println()

	r1 := pk.AddPoly(c1, c4)
	fmt.Printf("[Add] E(%s) ⊞ E(%s) = E(%s)\n\n", m1, m4, sk.DecryptPoly(r1, pk).String())

	const1 := big.NewFloat(10.0)
	r2 := pk.MultConstPoly(c2, const1)
	fmt.Printf("[MultConst] E(%s) ⊠ %f = E(%s)\n\n", m2, const1, sk.DecryptPoly(r2, pk).String())

	r3 := pk.MultPoly(c3, c4)
	dr3 := sk.DecryptPoly(r3, pk)
	fmt.Printf("[Mult] E(%s) ⊠ E(%s) = E(%s)\n\n", m3, m4, sk.DecryptPoly(r3, pk).String())

	const2 := big.NewFloat(0.5)
	r4 := pk.MultConstPoly(r3, const2)
	dr4 := sk.DecryptPoly(r4, pk)
	fmt.Printf("[MultConst] E(%s) ⊠ %f = E(%s)\n\n", dr3.String(), const2, dr4.String())

	r5 := pk.AddPoly(r3, r3)
	fmt.Printf("[Add] E(%s) ⊞ E(%s) = E(%s)\n\n", dr3.String(), dr3.String(), sk.DecryptPoly(r5, pk).String())

	r6 := pk.AddPoly(c1, c6)
	fmt.Printf("[Add] E(%s) ⊞ Neg(E(%s)) = E(%s)\n\n", m1, m4, sk.DecryptPoly(r6, pk).String())

	fmt.Println("\n----------DONE----------")

}

func runSimpleCheck(keyBits int, polyBase int) {

	pk, sk, _ := bgn.NewKeyGen(keyBits, big.NewInt(1021), polyBase, 3, 2, true)

	genG1 := pk.P.NewFieldElement()
	genG1.PowBig(pk.P, sk.Key)

	genGT := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	genGT.PowBig(genGT, sk.Key)
	pk.PrecomputeTables(genG1, genGT)

	zero := pk.Encrypt(big.NewInt(0))
	one := pk.Encrypt(big.NewInt(1))
	negone := pk.Encrypt(big.NewInt(-1.0))

	fmt.Print("\n---------RUNNING BASIC CHECK----------\n\n")
	fmt.Println("0 + 0 = " + sk.DecryptFailSafe(pk.Add(zero, zero), pk).String())
	fmt.Println("0 + 1 = " + sk.DecryptFailSafe(pk.Add(zero, one), pk).String())
	fmt.Println("1 + 1 = " + sk.DecryptFailSafe(pk.Add(one, one), pk).String())
	fmt.Println("1 + 0 = " + sk.DecryptFailSafe(pk.Add(one, zero), pk).String())

	fmt.Println("0 * 0 = " + sk.DecryptFailSafe(pk.Mult(zero, zero), pk).String())
	fmt.Println("0 * 1 = " + sk.DecryptFailSafe(pk.Mult(zero, one), pk).String())
	fmt.Println("1 * 0 = " + sk.DecryptFailSafe(pk.Mult(one, zero), pk).String())
	fmt.Println("1 * 1 = " + sk.DecryptFailSafe(pk.Mult(one, one), pk).String())

	fmt.Println("0 - 0 = " + sk.DecryptFailSafe(pk.Add(zero, pk.Neg(zero)), pk).String())
	fmt.Println("0 - 1 = " + sk.DecryptFailSafe(pk.Add(zero, pk.Neg(one)), pk).String())
	fmt.Println("0 + (-1) = " + sk.DecryptFailSafe(pk.Add(zero, negone), pk).String())
	fmt.Println("1 - 1 = " + sk.DecryptFailSafe(pk.Add(one, pk.Neg(one)), pk).String())
	fmt.Println("1 - 0 = " + sk.DecryptFailSafe(pk.Add(one, pk.Neg(zero)), pk).String())

	fmt.Println("0 * (-0) = " + sk.DecryptFailSafe(pk.Mult(zero, pk.Neg(zero)), pk).String())
	fmt.Println("0 * (-1) = " + sk.DecryptFailSafe(pk.Mult(zero, pk.Neg(one)), pk).String())
	fmt.Println("1 * (-0) = " + sk.DecryptFailSafe(pk.Mult(one, pk.Neg(zero)), pk).String())
	fmt.Println("1 * (-1) = " + sk.DecryptFailSafe(pk.Mult(one, pk.Neg(one)), pk).String())
	fmt.Println("(-1) * (-1) = " + sk.DecryptFailSafe(pk.Mult(pk.Neg(one), pk.Neg(one)), pk).String())
	fmt.Println("\n---------DONE----------")

}

func printWelcome() {
	fmt.Println("====================================")
	fmt.Println(" ____   _____ _   _ ")
	fmt.Println("|  _ \\ / ____| \\ | |")
	fmt.Println("| |_) | |  __|  \\| |")
	fmt.Println("|  _ <| | |_ | . ` |")
	fmt.Println("| |_) | |__| | |\\  |")
	fmt.Println("|____/ \\_____|_| \\_|")

	fmt.Println("Boneh Goh Nissim Cryptosystem in Go")
	fmt.Println("====================================")

}
