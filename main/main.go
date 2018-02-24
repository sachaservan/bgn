package main

import (
	"bgn"
	"fmt"
	"math/big"
)

func main() {
	printWelcome()

	keyBits := 512 // length of q1 and q2
	polyBase := 3  // base for the ciphertext polynomial

	runSanityCheck(keyBits, polyBase)
	runArithmeticCheck(keyBits, polyBase)
}

func runArithmeticCheck(keyBits int, polyBase int) {

	println("\n----------RUNNING ARITHMETIC TEST----------\n")

	pk, sk, _ := bgn.NewKeyGen(keyBits, big.NewInt(1021), polyBase, true)

	m1 := bgn.NewPlaintext(big.NewFloat(11.0), pk.PolyBase)
	m2 := bgn.NewPlaintext(big.NewFloat(9.0), pk.PolyBase)
	m3 := bgn.NewPlaintext(big.NewFloat(2.75), pk.PolyBase)
	m4 := bgn.NewPlaintext(big.NewFloat(32.99), pk.PolyBase)

	c1 := pk.Encrypt(m1)
	c2 := pk.Encrypt(m2)
	c3 := pk.Encrypt(m3)
	c4 := pk.Encrypt(m4)
	c6 := pk.AInv(c4)

	r1 := pk.EAdd(c1, c2)
	fmt.Printf("EADD E(%s) ⊞ E(%s) = E(%s)\n\n", m1, m2, sk.Decrypt(r1, pk).String())

	const1 := big.NewFloat(88.0)
	r2 := pk.EMultC(c2, const1)
	fmt.Printf("EMULTC E(%s) ⊠ %f = E(%s)\n\n", m2, const1, sk.Decrypt(r2, pk).String())

	r3 := pk.EMult(c3, c4)
	dr3 := sk.Decrypt(r3, pk)
	fmt.Printf("EMULT E(%s) ⊠ E(%s) = E(%s)\n\n", m3, m4, sk.Decrypt(r3, pk).String())

	const2 := big.NewFloat(0.5)
	r4 := pk.EMultC(r3, const2)
	dr4 := sk.Decrypt(r4, pk)
	fmt.Printf("EMULTC E(%s) ⊠ %f = E(%s)\n\n", dr3.String(), const2, dr4.String())

	r5 := pk.EAdd(r3, r3)
	fmt.Printf("EADD E(%s) ⊞ E(%s) = E(%s)\n\n", dr3.String(), dr3.String(), sk.Decrypt(r5, pk).String())

	r6 := pk.EAdd(c1, c6)
	fmt.Printf("EADD E(%s) ⊞ AINV(E(%s)) = E(%s)\n\n", m1, m4, sk.Decrypt(r6, pk).String())

	fmt.Println("\n----------DONE----------")

}

func runSanityCheck(keyBits int, polyBase int) {

	pk, sk, _ := bgn.NewKeyGen(keyBits, big.NewInt(1048609), polyBase, true)

	zero := pk.Encrypt(bgn.NewPlaintext(big.NewFloat(0.0), pk.PolyBase))
	one := pk.Encrypt(bgn.NewPlaintext(big.NewFloat(1.0), pk.PolyBase))
	negone := pk.Encrypt(bgn.NewPlaintext(big.NewFloat(-1.0), pk.PolyBase))

	fmt.Println("\n---------RUNNING SANITY CHECK----------")
	fmt.Println("0+0 = " + sk.Decrypt(pk.EAdd(zero, zero), pk).String())
	fmt.Println("0+1 = " + sk.Decrypt(pk.EAdd(zero, one), pk).String())
	fmt.Println("1+1 = " + sk.Decrypt(pk.EAdd(one, one), pk).String())
	fmt.Println("1+0 = " + sk.Decrypt(pk.EAdd(one, zero), pk).String())

	fmt.Println("0*0 = " + sk.Decrypt(pk.EMult(zero, zero), pk).String())
	fmt.Println("0*1 = " + sk.Decrypt(pk.EMult(zero, one), pk).String())
	fmt.Println("1*0 = " + sk.Decrypt(pk.EMult(one, zero), pk).String())
	fmt.Println("1*1 = " + sk.Decrypt(pk.EMult(one, one), pk).String())

	fmt.Println("0-0 = " + sk.Decrypt(pk.EAdd(zero, pk.AInv(zero)), pk).String())
	fmt.Println("0-1 = " + sk.Decrypt(pk.EAdd(zero, pk.AInv(one)), pk).String())
	fmt.Println("0 + (-1) = " + sk.Decrypt(pk.EAdd(zero, negone), pk).String())
	fmt.Println("1-1 = " + sk.Decrypt(pk.EAdd(one, pk.AInv(one)), pk).String())
	fmt.Println("1-0 = " + sk.Decrypt(pk.EAdd(one, pk.AInv(zero)), pk).String())

	fmt.Println("0*(-0) = " + sk.Decrypt(pk.EMult(zero, pk.AInv(zero)), pk).String())
	fmt.Println("0*(-1) = " + sk.Decrypt(pk.EMult(zero, pk.AInv(one)), pk).String())
	fmt.Println("1*-(0) = " + sk.Decrypt(pk.EMult(one, pk.AInv(zero)), pk).String())
	fmt.Println("1*-(1) = " + sk.Decrypt(pk.EMult(one, pk.AInv(one)), pk).String())
	fmt.Println("(-1)*-(1) = " + sk.Decrypt(pk.EMult(pk.AInv(one), pk.AInv(one)), pk).String())

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

	fmt.Println("Boneh Nissim Goh Cryptosystem in Go")
	fmt.Println("====================================")

}
