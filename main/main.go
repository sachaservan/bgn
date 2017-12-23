package main

import (
	"bgn"
	"fmt"
	"math/big"
)

func main() {
	printWelcome()

	println("\n***Begin Executing Demo****\n")

	keyBits := 35 // length of q1 and q2
	polyBase := 3
	fpPrecision := 2

	runSanityCheck(keyBits, polyBase, fpPrecision)
	// exampleArithmetic(keyBits, polyBase, fpPrecision)
	// exampleMultiParty(5, keyBits, polyBase, fpPrecision)

	examplePearsonsTestSimulation(2, keyBits, polyBase, fpPrecision, true)
	exampleTTestSimulation(2, keyBits, polyBase, fpPrecision, true)

	println("\n***End Executing Demo****\n")
}

func exampleMultiParty(numParties int, keyBits int, polyBase int, fpPrecision int) {

	pk, sk, shares, _ := bgn.NewMPCKeyGen(numParties, keyBits, polyBase, fpPrecision, true)
	blackboxMPC := bgn.NewBlackboxMPC(shares, pk, sk)

	m1 := bgn.NewPlaintext(big.NewFloat(3.0), pk.PolyBase, pk.FPPrecision)
	m2 := bgn.NewPlaintext(big.NewFloat(-3.0), pk.PolyBase, pk.FPPrecision)
	c1 := pk.Encrypt(m1)
	c2 := pk.Encrypt(m2)
	c3 := pk.EAdd(c1, c2)
	c4 := pk.EMult(c1, c2)

	resultInv := blackboxMPC.MPCDecrypt(blackboxMPC.MPCEMInv(blackboxMPC.MPCEncrypt(pk.EMult(c1, c1))))
	fmt.Printf("MPCINV 1/9 = E(%s)\n\n", resultInv.String())

	return

	resultAdd := blackboxMPC.MPCDecrypt(c3)
	resultMult := blackboxMPC.MPCDecrypt(c4)
	c5 := blackboxMPC.MPCEncrypt(c4)
	c5 = pk.EMult(c5, c5)
	c5 = pk.EMultC(c5, big.NewFloat(-1.0))
	resultMult2 := sk.Decrypt(c5, pk)

	c6 := blackboxMPC.MPCEncrypt(c5)
	resultMult3 := sk.Decrypt(c6, pk)

	c7 := blackboxMPC.MPCEMInv(c5)
	resultDiv := sk.Decrypt(c7, pk)

	fmt.Printf("EADD E(%s) ⊞ E(%s) = E(%s)\n\n", m1.String(), m2.String(), resultAdd.String())
	fmt.Printf("EMULT E(%s) ⊠ E(%s) = E(%s)\n\n", m1.String(), m2.String(), resultMult.String())
	fmt.Printf("MPCEMULT E(%s) ⊠ E(%s*(-1)) = E(%s)\n\n", resultMult.String(), resultMult.String(), resultMult2.String())
	fmt.Printf("MPCEMULT E(%s) ⊠ E(%s) = E(%s)\n\n", resultMult2.String(), resultMult2.String(), resultMult3.String())
	fmt.Printf("MPCEMINV 1.0/E(%s) = E(%s)\n\n", resultMult2.String(), resultDiv.String())

}

func exampleArithmetic(keyBits int, polyBase int, fpPrecision int) {

	pk, sk, _ := bgn.NewKeyGen(keyBits, big.NewInt(1021), polyBase, fpPrecision, true)

	m1 := bgn.NewPlaintext(big.NewFloat(11.0), pk.PolyBase, pk.FPPrecision)
	m2 := bgn.NewPlaintext(big.NewFloat(9.0), pk.PolyBase, pk.FPPrecision)
	m3 := bgn.NewPlaintext(big.NewFloat(2.75), pk.PolyBase, pk.FPPrecision)
	m4 := bgn.NewPlaintext(big.NewFloat(32.99), pk.PolyBase, pk.FPPrecision)

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

}

func runSanityCheck(keyBits int, polyBase int, fpPrecision int) {
	pk, sk, _ := bgn.NewKeyGen(keyBits, big.NewInt(1021), polyBase, fpPrecision, true)

	zero := pk.Encrypt(bgn.NewPlaintext(big.NewFloat(0.0), pk.PolyBase, pk.FPPrecision))
	one := pk.Encrypt(bgn.NewPlaintext(big.NewFloat(1.0), pk.PolyBase, pk.FPPrecision))
	negone := pk.Encrypt(bgn.NewPlaintext(big.NewFloat(-1.0), pk.PolyBase, pk.FPPrecision))

	fmt.Println("*****RUNNING SANITY CHECK*******")
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
	fmt.Println("AINV((-1)*(-1)) = " + sk.Decrypt(pk.AInv(pk.EMult(pk.AInv(one), pk.AInv(one))), pk).String())

	fmt.Println("*****DONE WITH SANITY CHECK*******")

}

func printWelcome() {
	fmt.Println("BBBBBBBBBBBBBBBBB           GGGGGGGGGGGGGNNNNNNNN        NNNNNNNN")
	fmt.Println("B::::::::::::::::B       GGG::::::::::::GN:::::::N       N::::::N")
	fmt.Println("B::::::BBBBBB:::::B    GG:::::::::::::::GN::::::::N      N::::::N")
	fmt.Println("BB:::::B     B:::::B  G:::::GGGGGGGG::::GN:::::::::N     N::::::N")
	fmt.Println("  B::::B     B:::::B G:::::G       GGGGGGN::::::::::N    N::::::N")
	fmt.Println("  B::::B     B:::::BG:::::G              N:::::::::::N   N::::::N")
	fmt.Println("  B::::BBBBBB:::::B G:::::G              N:::::::N::::N  N::::::N")
	fmt.Println("  B:::::::::::::BB  G:::::G    GGGGGGGGGGN::::::N N::::N N::::::N")
	fmt.Println("  B::::BBBBBB:::::B G:::::G    G::::::::GN::::::N  N::::N:::::::N")
	fmt.Println("  B::::B     B:::::BG:::::G    GGGGG::::GN::::::N   N:::::::::::N")
	fmt.Println("  B::::B     B:::::BG:::::G        G::::GN::::::N    N::::::::::N")
	fmt.Println("  B::::B     B:::::B G:::::G       G::::GN::::::N     N:::::::::N")
	fmt.Println("BB:::::BBBBBB::::::B  G:::::GGGGGGGG::::GN::::::N      N::::::::N")
	fmt.Println("B:::::::::::::::::B    GG:::::::::::::::GN::::::N       N:::::::N")
	fmt.Println("B::::::::::::::::B       GGG::::::GGG:::GN::::::N        N::::::N")
	fmt.Println("BBBBBBBBBBBBBBBBB           GGGGGG   GGGGNNNNNNNN         NNNNNNN")
	fmt.Println("-----------------------------------------------------------------")
}
