package main

import (
	"bgn"
	"fmt"
)

func main() {
	printWelcome()

	println("\n***Begin Executing Demo****\n")

	keyBits := 32 // length of q1 and q2
	polyBase := 3
	fpPrecision := 15

	// runSanityCheck(keyBits, polyBase, fpPrecision)
	// exampleArithmetic(keyBits, polyBase, fpPrecision)
	// examplePearsonsTestSimulation(2, keyBits, polyBase, fpPrecision, true)
	exampleTTestSimulation(10, keyBits, polyBase, fpPrecision, true)
	//exampleMultiParty(10, keyBits, polyBase, fpPrecision)

	println("\n***End Executing Demo****\n")
}

func exampleMultiParty(numParties int, keyBits int, polyBase int, fpPrecision int) {

	pk, sk, shares, _ := bgn.NewMPCKeyGen(numParties, keyBits, polyBase, fpPrecision, true)
	blackboxMPC := bgn.NewBlackboxMPC(shares, pk, sk)

	m1 := bgn.NewPlaintext(3, pk.PolyBase, pk.FPPrecision)
	m2 := bgn.NewPlaintext(-3, pk.PolyBase, pk.FPPrecision)
	c1 := pk.Encrypt(m1)
	c2 := pk.Encrypt(m2)
	c3 := pk.EAdd(c1, c2)
	c4 := pk.EMult(c1, c2)

	blackboxMPC.MPCEMInv(c1)

	resultAdd := blackboxMPC.MPCDecrypt(c3)
	resultMult := blackboxMPC.MPCDecrypt(c4)
	c5 := blackboxMPC.MPCEmult(c4, c4)
	c5 = pk.EMultC(c5, -1.0)
	resultMult2 := sk.Decrypt(c5, pk)

	c6 := blackboxMPC.MPCEmult(c5, c5)
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

	pk, sk, _ := bgn.NewKeyGen(keyBits, polyBase, fpPrecision, true)

	m1 := bgn.NewPlaintext(11, pk.PolyBase, pk.FPPrecision)
	m2 := bgn.NewPlaintext(9, pk.PolyBase, pk.FPPrecision)
	m3 := bgn.NewPlaintext(2.75, pk.PolyBase, pk.FPPrecision)
	m4 := bgn.NewPlaintext(32.99, pk.PolyBase, pk.FPPrecision)
	m5 := bgn.NewPlaintext(-6.99, pk.PolyBase, pk.FPPrecision)

	c1 := pk.Encrypt(m1)
	c2 := pk.Encrypt(m2)
	c3 := pk.Encrypt(m3)
	c4 := pk.Encrypt(m4)
	c5 := pk.Encrypt(m5)
	c6 := pk.AInv(c4)

	r1 := pk.EAdd(c1, c2)
	fmt.Printf("EADD E(%s) ⊞ E(%s) = E(%s)\n\n", m1, m2, sk.Decrypt(r1, pk).String())

	const1 := 88.0
	r2 := pk.EMultC(c2, const1)
	fmt.Printf("EMULTC E(%s) ⊠ %f = E(%s)\n\n", m2, const1, sk.Decrypt(r2, pk).String())

	r3 := pk.EMult(c3, c4)
	dr3 := sk.Decrypt(r3, pk)
	fmt.Printf("EMULT E(%s) ⊠ E(%s) = E(%s)\n\n", m3, m4, sk.Decrypt(r3, pk).String())

	const2 := 0.5
	r4 := pk.EMultC(r3, const2)
	dr4 := sk.Decrypt(r4, pk)
	fmt.Printf("EMULTC E(%s) ⊠ %f = E(%s)\n\n", dr3.String(), const2, dr4.String())

	r5 := pk.EAdd(r3, r3)
	fmt.Printf("EADD E(%s) ⊞ E(%s) = E(%s)\n\n", dr3.String(), dr3.String(), sk.Decrypt(r5, pk).String())

	r6 := pk.EAdd(c1, c6)
	fmt.Printf("EADD E(%s) ⊞ AINV(E(%s)) = E(%s)\n\n", m1, m4, sk.Decrypt(r6, pk).String())

	r7 := pk.AInv(pk.EMult(c5, c5))
	dr7 := sk.Decrypt(r7, pk)
	mpcMultRes := runMPCEMultSimulation(pk, sk, r7, r3)
	fmt.Printf("MPCEMULT E(%s) ⊠ E(%s) = E(%s)\n\n", dr7.String(), dr3.String(), sk.Decrypt(mpcMultRes, pk).String())

}

func runMPCEMultSimulation(pk *bgn.PublicKey, sk *bgn.SecretKey, ct1 *bgn.Ciphertext, ct2 *bgn.Ciphertext) *bgn.Ciphertext {

	var result *bgn.MPCEMultReceptacle

	// simulate 10 parties
	for i := 0; i < 10; i++ {
		req := bgn.NewMPCEmultRequest(ct2)
		res := pk.RequestMPCMultiplication(req)

		if result == nil {
			result = &bgn.MPCEMultReceptacle{TermA: res.PartialTermA, TermBA: res.PartialTermBA}
		} else {
			result.TermA = pk.EAdd(result.TermA, res.PartialTermA)
			result.TermBA = pk.EAdd(result.TermBA, res.PartialTermBA)
		}
	}

	partial := pk.EAdd(ct1, pk.AInv(result.TermA))
	term1 := sk.Decrypt(partial, pk)
	fmt.Println("MPC decryption of (ct1-a) = " + term1.String())

	term1Float, _ := term1.PolyEval().Float64()
	fmt.Printf("[DEBUG] Random BigFloat is %s float64 is %f\n", term1.PolyEval().String(), term1Float)
	if term1Float < 0 {
		term1Float *= -1.0
		return pk.AInv(pk.EAdd(pk.EMultC(ct2, term1Float), pk.AInv(result.TermBA)))
	}

	return pk.EAdd(pk.EMultC(ct2, term1Float), result.TermBA)
}

func runSanityCheck(keyBits int, polyBase int, fpPrecision int) {
	pk, sk, _ := bgn.NewKeyGen(keyBits, polyBase, fpPrecision, true)

	zero := pk.Encrypt(bgn.NewPlaintext(0, pk.PolyBase, pk.FPPrecision))
	one := pk.Encrypt(bgn.NewPlaintext(1, pk.PolyBase, pk.FPPrecision))
	negone := pk.Encrypt(bgn.NewPlaintext(-1, pk.PolyBase, pk.FPPrecision))

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
