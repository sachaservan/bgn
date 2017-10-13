package main

import (
	"bgn"
	"fmt"
	"math"
)

func main() {
	printWelcome()

	println("\n***Begin Executing Demo****\n")

	keyBits := 32 // length of q1 and q2
	polyBase := 3
	fpPrecision := 10

	//	runSanityCheck(keyBits, polyBase, fpPrecision)
	// exampleArithmetic(keyBits, polyBase, fpPrecision)
	//exampleTTestSimulation(10, keyBits, polyBase, fpPrecision)
	exampleMultiParty(10, keyBits, polyBase, fpPrecision)

	println("\n***End Executing Demo****\n")

}

func exampleMultiParty(numParties int, keyBits int, polyBase int, fpPrecision int) {

	pk, sk, shares, _ := bgn.NewMPCKeyGen(numParties, keyBits, polyBase, fpPrecision, true)
	blackboxMPC := bgn.NewBlackboxMPC(shares, pk, sk)

	m1 := bgn.NewPlaintext(10, pk.PolyBase, pk.FPPrecision)
	m2 := bgn.NewPlaintext(-3, pk.PolyBase, pk.FPPrecision)
	c1 := pk.Encrypt(m1)
	c2 := pk.Encrypt(m2)
	c3 := pk.EAdd(c1, c2)
	c4 := pk.EMult(c1, c2)

	resultAdd := blackboxMPC.MPCDecrypt(c3)
	resultMult := blackboxMPC.MPCDecrypt(c4)
	c5 := blackboxMPC.MPCEmult(c4, c4)
	c5 = pk.EMultC(c5, -1.0)
	resultMult2 := sk.Decrypt(c5, pk)

	c6 := blackboxMPC.MPCEmult(c5, c5)
	resultMult3 := sk.Decrypt(c6, pk)

	fmt.Printf("EADD E(%s) ⊞ E(%s) = E(%s)\n\n", m1.String(), m2.String(), resultAdd.String())
	fmt.Printf("EMULT E(%s) ⊠ E(%s) = E(%s)\n\n", m1.String(), m2.String(), resultMult.String())
	fmt.Printf("MPCEMULT E(%s) ⊠ E(%s*(-1)) = E(%s)\n\n", resultMult.String(), resultMult.String(), resultMult2.String())
	fmt.Printf("MPCEMULT E(%s) ⊠ E(%s) = E(%s)\n\n", resultMult2.String(), resultMult2.String(), resultMult3.String())

}

func exampleTTestSimulation(numParties int, keyBits int, polyBase int, fpPrecision int) {

	pk, sk, _ := bgn.NewKeyGen(keyBits, polyBase, fpPrecision, true)

	// START DEALER CODE
	var placebo = []float64{105.0, 119.0, 100.0, 97.0, 96.0, 101.0, 94.0, 95.0, 98.0}
	var placebo2 = []float64{105.0, 119.0, 100.0, 97.0, 96.0, 101.0, 94.0, 95.0, 98.0}

	var caffeine = []float64{96.0, 99.0, 94.0, 89.0, 96.0, 93.0, 88.0, 105.0, 88.0}
	var caffeine2 = []float64{96, 99, 94, 89, 96, 93, 88, 105, 88}

	numRows := len(caffeine)

	for i := 0; i < numRows; i++ {
		placebo2[i] = placebo[i] * placebo[i]
		caffeine2[i] = caffeine[i] * caffeine[i]
	}

	var ePlacebo []*bgn.Ciphertext
	ePlacebo = make([]*bgn.Ciphertext, numRows)
	var eCaffeine []*bgn.Ciphertext
	eCaffeine = make([]*bgn.Ciphertext, numRows)

	// encrypted squared values
	var ePlacebo2 []*bgn.Ciphertext
	ePlacebo2 = make([]*bgn.Ciphertext, numRows)
	var eCaffeine2 []*bgn.Ciphertext
	eCaffeine2 = make([]*bgn.Ciphertext, numRows)

	sumPlaceboActual := 0.0
	sumCaffeineActual := 0.0
	for i := 0; i < numRows; i++ {

		sumPlaceboActual += placebo[i]
		sumCaffeineActual += caffeine[i]

		plaintextPlacebo := bgn.NewPlaintext(placebo[i], polyBase, pk.FPPrecision)
		plaintextCaffeine := bgn.NewPlaintext(caffeine[i], polyBase, pk.FPPrecision)

		plaintextCaffeine2 := bgn.NewPlaintext(caffeine2[i], polyBase, pk.FPPrecision)
		plaintextPlacebo2 := bgn.NewPlaintext(placebo2[i], polyBase, pk.FPPrecision)

		ePlacebo[i] = pk.Encrypt(plaintextPlacebo)
		eCaffeine[i] = pk.Encrypt(plaintextCaffeine)

		ePlacebo2[i] = pk.Encrypt(plaintextPlacebo2)
		eCaffeine2[i] = pk.Encrypt(plaintextCaffeine2)
	}

	// **********************************
	// END DEALER CODE
	// START CLIENT CODE
	// **********************************

	invNumRows := 1.0 / float64(numRows)
	sumPlacebo := ePlacebo[0]
	sumCaffeine := eCaffeine[0]

	// sum of the squares
	sumPlacebo2 := ePlacebo2[0]
	sumCaffeine2 := eCaffeine2[0]

	for i := 1; i < numRows; i++ {
		sumPlacebo = pk.EAdd(sumPlacebo, ePlacebo[i])
		sumCaffeine = pk.EAdd(sumCaffeine, eCaffeine[i])
		sumPlacebo2 = pk.EAdd(sumPlacebo2, ePlacebo2[i])
		sumCaffeine2 = pk.EAdd(sumCaffeine2, eCaffeine2[i])
	}

	meanPlacebo := pk.EMultC(sumPlacebo, invNumRows)
	meanCaffeine := pk.EMultC(sumCaffeine, invNumRows)

	// sanity check
	fmt.Printf("MEAN PLACEBO: %s, sum=%s\n", sk.Decrypt(meanPlacebo, pk).String(), sk.Decrypt(sumPlacebo, pk).String())
	fmt.Printf("MEAN CAFFEINE: %s, sum=%s\n", sk.Decrypt(meanCaffeine, pk).String(), sk.Decrypt(sumCaffeine, pk).String())

	// encryption of 1 to take ciphertext to G2 for  ops
	e1 := pk.Encrypt(bgn.NewPlaintext(1.0, pk.PolyBase, pk.FPPrecision))
	e0 := pk.Encrypt(bgn.NewPlaintext(0.0, pk.PolyBase, pk.FPPrecision))

	ssPlacebo := pk.EMult(e1, e0)
	ssCaffeine := pk.EMult(e1, e0)
	for i := 0; i < numRows; i++ {

		smp := pk.EAdd(ePlacebo[i], pk.AInv(meanPlacebo))
		ssPlacebo = pk.EAdd(ssPlacebo, pk.EMult(smp, smp))

		smc := pk.EAdd(eCaffeine[i], pk.AInv(meanCaffeine))
		ssCaffeine = pk.EAdd(ssCaffeine, pk.EMult(smc, smc))
	}

	fmt.Printf("SS PLACEBO: %s\n", sk.Decrypt(ssPlacebo, pk).PolyEval().String())
	fmt.Printf("SS CAFFEINE: %s\n", sk.Decrypt(ssCaffeine, pk).PolyEval().String())

	ssPlacebo = pk.EMultC(ssPlacebo, invNumRows)
	ssCaffeine = pk.EMultC(ssCaffeine, invNumRows)

	// sanity check
	sdPlaceboFloat, _ := sk.Decrypt(ssPlacebo, pk).PolyEval().Float64()
	sdCaffeineFloat, _ := sk.Decrypt(ssCaffeine, pk).PolyEval().Float64()

	fmt.Printf("SD PLACEBO: %f\n", math.Sqrt(sdPlaceboFloat))
	fmt.Printf("SD CAFFEINE: %f\n", math.Sqrt(sdCaffeineFloat))

	top := pk.EAdd(meanPlacebo, pk.AInv(meanCaffeine))
	top = pk.EMult(top, top)

	ta := pk.EAdd(pk.EMult(e1, sumPlacebo2), pk.AInv(pk.EMultC(pk.EMult(sumPlacebo, sumPlacebo), invNumRows)))
	tb := pk.EAdd(pk.EMult(e1, sumCaffeine2), pk.AInv(pk.EMultC(pk.EMult(sumCaffeine, sumCaffeine), invNumRows)))

	bottom := pk.EAdd(ta, tb)

	fmt.Printf("b1: %s\n", sk.Decrypt(bottom, pk).String())

	bottom = pk.EMultC(bottom, 1.0/(float64(numRows+numRows-2)))
	fmt.Printf("b2: %s\n", sk.Decrypt(bottom, pk).String())

	bottom = pk.EMultC(bottom, 2.0/float64(numRows))

	fmt.Printf("b3: %s, %f\n", sk.Decrypt(bottom, pk).String(), 1.0/(float64(numRows+numRows-2)))

	numerator, _ := sk.Decrypt(top, pk).PolyEval().Float64()
	denominator, _ := sk.Decrypt(bottom, pk).PolyEval().Float64()
	// sanity check
	fmt.Printf("numerator: %f, denominator: %f\n", numerator, denominator)

	tstatistic := math.Sqrt(numerator / math.Abs(denominator))

	fmt.Printf("T statistic %f\n", tstatistic)
}

func exampleArithmetic(keyBits int, polyBase int, fpPrecision int) {

	pk, sk, _ := bgn.NewKeyGen(keyBits, polyBase, fpPrecision, true)

	m1 := bgn.NewPlaintext(1, pk.PolyBase, pk.FPPrecision)
	m2 := bgn.NewPlaintext(10, pk.PolyBase, pk.FPPrecision)
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

	const1 := 8863.0
	r2 := pk.EMultC(pk.EMult(c2, c1), const1)
	fmt.Printf("EMULTC E(%s) ⊠ %f = E(%s)\n\n", m2, const1, sk.Decrypt(r2, pk).String())

	r3 := pk.EMult(c3, c4)
	dr3 := sk.Decrypt(r3, pk)
	fmt.Printf("EMULT E(%s) ⊠ E(%s) = E(%s)\n\n", m3, m4, sk.Decrypt(r3, pk).String())

	const2 := -3.5
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
