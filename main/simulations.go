package main

import (
	"bgn"
	"fmt"
	"log"
	"math"
	"time"
)

func examplePearsonsTestSimulation(numParties int, keyBits int, polyBase int, fpPrecision int, debug bool) {

	pk, sk, shares, _ := bgn.NewMPCKeyGen(numParties, keyBits, polyBase, fpPrecision, true)
	blackboxMPC := bgn.NewBlackboxMPC(shares, pk, sk)

	// Start dealer code
	//**************************************************************************************
	var placebo = []float64{56, 56, 65, 65, 50, 25, 87, 44, 35}
	var caffeine = []float64{87, 91, 85, 91, 75, 28, 122, 66, 58}

	numRows := len(caffeine)

	var ePlacebo []*bgn.Ciphertext
	ePlacebo = make([]*bgn.Ciphertext, numRows)
	var eCaffeine []*bgn.Ciphertext
	eCaffeine = make([]*bgn.Ciphertext, numRows)

	sumPlaceboActual := 0.0
	sumCaffeineActual := 0.0
	for i := 0; i < numRows; i++ {

		sumPlaceboActual += placebo[i]
		sumCaffeineActual += caffeine[i]

		plaintextPlacebo := bgn.NewPlaintext(placebo[i], polyBase, pk.FPPrecision)
		plaintextCaffeine := bgn.NewPlaintext(caffeine[i], polyBase, pk.FPPrecision)

		ePlacebo[i] = pk.Encrypt(plaintextPlacebo)
		eCaffeine[i] = pk.Encrypt(plaintextCaffeine)
	}

	//**************************************************************************************
	// End dealer code

	startTime := time.Now()

	invNumRows := 1.0 / float64(numRows)

	// an encryption of zero
	e0 := pk.Encrypt(bgn.NewPlaintext(0.0, pk.PolyBase, pk.FPPrecision))

	// sum of the squares
	sumPlacebo := e0
	sumCaffeine := e0

	for i := 0; i < numRows; i++ {
		sumPlacebo = pk.EAdd(sumPlacebo, ePlacebo[i])
		sumCaffeine = pk.EAdd(sumCaffeine, eCaffeine[i])
	}

	meanPlacebo := pk.EMultC(sumPlacebo, invNumRows)
	meanCaffeine := pk.EMultC(sumCaffeine, invNumRows)

	if debug {
		// sanity check
		fmt.Printf("MEAN PLACEBO: %s, sum=%s\n", sk.Decrypt(meanPlacebo, pk).String(), sk.Decrypt(sumPlacebo, pk).String())
		fmt.Printf("MEAN CAFFEINE: %s, sum=%s\n", sk.Decrypt(meanCaffeine, pk).String(), sk.Decrypt(sumCaffeine, pk).String())
	}

	ssPlacebo := e0
	ssCaffeine := e0
	covariance := e0
	for i := 0; i < numRows; i++ {

		// TODO: pre-compute inv_mean?
		smp := pk.EAdd(ePlacebo[i], pk.AInv(meanPlacebo))
		ssPlacebo = pk.EAdd(ssPlacebo, pk.EMult(smp, smp))

		smc := pk.EAdd(eCaffeine[i], pk.AInv(meanCaffeine))
		ssCaffeine = pk.EAdd(ssCaffeine, pk.EMult(smc, smc))

		covariance = pk.EAdd(covariance, pk.EMult(smp, smc))

	}

	variancePlacebo := blackboxMPC.MPCEmult(ssPlacebo, ssPlacebo)
	varianceCaffeine := blackboxMPC.MPCEmult(ssCaffeine, ssCaffeine)

	if debug {
		// begin sanity check
		fmt.Printf("VARIANCE PLACEBO: %s\n", sk.Decrypt(variancePlacebo, pk).String())
		fmt.Printf("VARIANCE CAFFEINE: %s\n", sk.Decrypt(varianceCaffeine, pk).String())
	}

	covariance = pk.EMultC(covariance, 1.0/(float64(numRows+numRows)))

	if debug {
		// begin sanity check
		fmt.Printf("COVARIANCE: %s\n", sk.Decrypt(covariance, pk).String())
	}

	numerator := blackboxMPC.MPCEmult(covariance, covariance)
	denom := blackboxMPC.MPCEmult(variancePlacebo, varianceCaffeine)

	//r2 := blackboxMPC.MPCEmult(numerator, blackboxMPC.MPCEMInv(denom))

	fmt.Println("Denominator: " + sk.Decrypt(denom, pk).String())
	fmt.Println("Numerator: " + sk.Decrypt(numerator, pk).String())

	res, _ := sk.Decrypt(numerator, pk).PolyEval().Float64()
	resd, _ := sk.Decrypt(denom, pk).PolyEval().Float64()

	r := math.Sqrt(res / resd)

	fmt.Printf("r %f\n", r)

	endTime := time.Now()
	log.Println("runtime: " + endTime.Sub(startTime).String())

}

func exampleTTestSimulation(numParties int, keyBits int, polyBase int, fpPrecision int, debug bool) {

	pk, sk, shares, _ := bgn.NewMPCKeyGen(numParties, keyBits, polyBase, fpPrecision, true)
	blackboxMPC := bgn.NewBlackboxMPC(shares, pk, sk)

	// Start dealer code
	//**************************************************************************************
	var placebo = []float64{105.0, 119.0, 100.0, 97.0, 96.0, 101.0, 94.0, 95.0, 98.0}
	var caffeine = []float64{96.0, 99.0, 94.0, 89.0, 96.0, 93.0, 88.0, 105.0, 88.0}

	numRows := len(caffeine)

	var ePlacebo []*bgn.Ciphertext
	ePlacebo = make([]*bgn.Ciphertext, numRows)
	var eCaffeine []*bgn.Ciphertext
	eCaffeine = make([]*bgn.Ciphertext, numRows)

	sumPlaceboActual := 0.0
	sumCaffeineActual := 0.0
	for i := 0; i < numRows; i++ {

		sumPlaceboActual += placebo[i]
		sumCaffeineActual += caffeine[i]

		plaintextPlacebo := bgn.NewPlaintext(placebo[i], polyBase, pk.FPPrecision)
		plaintextCaffeine := bgn.NewPlaintext(caffeine[i], polyBase, pk.FPPrecision)

		ePlacebo[i] = pk.Encrypt(plaintextPlacebo)
		eCaffeine[i] = pk.Encrypt(plaintextCaffeine)
	}

	//**************************************************************************************
	// End dealer code

	startTime := time.Now()

	invNumRows := 1.0 / float64(numRows)

	// an encryption of zero
	e0 := pk.Encrypt(bgn.NewPlaintext(0.0, pk.PolyBase, pk.FPPrecision))

	// sum of the squares
	sumPlacebo2 := e0
	sumCaffeine2 := e0
	sumPlacebo := e0
	sumCaffeine := e0

	for i := 0; i < numRows; i++ {
		sumPlacebo = pk.EAdd(sumPlacebo, ePlacebo[i])
		sumCaffeine = pk.EAdd(sumCaffeine, eCaffeine[i])

		placebo2 := pk.EMult(ePlacebo[i], ePlacebo[i])
		sumPlacebo2 = pk.EAdd(sumPlacebo2, placebo2)

		caffeine2 := pk.EMult(eCaffeine[i], eCaffeine[i])
		sumCaffeine2 = pk.EAdd(sumCaffeine2, caffeine2)
	}

	meanPlacebo := pk.EMultC(sumPlacebo, invNumRows)
	meanCaffeine := pk.EMultC(sumCaffeine, invNumRows)

	if debug {
		// sanity check
		fmt.Printf("[DEBUG] MEAN PLACEBO: %s\n", sk.Decrypt(meanPlacebo, pk).String())
		fmt.Printf("[DEBUG] MEAN CAFFEINE: %s\n", sk.Decrypt(meanCaffeine, pk).String())
	}

	ssPlacebo := e0
	ssCaffeine := e0
	for i := 0; i < numRows; i++ {

		smp := pk.EAdd(ePlacebo[i], pk.AInv(meanPlacebo))
		ssPlacebo = pk.EAdd(ssPlacebo, pk.EMult(smp, smp))

		smc := pk.EAdd(eCaffeine[i], pk.AInv(meanCaffeine))
		ssCaffeine = pk.EAdd(ssCaffeine, pk.EMult(smc, smc))
	}

	if debug {
		// begin sanity check
		fmt.Printf("[DEBUG] VARIANCE PLACEBO: %s\n", sk.Decrypt(ssPlacebo, pk).PolyEval().String())
		fmt.Printf("[DEBUG] VARIANCE CAFFEINE: %s\n", sk.Decrypt(ssCaffeine, pk).PolyEval().String())
	}

	ssPlacebo = pk.EMultC(ssPlacebo, invNumRows)
	ssCaffeine = pk.EMultC(ssCaffeine, invNumRows)

	if debug {
		// begin sanity check
		sdPlaceboFloat, _ := sk.Decrypt(ssPlacebo, pk).PolyEval().Float64()
		sdCaffeineFloat, _ := sk.Decrypt(ssCaffeine, pk).PolyEval().Float64()
		fmt.Printf("[DEBUG] SD PLACEBO: %f\n", math.Sqrt(sdPlaceboFloat))
		fmt.Printf("[DEBUG] SD CAFFEINE: %f\n", math.Sqrt(sdCaffeineFloat))
	}

	top := pk.EAdd(meanPlacebo, pk.AInv(meanCaffeine))
	top = pk.EMult(top, top)

	ta := pk.EAdd(sumPlacebo2, pk.AInv(pk.EMultC(pk.EMult(sumPlacebo, sumPlacebo), invNumRows)))
	tb := pk.EAdd(sumCaffeine2, pk.AInv(pk.EMultC(pk.EMult(sumCaffeine, sumCaffeine), invNumRows)))

	bottom := pk.EAdd(ta, tb)

	if debug {
		// begin sanity check
		fmt.Printf("[DEBUG] t1: %s\n", sk.Decrypt(bottom, pk).String())
	}

	bottom = pk.EMultC(bottom, 1.0/(float64(numRows+numRows-2)))

	if debug {
		// begin sanity check
		fmt.Printf("[DEBUG] t2: %s\n", sk.Decrypt(bottom, pk).String())
	}

	bottom = pk.EMultC(bottom, 2.0/float64(numRows))

	if debug {
		// begin sanity check
		fmt.Printf("[DEBUG] t3: %s, %f\n", sk.Decrypt(bottom, pk).String(), 1.0/(float64(numRows+numRows-2)))
	}

	res := blackboxMPC.MPCEmult(top, blackboxMPC.MPCEMInv(bottom))
	tstat2, _ := blackboxMPC.MPCDecrypt(res).PolyEval().Float64()
	tstatistic := math.Sqrt(tstat2)

	fmt.Printf("T statistic %f\n", tstatistic)

	endTime := time.Now()
	log.Println("runtime: " + endTime.Sub(startTime).String())

}
