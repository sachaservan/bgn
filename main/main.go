package main

import (
	"bgn"
	"fmt"
	"math/big"
)

func main() {
	printWelcome()

	println("\n***Begin Executing Demo****")

	fmt.Println(big.NewRat(0, 1).SetFloat64(0.0112).FloatString(8))

	keyBits := 16 // length of q1 and q2
	polyBase := 3
	fpPrecision := 8

	pk, sk, _ := bgn.NewKeyGen(keyBits, polyBase, fpPrecision)

	m1 := bgn.NewPlaintext(5.519197, pk.PolyBase)
	m2 := bgn.NewPlaintext(1.121212, pk.PolyBase)
	m3 := bgn.NewPlaintext(10, pk.PolyBase)
	m4 := bgn.NewPlaintext(15.11111, pk.PolyBase)

	fmt.Println("m1 = " + m1.String())
	fmt.Println("m2 = " + m2.String())
	fmt.Println("m3 = " + m3.String())
	fmt.Println("m4 = " + m4.String())

	c1 := pk.Encrypt(m1)
	c2 := pk.Encrypt(m2)
	c3 := pk.Encrypt(m3)
	c4 := pk.Encrypt(m4)

	r1 := pk.EAdd(c1, c2)
	fmt.Printf("Result of EADD %s + %s = %s\n", m1, m2, sk.Decrypt(r1, pk).String())

	r2 := pk.EMultC(c2, 10)
	fmt.Printf("Result of EMULTC %s * 10 = %s\n", m2, sk.Decrypt(r2, pk).String())

	r3 := pk.EMult(c3, c4)
	dr3 := sk.DecryptL2(r3, pk)
	fmt.Printf("Result of EMULT %s * %s = %s\n", m3, m4, sk.DecryptL2(r3, pk).String())

	r4 := pk.EMultCL2(r3, 4.444444)
	fmt.Printf("Result of EMULTCL2 %s * 4.444444 = %s\n", dr3.String(), sk.DecryptL2(r4, pk).String())

	r5 := pk.EAddL2(r3, r3)
	fmt.Printf("Result of EADDL2 %s + %s = %s\n", dr3.String(), dr3.String(), sk.DecryptL2(r5, pk).String())

	println("\n***End Executing Demo****\n")

}

// func exampleMultiParty(bits int, numParties int) {

// 	println("\n***Multi-party decryption****\n")

// 	pk, shares, _ := bgn.NewMPKeyGen(bits, numParties)

// 	m1 := bgn.NewPlaintextInt(big.NewInt(24))
// 	m2 := bgn.NewPlaintextInt(big.NewInt(23))
// 	fmt.Println("\nP1 is: " + m1.String())
// 	fmt.Println("\nP2 is: " + m2.String())

// 	c1 := pk.Encrypt(m1)
// 	c2 := pk.Encrypt(m2)
// 	c3 := pk.EAdd(c1, c2)
// 	c4 := pk.EMult(c1, c2)

// 	fmt.Println("\n[LEVEL 1] E(P1) is: " + c1.String())
// 	fmt.Println("\n[LEVEL 1] E(P2) is: " + c2.String())

// 	partialDecryptions := []*bgn.PartialDecrypt{}

// 	for index, share := range shares {
// 		partial := share.PartialDecrypt(c3, pk)
// 		partialDecryptions = append(partialDecryptions, partial)
// 		fmt.Println("\nPartial decryption from party #" + strconv.Itoa(index) + " is: " + partial.Csk.String())
// 	}

// 	resultAdd := bgn.CombinedShares(partialDecryptions, pk)

// 	partialDecryptions = []*bgn.PartialDecrypt{}
// 	for index, share := range shares {
// 		partial := share.PartialDecrypt2(c4, pk)
// 		partialDecryptions = append(partialDecryptions, partial)
// 		fmt.Println("\nPartial decryption from party #" + strconv.Itoa(index) + " is: " + partial.Csk.String())
// 	}

// 	resultMult := bgn.CombinedShares(partialDecryptions, pk)

// 	fmt.Println("\nMulti-party result of [LEVEL 1] E(" + m1.String() + ") + [LEVEL 1] E(" + m2.String() + ") is: [LEVEL 1] E(" + resultAdd.String() + ")\n")
// 	fmt.Println("\nMulti-party result of [LEVEL 1] E(" + m1.String() + ") * [LEVEL 1] E(" + m2.String() + ") is: [LEVEL 2] E(" + resultMult.String() + ")\n")

// }

// func exampleClassic(bits int) {

// 	pk, sk, _ := bgn.NewKeyGen(bits)
// 	m1 := bgn.NewPlaintextInt(big.NewInt(25))
// 	m2 := bgn.NewPlaintextInt(big.NewInt(7))
// 	constant := big.NewInt(10)

// 	fmt.Println("\nP1 is: " + m1.String())
// 	fmt.Println("\nP2 is: " + m2.String())

// 	c1 := pk.Encrypt(m1)
// 	c2 := pk.Encrypt(m2)

// 	fmt.Println("\n[LEVEL 1] E(P1) is: " + c1.String())
// 	fmt.Println("\n[LEVEL 2] E(P2) is: " + c2.String())

// 	c3 := pk.EAdd(c1, c2)
// 	c4 := pk.EMultC(c1, constant)
// 	c5 := pk.EMult(c1, c2)
// 	c6 := pk.EAdd2(c5, c5)
// 	c7 := pk.EMultC2(c5, constant)

// 	fmt.Println("\nResult of " + "[LEVEL 1] E(" + m1.String() + ") + [LEVEL 1] E(" + m2.String() + ") is: [LEVEL 1] E(" + sk.Decrypt(c3, pk).String() + ")")
// 	fmt.Println("\nResult of " + "[LEVEL 1] E(" + m1.String() + ") * " + constant.String() + " is: [LEVEL 1] E(" + sk.Decrypt(c4, pk).String() + ")")

// 	plaintextMult := sk.Decrypt2(c5, pk)
// 	fmt.Println("\nResult of " + "[LEVEL 1] E(" + m1.String() + ") * [LEVEL 1] E(" + m2.String() + ") is: [LEVEL 2] E(" + plaintextMult.String() + ")")
// 	fmt.Println("\nResult of " + "[LEVEL 2] E(" + plaintextMult.String() + ") + " + "[LEVEL 2] E(" + plaintextMult.String() + ") is: [LEVEL 2] E(" + sk.Decrypt2(c6, pk).String() + ")")
// 	fmt.Println("\nResult of " + "[LEVEL 2] E(" + plaintextMult.String() + ") * " + constant.String() + " is: [LEVEL 2] E(" + sk.Decrypt2(c7, pk).String() + ")")
// }

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
	fmt.Println("  Test implementation of the Boneh Goh Nissim crypto system.")
	fmt.Println("-----------------------------------------------------------------")
}
