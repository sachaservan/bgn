package main

import (
	"bgn"
	"fmt"
	"math/big"
	"strconv"

	"github.com/Nik-U/pbc"
)

func main() {

	printWelcome()

	println("\n***Begin Executing Demo****")

	bits := 512 // length of q1 and q2
	n := 8      // number of decryption parties
	exampleClassic(bits)
	exampleMultiParty(bits, n)

	println("\n***End Executing Demo****\n")

}

func exampleMultiParty(bits int, numParties int) {

	println("\n***Multi-party decryption****\n")

	pk, shares, _ := bgn.NewMPKeyGen(bits, numParties)

	m1 := big.NewInt(24)
	m2 := big.NewInt(23)
	fmt.Println("\nP1 is: " + m1.String())
	fmt.Println("\nP2 is: " + m2.String())

	c1 := pk.Encrypt(m1)
	c2 := pk.Encrypt(m2)
	c3 := pk.EAdd(c1, c2)
	c4 := pk.EMult(c1, c2)

	fmt.Println("\n[LEVEL 1] E(P1) is: " + c1.String())
	fmt.Println("\n[LEVEL 1] E(P2) is: " + c2.String())

	cskArray := []*pbc.Element{}
	gskArray := []*pbc.Element{}

	for index, share := range shares {
		csk, gsk := share.PartialDecrypt(c3, pk)
		cskArray = append(cskArray, csk)
		gskArray = append(gskArray, gsk)
		fmt.Println("\nPartial decryption from party #" + strconv.Itoa(index) + " is: " + csk.String())
	}

	resultAdd := bgn.CombinedShares(cskArray, gskArray, pk)

	cskArray = []*pbc.Element{}
	gskArray = []*pbc.Element{}
	for index, share := range shares {
		csk, gsk := share.PartialDecrypt2(c4, pk)
		cskArray = append(cskArray, csk)
		gskArray = append(gskArray, gsk)
		fmt.Println("\nPartial decryption from party #" + strconv.Itoa(index) + " is: " + csk.String())
	}

	resultMult := bgn.CombinedShares(cskArray, gskArray, pk)
	fmt.Println("\nMulti-party result of [LEVEL 1] E(" + m1.String() + ") + [LEVEL 1] E(" + m2.String() + ") is: [LEVEL 1] E(" + resultAdd.String() + ")\n")
	fmt.Println("\nMulti-party result of [LEVEL 1] E(" + m1.String() + ") * [LEVEL 1] E(" + m2.String() + ") is: [LEVEL 2] E(" + resultMult.String() + ")\n")

}

func exampleClassic(bits int) {

	pk, sk, _ := bgn.NewKeyGen(bits)
	m1 := big.NewInt(21)
	m2 := big.NewInt(32)
	constant := big.NewInt(10)

	fmt.Println("\nP1 is: " + m1.String())
	fmt.Println("\nP2 is: " + m2.String())

	c1 := pk.Encrypt(m1)
	c2 := pk.Encrypt(m2)

	fmt.Println("\n[LEVEL 1] E(P1) is: " + c1.String())
	fmt.Println("\n[LEVEL 2] E(P2) is: " + c2.String())

	c3 := pk.EAdd(c1, c2)
	c4 := pk.EMultC(c1, constant)
	c5 := pk.EMult(c1, c2)
	c6 := pk.EAdd2(c5, c5)
	c7 := pk.EMultC2(c5, constant)

	fmt.Println("\nResult of " + "[LEVEL 1] E(" + m1.String() + ") + [LEVEL 1] E(" + m2.String() + ") is: [LEVEL 1] E(" + sk.Decrypt(c3, pk).String() + ")")
	fmt.Println("\nResult of " + "[LEVEL 1] E(" + m1.String() + ") * " + constant.String() + " is: [LEVEL 1] E(" + sk.Decrypt(c4, pk).String() + ")")

	plaintextMult := sk.Decrypt2(c5, pk)
	fmt.Println("\nResult of " + "[LEVEL 1] E(" + m1.String() + ") * [LEVEL 1] E(" + m2.String() + ") is: [LEVEL 2] E(" + plaintextMult.String() + ")")
	fmt.Println("\nResult of " + "[LEVEL 2] E(" + plaintextMult.String() + ") + " + "[LEVEL 2] E(" + plaintextMult.String() + ") is: [LEVEL 2] E(" + sk.Decrypt2(c6, pk).String() + ")")
	fmt.Println("\nResult of " + "[LEVEL 2] E(" + plaintextMult.String() + ") * " + constant.String() + " is: [LEVEL 2] E(" + sk.Decrypt2(c7, pk).String() + ")")
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
	fmt.Println("  Test implementation of the Boneh Goh Nissim crypto system.")
	fmt.Println("-----------------------------------------------------------------")
}
