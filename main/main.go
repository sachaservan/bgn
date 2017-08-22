package main

import (
	"bgn"
	"fmt"
	"math/big"
)

func main() {

	bits := 512 // length of p and q

	bgn.NewMPKeyGen(bits, 20)
	pk, sk, _ := bgn.NewKeyGen(bits)
	m1 := big.NewInt(2)
	m2 := big.NewInt(3)
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
