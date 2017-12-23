package bgn

import (
	"fmt"
	"math/big"

	"github.com/Nik-U/pbc"
)

type BlackBoxMPC struct {
	Shares     []*SecretKeyShare
	Pk         *PublicKey
	Sk         *SecretKey
	NumParties int
}

// SecretKeyShare is a share of a secret key
type SecretKeyShare struct {
	Share *big.Int
}

/* multiply ct1*ct2 together in MPC
 * Party 0 send everyone E(ct2)
 * Party i generate/compute a_i, E(a_i) and E(ct2 a_i). Send E(a_i) and E(b a_i) to Party 0
 * Party 0 computes E(ct1) – E(a), where E(a) is the sum of E(a_i)’s.
 * All decrypt E(ct1-a) 1/b/r * 1/r
 * Party 0 computes E(ct2)*(ct1-a) + E(ct2*a) from E(ct2*a_i) it got in step 2.
 */

type MPCRequest struct {
	Ct *Ciphertext
}

type MPCResponse struct {
	PartialCt   *Ciphertext
	PartialRand *Ciphertext
}

type MPCReceptacle struct {
	Ct   *Ciphertext
	Rand *Ciphertext
}

type PartialDecrypt struct {
	Csks        []*pbc.Element
	Gsk         *pbc.Element
	Degree      int
	ScaleFactor int
}

func NewBlackboxMPC(shares []*SecretKeyShare, pk *PublicKey, sk *SecretKey) *BlackBoxMPC {
	return &BlackBoxMPC{shares, pk, sk, len(shares)}
}

func NewMPCRequest(ct *Ciphertext) *MPCRequest {
	return &MPCRequest{ct}
}

func (bb *BlackBoxMPC) MPCDecrypt(ct *Ciphertext) *Plaintext {

	partialDecryptions := make([]*PartialDecrypt, bb.NumParties)

	for index, share := range bb.Shares {
		if ct.L2 {
			partial := share.partialDecryptL2(ct, bb.Pk)
			partialDecryptions[index] = partial
		} else {
			partial := share.partialDecrypt(ct, bb.Pk)
			partialDecryptions[index] = partial
		}
	}

	result := bb.combineShares(ct, partialDecryptions, bb.Pk)
	return result
}

func (bb *BlackBoxMPC) MPCEncrypt(ct *Ciphertext) *Ciphertext {

	var result *MPCReceptacle

	for i := 0; i < bb.NumParties; i++ {
		res := bb.Pk.requestMPCReEncryption(ct)

		if result == nil {
			result = &MPCReceptacle{Ct: res.PartialCt, Rand: res.PartialRand}
		} else {
			bb.Pk.EAdd(result.Ct, res.PartialCt)

			for k := 0; k < len(res.PartialRand.Coefficients); k++ {
				result.Rand.Coefficients[k] = bb.Pk.eAddElements(result.Rand.Coefficients[k],
					res.PartialRand.Coefficients[k])
			}
		}
	}

	plaintext := bb.MPCDecrypt(result.Ct)
	recrypt := bb.Pk.Encrypt(plaintext)

	return bb.Pk.EAdd(recrypt, bb.Pk.AInv(result.Rand))
}

func (bb *BlackBoxMPC) MPCEMInv(ct *Ciphertext) *Ciphertext {

	fmt.Println("Message space is " + bb.Pk.T.String())

	fmt.Println("Original ciphertext was " + bb.MPCDecrypt(ct).String())
	ct = bb.Pk.scaleDownL2Ciphertext(ct)
	fmt.Println("Scaled down ciphertext is " + bb.MPCDecrypt(ct).String())

	result := bb.Pk.Encrypt(NewPlaintext(big.NewFloat(0.09), bb.Pk.PolyBase, bb.Pk.FPPrecision))

	for i := 0; i <= 10; i++ {
		fmt.Println("Result of division is now " + bb.MPCDecrypt(result).String())
		fmt.Printf("Poly degree is now %d\n", result.Degree)
		result2 := bb.Pk.EMult(bb.MPCEncrypt(bb.Pk.EMult(result, result)), ct)
		result = bb.Pk.EMultC(result, big.NewFloat(2.0))
		result = bb.Pk.EAdd(result, bb.Pk.AInv(result2))
		result = bb.MPCEncrypt(result)
	}

	return result
}

func (pk *PublicKey) scaleDownL2Ciphertext(ct *Ciphertext) *Ciphertext {

	newCoefficients := make([]*pbc.Element, 1)
	newCoefficients[0] = ct.Coefficients[0]

	for i := 1; i < ct.Degree; i++ {

		value := ct.Coefficients[i]
		var pow *big.Int
		if degreeTable != nil && len(degreeTable) > i {
			pow = degreeTable[i]
		} else {
			pow = big.NewInt(0).Exp(big.NewInt(int64(pk.PolyBase)), big.NewInt(int64(i)), nil)
		}

		value = pk.eMultCElement(value, pow, true)
		newCoefficients[0] = pk.eAddElements(newCoefficients[0], value)
	}

	scaleFactor := ct.ScaleFactor
	//invPow := big.NewInt(0).Sub(pk.T, big.NewInt(2))

	// for i := 2; i <= ct.Degree; i++ {

	// 	value := newCoefficients[0]
	// 	pow := big.NewInt(0).Exp(big.NewInt(int64(pk.PolyBase)), big.NewInt(int64(i-1)), nil)
	// 	modInv := pow.Exp(pow, invPow, pk.T)
	// 	value = pk.eMultCElementL2(value, modInv, true)

	// 	fmt.Println("modInv for pow is " + modInv.String() + " where pow is " + pow.String())
	// 	newCoefficients[0] = value
	// 	scaleFactor--
	// }

	return &Ciphertext{newCoefficients, 1, scaleFactor, ct.L2}

}

func (pk *PublicKey) requestMPCMultiplicativeRandomization(ct *Ciphertext) *MPCResponse {

	randFloat := big.NewFloat(float64(newCryptoRandom(pk.T).Int64()) + 1.0)
	rand := pk.Encrypt(NewUnbalancedPlaintext(randFloat, pk.PolyBase, pk.FPPrecision))

	return &MPCResponse{pk.EMultC(ct, randFloat), rand}
}

func (pk *PublicKey) requestMPCReEncryption(ct *Ciphertext) *MPCResponse {

	randCt := ct.Copy()
	rand := &Ciphertext{make([]*pbc.Element, randCt.Degree), randCt.Degree, randCt.ScaleFactor, false}

	for i := 0; i < len(randCt.Coefficients); i++ {
		randVal := pk.encrypt(newCryptoRandom(pk.T))
		randCt.Coefficients[i] = pk.eAddL2Elements(randCt.Coefficients[i], pk.toDeterministicL2Element(randVal))
		rand.Coefficients[i] = randVal
	}

	return &MPCResponse{randCt, rand}
}

func (sk *SecretKeyShare) partialDecrypt(ct *Ciphertext, pk *PublicKey) *PartialDecrypt {

	if ct.L2 {
		return sk.partialDecryptL2(ct, pk)
	}

	csks := make([]*pbc.Element, ct.Degree)

	gsk := pk.G1.NewFieldElement()
	gsk = gsk.PowBig(pk.P, sk.Share)

	for i, coeff := range ct.Coefficients {
		csk := pk.G1.NewFieldElement()
		csks[i] = csk.PowBig(coeff, sk.Share)
	}

	return &PartialDecrypt{csks, gsk, ct.Degree, ct.ScaleFactor}
}

func (sk *SecretKeyShare) partialDecryptL2(ct *Ciphertext, pk *PublicKey) *PartialDecrypt {

	csks := make([]*pbc.Element, ct.Degree)

	gsk := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	gsk = gsk.PowBig(gsk, sk.Share)

	for i, coeff := range ct.Coefficients {
		csk := pk.Pairing.NewGT().NewFieldElement()
		csks[i] = csk.PowBig(coeff, sk.Share)
	}

	return &PartialDecrypt{csks, gsk, ct.Degree, ct.ScaleFactor}
}

func (bb *BlackBoxMPC) combineShares(ct *Ciphertext, shares []*PartialDecrypt, pk *PublicKey) *Plaintext {

	if len(shares) < 1 {
		panic("Number of shares to combine must be >= 1")
	}

	size := shares[0].Degree // assume all partial decrypts will have same number of coeffs (they should)
	csks := make([]*pbc.Element, size)
	csksNegative := make([]*pbc.Element, size)

	gsk := shares[0].Gsk
	for i := 0; i < size; i++ {
		csks[i] = shares[0].Csks[i].NewFieldElement()
		csks[i].Set(shares[0].Csks[i])
	}

	for index, share := range shares {

		if index == 0 {
			continue
		}

		for i := 0; i < size; i++ {
			csks[i].Mul(csks[i], share.Csks[i])
		}

		gsk = gsk.Mul(gsk, share.Gsk)
	}

	plaintextCoeffs := make([]int64, size)
	for i := 0; i < size; i++ {

		pt, err := pk.recoverMessageWithDL(gsk, csks[i], true)
		if err != nil {
			pt, err := pk.recoverMessageWithDL(gsk, csksNegative[i], true)
			if err != nil {
				panic("second decrypt attempt failed. Message not recoverable")
			}
			plaintextCoeffs[i] = pt

		} else {
			plaintextCoeffs[i] = pt
		}
	}

	return &Plaintext{plaintextCoeffs, size, pk.PolyBase, shares[0].ScaleFactor}

}

// NewMPCKeyGen generates a new public key and n shares of a secret key
func NewMPCKeyGen(numShares int, keyBits int, polyBase int, fpPrecision int, deterministic bool) (*PublicKey, *SecretKey, []*SecretKeyShare, error) {

	// generate standard key pair
	var sk *SecretKey
	pk, sk, err := NewKeyGen(keyBits, big.NewInt(15010109923), polyBase, fpPrecision, deterministic)

	if err != nil {
		return nil, nil, nil, err
	}

	// secret key shares
	var shares []*SecretKeyShare

	// max value of each share (no bigger than sk/n)
	max := big.NewInt(0).Div(sk.Key, big.NewInt(int64(numShares)))

	// sum of all the shares
	sum := big.NewInt(0)

	// compute shares
	for i := 0; i < numShares-1; i++ {
		// create new random share
		next := newCryptoRandom(max)
		shares = append(shares, &SecretKeyShare{next})
		sum.Add(sum, next)
	}

	// last share should be computed so as to
	// have all shares add up to sk
	last := sum.Sub(sk.Key, sum)
	shares = append(shares, &SecretKeyShare{last})

	return pk, sk, shares, err
}
