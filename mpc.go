package bgn

import (
	"fmt"
	"math"
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

// multiply ct1*ct2 together in MPC
// Party 0 send everyone E(ct2)
// Party i generate/compute a_i, E(a_i) and E(ct2 a_i). Send E(a_i) and E(b a_i) to Party 0
// Party 0 computes E(ct1) – E(a), where E(a) is the sum of E(a_i)’s.
// All decrypt E(ct1-a)
// Party 0 computes E(ct2)*(ct1+a) - E(ct2*a) from E(ct2*a_i) it got in step 2.

type MPCEMultRequest struct {
	Ct *Ciphertext
}

type MPCEMultResponse struct {
	PartialTermA  *Ciphertext // E(a_i)
	PartialTermBA *Ciphertext // E(b*a_i)
}

type MPCEMultReceptacle struct {
	TermA  *Ciphertext
	TermBA *Ciphertext
}

type PartialDecrypt struct {
	Csks         []*pbc.Element
	CsksNegative []*pbc.Element
	Gsk          *pbc.Element
	Degree       int
	ScaleFactor  int
}

func NewBlackboxMPC(shares []*SecretKeyShare, pk *PublicKey, sk *SecretKey) *BlackBoxMPC {
	return &BlackBoxMPC{shares, pk, sk, len(shares)}
}

func NewMPCEmultRequest(ct *Ciphertext) *MPCEMultRequest {
	return &MPCEMultRequest{ct}
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

	result := bb.combinedShares(ct, partialDecryptions, bb.Pk)
	return result
}

func (bb *BlackBoxMPC) MPCEmult(ct1 *Ciphertext, ct2 *Ciphertext) *Ciphertext {

	var result *MPCEMultReceptacle

	for i := 0; i < bb.NumParties; i++ {
		req := NewMPCEmultRequest(ct2)
		res := bb.Pk.RequestMPCMultiplication(req)

		if result == nil {
			result = &MPCEMultReceptacle{TermA: res.PartialTermA, TermBA: res.PartialTermBA}
		} else {
			result.TermA = bb.Pk.EAdd(result.TermA, res.PartialTermA)
			result.TermBA = bb.Pk.EAdd(result.TermBA, res.PartialTermBA)
		}
	}

	partial := bb.Pk.EAdd(ct1, bb.Pk.AInv(result.TermA))
	term1 := bb.MPCDecrypt(partial)

	fmt.Printf("MPC decryption of (ct1-%s) = %s\n", bb.Sk.Decrypt(result.TermA, bb.Pk).String(), term1.String())

	term1Float, _ := term1.PolyEval().Float64()

	if term1Float < 0 {
		term1Float *= -1.0
		return bb.Pk.AInv(bb.Pk.EAdd(bb.Pk.EMultC(ct2, term1Float), bb.Pk.AInv(result.TermBA)))
	}

	return bb.Pk.EAdd(bb.Pk.EMultC(ct2, term1Float), result.TermBA)
}

func (pk *PublicKey) RequestMPCMultiplication(request *MPCEMultRequest) *MPCEMultResponse {

	// TODO: remove constant rand factor here?
	termA := math.Floor(float64(newCryptoRandom(big.NewInt(10000)).Int64()))

	termAPoly := NewPlaintext(termA, pk.PolyBase, pk.FPPrecision)
	termAEnc := pk.Encrypt(termAPoly)

	return &MPCEMultResponse{termAEnc, pk.EMultC(request.Ct, termA)}
}

func (sk *SecretKeyShare) partialDecrypt(ct *Ciphertext, pk *PublicKey) *PartialDecrypt {

	if ct.L2 {
		return sk.partialDecryptL2(ct, pk)
	}

	csks := make([]*pbc.Element, ct.Degree)
	// TODO: find a better way than having to keep two ciphertexts
	csksNegative := make([]*pbc.Element, ct.Degree)
	gsk := pk.G1.NewFieldElement()
	gsk = gsk.PowBig(pk.P, sk.Share)

	for i, coeff := range ct.Coefficients {
		csk := pk.G1.NewFieldElement()
		csks[i] = csk.PowBig(coeff, sk.Share)

		cskNegative := pk.G1.NewFieldElement()
		csksNegative[i] = cskNegative.PowBig(pk.eSubElements(coeff, pk.DT, true), sk.Share)
	}

	return &PartialDecrypt{csks, csksNegative, gsk, ct.Degree, ct.ScaleFactor}
}

func (sk *SecretKeyShare) partialDecryptL2(ct *Ciphertext, pk *PublicKey) *PartialDecrypt {

	csks := make([]*pbc.Element, ct.Degree)
	// TODO: find a better way than having to keep two ciphertexts
	csksNegative := make([]*pbc.Element, ct.Degree)

	gsk := pk.Pairing.NewGT().Pair(pk.P, pk.P)
	gsk = gsk.PowBig(gsk, sk.Share)

	for i, coeff := range ct.Coefficients {
		csk := pk.Pairing.NewGT().NewFieldElement()
		csks[i] = csk.PowBig(coeff, sk.Share)

		cskNegative := pk.Pairing.NewGT().NewFieldElement()
		csksNegative[i] = cskNegative.PowBig(pk.eSubL2Elements(coeff, pk.toL2Element(pk.DT, true), true), sk.Share)
	}

	return &PartialDecrypt{csks, csksNegative, gsk, ct.Degree, ct.ScaleFactor}
}

func (bb *BlackBoxMPC) combinedShares(ct *Ciphertext, shares []*PartialDecrypt, pk *PublicKey) *Plaintext {

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

		csksNegative[i] = shares[0].CsksNegative[i].NewFieldElement()
		csksNegative[i].Set(shares[0].CsksNegative[i])
	}

	for index, share := range shares {

		if index == 0 {
			continue
		}

		for i := 0; i < size; i++ {
			csks[i].Mul(csks[i], share.Csks[i])
			csksNegative[i].Mul(csksNegative[i], share.CsksNegative[i])
		}

		gsk = gsk.Mul(gsk, share.Gsk)
	}

	plaintextCoeffs := make([]int64, size)
	for i := 0; i < size; i++ {

		pt, err := pk.recoverMessageWithDL(gsk, csks[i])
		if err != nil {
			pt, err := pk.recoverMessageWithDL(gsk, csksNegative[i])
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
	pk, sk, err := NewKeyGen(keyBits, polyBase, fpPrecision, deterministic)

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
