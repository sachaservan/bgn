package bgn

import (
	"bytes"
	"encoding/gob"

	"github.com/Nik-U/pbc"
)

// Ciphertext is BGN ciphertext encrypting a value with
// a ScaleFactor fixed-point encoding precision
type Ciphertext struct {
	C  *pbc.Element // point on the elliptic curve
	L2 bool         // indicates whether ciphertext is atlevel2
}

type ciphertextWrapper struct {
	CBytes []byte
	L2     bool
}

// PolyCiphertext is an encoding of a value in a
// a given base (specified in the public key)
// such an encoding is useful for reducing the impact of modular wrap around as
// the encrypted values grow
type PolyCiphertext struct {
	Coefficients []*Ciphertext // coefficients of the encrypted plaintext poly
	Degree       int           // degree of the polynomial s
	ScaleFactor  int           // scaling factor for fixed-point encoding
	L2           bool          // indicates whether ciphertext is atlevel2
}

type polyCiphertextWrapper struct {
	CoeffBytes  [][]byte
	Degree      int
	ScaleFactor int
	L2          bool
}

// Copy returns a copy of the given ciphertext
func (ct *PolyCiphertext) Copy() *PolyCiphertext {
	return &PolyCiphertext{ct.Coefficients, ct.Degree, ct.ScaleFactor, ct.L2}
}

// NewPolyCiphertext generates a new polynmial ciphertext with specified coefficients and parameters
func NewPolyCiphertext(coefficients []*Ciphertext, degree int, scaleFactor int, l2 bool) *PolyCiphertext {
	return &PolyCiphertext{coefficients, degree, scaleFactor, l2}
}

// NewCiphertext generates a BGN ciphertext with specified coefficients and parameters
func NewCiphertext(c *pbc.Element, l2 bool) *Ciphertext {
	return &Ciphertext{c, l2}
}

// Copy returns a copy of the given ciphertext
func (ct *Ciphertext) Copy() *Ciphertext {
	return &Ciphertext{ct.C, ct.L2}
}

func (ct *Ciphertext) String() string {
	return ct.C.String() + "\n"
}

func (ct *PolyCiphertext) String() string {

	str := ""
	for _, coeff := range ct.Coefficients {
		str += coeff.C.String() + "\n"
	}

	return str
}

// Bytes returns the marshalled bytes of
// the ciphertext struct
func (ct *Ciphertext) Bytes() ([]byte, error) {

	w := ciphertextWrapper{}
	w.CBytes = ct.C.Bytes()
	w.L2 = ct.L2

	// use default gob encoder
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(w); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Bytes returns the marshalled bytes of
// the ciphertext struct
func (ct *PolyCiphertext) Bytes() ([]byte, error) {

	w := polyCiphertextWrapper{}

	coeffBytes := make([][]byte, 0)
	for _, c := range ct.Coefficients {
		coeffBytes = append(coeffBytes, c.C.Bytes())
	}

	w.CoeffBytes = coeffBytes
	w.L2 = ct.L2
	w.Degree = ct.Degree
	w.ScaleFactor = ct.ScaleFactor

	// use default gob encoder
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(w); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
