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

// ciphertextWrapper is a wrapper for the Ciphertext struct
// for marshalling/unmarshalling purposes since pbc.Element does not export fields
type ciphertextWrapper struct {
	C  []byte
	L2 bool
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
func NewCiphertext(c *pbc.Element, scaleFactor int, l2 bool) *Ciphertext {
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

// MarshalBinary is needed in order to encode/decode
// pbc.Element type since it has no exported fields
func (ct *Ciphertext) MarshalBinary() ([]byte, error) {

	// wrap struct
	w := ciphertextWrapper{
		C:  ct.C.Bytes(),
		L2: ct.L2,
	}

	// use default gob encoder
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary is needed in order to encode/decode
// pbc.Element type since it has no exported fields
func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	w := ciphertextWrapper{}

	reader := bytes.NewReader(data)
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&w); err != nil {
		return err
	}

	el := ct.C.NewFieldElement()
	el.SetBytes(w.C)

	ct.C = el
	ct.L2 = w.L2

	return nil
}
