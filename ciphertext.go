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

// TransportableCiphertext can be marshalled and unmarshalled
// but requires keeping PairingParams for doing so
type TransportableCiphertext struct {
	Ciphertext
	PairingParams string
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

// TransportablePolyCiphertext can be marshalled and unmarshalled
// but requires keeping PairingParams for doing so
type TransportablePolyCiphertext struct {
	*PolyCiphertext
	PairingParams string
}

// ciphertextWrapper is a wrapper for the Ciphertext struct
// for marshalling/unmarshalling purposes since pbc.Element does not export fields
type transporableCiphertextWrapper struct {
	C             []byte
	L2            bool
	PairingParams string
}

// ciphertextWrapper is a wrapper for the Ciphertext struct
// for marshalling/unmarshalling purposes since pbc.Element does not export fields
type transporablePolyCiphertextWrapper struct {
	Coefficients  [][]byte
	Degree        int
	ScaleFactor   int
	L2            bool
	PairingParams string
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
func (ct *TransportableCiphertext) MarshalBinary() ([]byte, error) {

	if ct == nil || ct.C == nil {
		return nil, nil
	}

	// wrap struct
	w := transporableCiphertextWrapper{
		C:             ct.C.Bytes(),
		L2:            ct.L2,
		PairingParams: ct.PairingParams,
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
func (ct *TransportableCiphertext) UnmarshalBinary(data []byte) error {

	if len(data) == 0 {
		return nil
	}

	w := transporableCiphertextWrapper{}

	reader := bytes.NewReader(data)
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&w); err != nil {
		return err
	}

	params, err := pbc.NewParamsFromString(w.PairingParams)
	if err != nil {
		return err
	}

	pairing := pbc.NewPairing(params)

	if w.L2 {
		el := pairing.NewGT().NewFieldElement()
		el.SetBytes(w.C)
		ct.C = el
	} else {
		el := pairing.NewG1().NewFieldElement()
		el.SetBytes(w.C)
		ct.C = el
	}

	ct.L2 = w.L2
	ct.PairingParams = w.PairingParams

	return nil
}

// MarshalBinary is needed in order to encode/decode
// pbc.Element type since it has no exported fields
func (ct *TransportablePolyCiphertext) MarshalBinary() ([]byte, error) {

	if ct == nil || ct.PolyCiphertext == nil {
		return nil, nil
	}

	coeffBytes := make([][]byte, 0)
	for _, c := range ct.Coefficients {
		coeffBytes = append(coeffBytes, c.C.Bytes())
	}

	// wrap struct
	w := transporablePolyCiphertextWrapper{
		Coefficients:  coeffBytes,
		Degree:        ct.Degree,
		L2:            ct.L2,
		PairingParams: ct.PairingParams,
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
func (ct *TransportablePolyCiphertext) UnmarshalBinary(data []byte) error {

	if len(data) == 0 || ct.PolyCiphertext == nil {
		return nil
	}

	w := transporablePolyCiphertextWrapper{}

	reader := bytes.NewReader(data)
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&w); err != nil {
		return err
	}

	params, err := pbc.NewParamsFromString(w.PairingParams)
	if err != nil {
		return err
	}

	pairing := pbc.NewPairing(params)

	coeffs := make([]*Ciphertext, 0)
	for _, coeffBytes := range w.Coefficients {

		if w.L2 {
			el := pairing.NewGT().NewFieldElement()
			el.SetBytes(coeffBytes)
			coeffs = append(coeffs, &Ciphertext{el, w.L2})
		} else {
			el := pairing.NewG1().NewFieldElement()
			el.SetBytes(coeffBytes)
			coeffs = append(coeffs, &Ciphertext{el, w.L2})
		}
	}

	ct.Degree = w.Degree
	ct.Coefficients = coeffs
	ct.L2 = w.L2
	ct.ScaleFactor = w.ScaleFactor
	ct.PairingParams = w.PairingParams

	return nil
}
