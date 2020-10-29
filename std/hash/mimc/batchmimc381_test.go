package mimc

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	fr_bls381 "github.com/consensys/gurvy/bls381/fr"
)

//------------------------------------------------------------------
// benches

var nbHashesBLS381 = [...]int{
	1 << 11,
	1 << 12,
	1 << 13,
	1 << 14,
	1 << 15,
	1 << 16,
	1 << 17,
	1 << 18,
	1 << 19,
	1 << 20,
	1 << 21,
}

// nb mimcs = 2**11
type bls381BatchMimc11 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc11) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[0]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc11(b *testing.B) {

	nbMimcs := nbHashesBLS381[0]

	var batchedMimc, witness bls381BatchMimc11
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**12
type bls381BatchMimc12 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc12) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[1]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc12(b *testing.B) {

	nbMimcs := nbHashesBLS381[1]

	var batchedMimc, witness bls381BatchMimc12
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**13
type bls381BatchMimc13 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc13) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[2]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc13(b *testing.B) {

	nbMimcs := nbHashesBLS381[2]

	var batchedMimc, witness bls381BatchMimc13
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**14
type bls381BatchMimc14 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc14) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[3]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc14(b *testing.B) {

	nbMimcs := nbHashesBLS381[3]

	var batchedMimc, witness bls381BatchMimc14
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**15
type bls381BatchMimc15 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc15) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[4]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc15(b *testing.B) {

	nbMimcs := nbHashesBLS381[4]

	var batchedMimc, witness bls381BatchMimc15
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**16
type bls381BatchMimc16 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc16) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[5]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc16(b *testing.B) {

	nbMimcs := nbHashesBLS381[5]

	var batchedMimc, witness bls381BatchMimc16
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**17
type bls381BatchMimc17 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc17) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[6]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc17(b *testing.B) {

	nbMimcs := nbHashesBLS381[6]

	var batchedMimc, witness bls381BatchMimc17
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**18
type bls381BatchMimc18 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc18) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[7]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc18(b *testing.B) {

	nbMimcs := nbHashesBLS381[7]

	var batchedMimc, witness bls381BatchMimc18
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**19
type bls381BatchMimc19 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc19) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[8]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc19(b *testing.B) {

	nbMimcs := nbHashesBLS381[8]

	var batchedMimc, witness bls381BatchMimc19
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**20
type bls381BatchMimc20 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc20) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[9]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc20(b *testing.B) {

	nbMimcs := nbHashesBLS381[9]

	var batchedMimc, witness bls381BatchMimc20
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**21
type bls381BatchMimc21 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bls381BatchMimc21) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBLS381[10]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBLS381BatchMimc21(b *testing.B) {

	nbMimcs := nbHashesBLS381[10]

	var batchedMimc, witness bls381BatchMimc21
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bls381.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BLS381, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}
