package mimc

import (
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	fr_bn256 "github.com/consensys/gurvy/bn256/fr"
)

//------------------------------------------------------------------
// benches

var nbHashesBN256 = [...]int{
	1 << 11,
	1 << 12,
	1 << 13,
	1 << 14,
	1 << 15,
	1 << 16,
	1 << 17,
	1 << 18,
}

// nb mimcs = 2**11
type bn256BatchMimc11 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bn256BatchMimc11) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBN256[0]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBN256BatchMimc11(b *testing.B) {

	nbMimcs := nbHashesBN256[0]

	var batchedMimc, witness bn256BatchMimc11
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bn256.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BN256, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**12
type bn256BatchMimc12 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bn256BatchMimc12) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBN256[1]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBN256BatchMimc12(b *testing.B) {

	nbMimcs := nbHashesBN256[1]

	var batchedMimc, witness bn256BatchMimc12
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bn256.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BN256, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**13
type bn256BatchMimc13 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bn256BatchMimc13) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBN256[2]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBN256BatchMimc13(b *testing.B) {

	nbMimcs := nbHashesBN256[2]

	var batchedMimc, witness bn256BatchMimc13
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bn256.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BN256, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**14
type bn256BatchMimc14 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bn256BatchMimc14) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBN256[3]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBN256BatchMimc14(b *testing.B) {

	nbMimcs := nbHashesBN256[3]

	var batchedMimc, witness bn256BatchMimc14
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bn256.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BN256, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**15
type bn256BatchMimc15 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bn256BatchMimc15) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBN256[4]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBN256BatchMimc15(b *testing.B) {

	nbMimcs := nbHashesBN256[4]

	var batchedMimc, witness bn256BatchMimc15
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bn256.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BN256, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**16
type bn256BatchMimc16 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bn256BatchMimc16) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBN256[5]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBN256BatchMimc16(b *testing.B) {

	nbMimcs := nbHashesBN256[5]

	var batchedMimc, witness bn256BatchMimc16
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bn256.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BN256, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**17
type bn256BatchMimc17 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bn256BatchMimc17) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBN256[6]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBN256BatchMimc17(b *testing.B) {

	nbMimcs := nbHashesBN256[6]

	var batchedMimc, witness bn256BatchMimc17
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bn256.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BN256, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}

// nb mimcs = 2**18
type bn256BatchMimc18 struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
}

func (batch *bn256BatchMimc18) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < nbHashesBN256[7]; i++ {
		result := mimc.Hash(cs, batch.Data[i])
		cs.AssertIsEqual(result, batch.ExpectedResult[i])
	}
	return nil
}

func BenchmarkBN256BatchMimc18(b *testing.B) {

	nbMimcs := nbHashesBN256[7]

	var batchedMimc, witness bn256BatchMimc18
	batchedMimc.ExpectedResult = make([]frontend.Variable, nbMimcs)
	batchedMimc.Data = make([]frontend.Variable, nbMimcs)
	witness.ExpectedResult = make([]frontend.Variable, nbMimcs)
	witness.Data = make([]frontend.Variable, nbMimcs)

	var sample fr_bn256.Element

	for j := 0; j < nbMimcs; j++ {
		sample.SetRandom() // so the multi exp is not trivial
		witness.ExpectedResult[j].Assign(sample)
		sample.SetRandom()
		witness.Data[j].Assign(sample)
	}

	r1cs, _ := frontend.Compile(gurvy.BN256, &batchedMimc)

	pk := groth16.DummySetup(r1cs)

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		groth16.ProveUnsafe(r1cs, pk, &witness) // <- the constraint system is not satisfied, but the full proving algo is performed
	}
}
