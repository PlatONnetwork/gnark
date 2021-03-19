// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plonk

import (
	"github.com/consensys/gnark/crypto/polynomial"
	"github.com/consensys/gnark/frontend"

	mockcommitment_bls377 "github.com/consensys/gnark/crypto/polynomial/bls377/mock_commitment"
	mockcommitment_bls381 "github.com/consensys/gnark/crypto/polynomial/bls381/mock_commitment"
	mockcommitment_bn256 "github.com/consensys/gnark/crypto/polynomial/bn256/mock_commitment"
	mockcommitment_bw761 "github.com/consensys/gnark/crypto/polynomial/bw761/mock_commitment"

	backend_bls377 "github.com/consensys/gnark/internal/backend/bls377/cs"
	backend_bls381 "github.com/consensys/gnark/internal/backend/bls381/cs"
	backend_bn256 "github.com/consensys/gnark/internal/backend/bn256/cs"
	backend_bw761 "github.com/consensys/gnark/internal/backend/bw761/cs"

	plonkbls377 "github.com/consensys/gnark/internal/backend/bls377/plonk"
	plonkbls381 "github.com/consensys/gnark/internal/backend/bls381/plonk"
	plonkbn256 "github.com/consensys/gnark/internal/backend/bn256/plonk"
	plonkbw761 "github.com/consensys/gnark/internal/backend/bw761/plonk"

	bls377witness "github.com/consensys/gnark/internal/backend/bls377/witness"
	bls381witness "github.com/consensys/gnark/internal/backend/bls381/witness"
	bn256witness "github.com/consensys/gnark/internal/backend/bn256/witness"
	bw761witness "github.com/consensys/gnark/internal/backend/bw761/witness"
)

// PublicData contains
// * polynomials corresponding to the coefficients ql,qr,qm,qo,qk (either raw or committed)
// * polynomials corresponding to the permutations s1,s2,s3 (either raw or committed)
// * the commitment scheme
// * the fft domains
type PublicData interface{}

// Proof contains a plonk proof. The content of the proof might vary according
// to the plonk version which is chosen.
// For instance it can be the commitments of L,R,O,H,Z and the opening proofs.
type Proof interface{}

// Setup prepares the public data associated to a circuit + public inputs.
func Setup(sparseR1cs frontend.CompiledConstraintSystem, polynomialCommitment polynomial.CommitmentScheme, publicWitness frontend.Circuit) (PublicData, error) {

	switch _sparseR1cs := sparseR1cs.(type) {
	case *backend_bn256.SparseR1CS:
		w := bn256witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		publicData := plonkbn256.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bls381.SparseR1CS:
		w := bls381witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		publicData := plonkbls381.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bls377.SparseR1CS:
		w := bls377witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		publicData := plonkbls377.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bw761.SparseR1CS:
		w := bw761witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		publicData := plonkbw761.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	default:
		panic("unrecognized R1CS curve type")
	}

}

// SetupDummyCommitment is used for testing purposes, it sets up public data with dummy polynomial commitment scheme.
func SetupDummyCommitment(sparseR1cs frontend.CompiledConstraintSystem, publicWitness frontend.Circuit) (PublicData, error) {

	switch _sparseR1cs := sparseR1cs.(type) {
	case *backend_bn256.SparseR1CS:
		w := bn256witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		polynomialCommitment := &mockcommitment_bn256.Scheme{}
		publicData := plonkbn256.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bls381.SparseR1CS:
		w := bls381witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		polynomialCommitment := &mockcommitment_bls381.Scheme{}
		publicData := plonkbls381.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bls377.SparseR1CS:
		w := bls377witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		polynomialCommitment := &mockcommitment_bls377.Scheme{}
		publicData := plonkbls377.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	case *backend_bw761.SparseR1CS:
		w := bw761witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return nil, err
		}
		polynomialCommitment := &mockcommitment_bw761.Scheme{}
		publicData := plonkbw761.SetupRaw(_sparseR1cs, polynomialCommitment, w)
		return publicData, nil

	default:
		panic("unrecognized R1CS curve type")
	}

}

// Prove generates plonk proof from a circuit, associated preprocessed public data, and the witness
func Prove(sparseR1cs frontend.CompiledConstraintSystem, publicData PublicData, fullWitness frontend.Circuit) (Proof, error) {

	switch _sparseR1cs := sparseR1cs.(type) {
	case *backend_bn256.SparseR1CS:
		_publicData := publicData.(*plonkbn256.PublicRaw)
		w := bn256witness.Witness{}
		if err := w.FromFullAssignment(fullWitness); err != nil {
			return nil, err
		}
		proof := plonkbn256.ProveRaw(_sparseR1cs, _publicData, w)
		return proof, nil

	case *backend_bls381.SparseR1CS:
		_publicData := publicData.(*plonkbls381.PublicRaw)
		w := bls381witness.Witness{}
		if err := w.FromFullAssignment(fullWitness); err != nil {
			return nil, err
		}
		proof := plonkbls381.ProveRaw(_sparseR1cs, _publicData, w)
		return proof, nil

	case *backend_bls377.SparseR1CS:
		_publicData := publicData.(*plonkbls377.PublicRaw)
		w := bls377witness.Witness{}
		if err := w.FromFullAssignment(fullWitness); err != nil {
			return nil, err
		}
		proof := plonkbls377.ProveRaw(_sparseR1cs, _publicData, w)
		return proof, nil

	case *backend_bw761.SparseR1CS:
		_publicData := publicData.(*plonkbw761.PublicRaw)
		w := bw761witness.Witness{}
		if err := w.FromFullAssignment(fullWitness); err != nil {
			return nil, err
		}
		proof := plonkbw761.ProveRaw(_sparseR1cs, _publicData, w)
		return proof, nil

	default:
		panic("unrecognized R1CS curve type")
	}
}

// Verify verifies a plonk proof, from the proof, preprocessed public data, and public witness.
func Verify(proof Proof, publicData PublicData, publicWitness frontend.Circuit) error {

	switch _proof := proof.(type) {

	case *plonkbn256.ProofRaw:
		_publicData := publicData.(*plonkbn256.PublicRaw)
		w := bn256witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return err
		}
		return plonkbn256.VerifyRaw(_proof, _publicData, w)

	case *plonkbls381.ProofRaw:
		_publicData := publicData.(*plonkbls381.PublicRaw)
		w := bls381witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return err
		}
		return plonkbls381.VerifyRaw(_proof, _publicData, w)

	case *plonkbls377.ProofRaw:
		_publicData := publicData.(*plonkbls377.PublicRaw)
		w := bls377witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return err
		}
		return plonkbls377.VerifyRaw(_proof, _publicData, w)

	case *plonkbw761.ProofRaw:
		_publicData := publicData.(*plonkbw761.PublicRaw)
		w := bw761witness.Witness{}
		if err := w.FromPublicAssignment(publicWitness); err != nil {
			return err
		}
		return plonkbw761.VerifyRaw(_proof, _publicData, w)

	default:
		panic("unrecognized proof type")
	}

	return nil
}