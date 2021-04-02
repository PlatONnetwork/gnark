package main

import (
	"bytes"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/examples/cubic"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

// run this from /integration/solidity to regenerate files
// note: this is not in go generate format to avoid solc dependency in circleCI for now.
// go run contract/main.go && abigen --sol contract.sol --pkg solidity --out solidity.go
func main() {
	var circuit cubic.Circuit

	r1cs, err := frontend.Compile(gurvy.BN256, backend.GROTH16, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}
	{
		f, err := os.Create("cubic.vk")
		if err != nil {
			panic(err)
		}
		_, err = vk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}
	{
		f, err := os.Create("cubic.pk")
		if err != nil {
			panic(err)
		}
		_, err = pk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}

	{
		f, err := os.Create("contract.sol")
		if err != nil {
			panic(err)
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			panic(err)
		}

		f, err = os.Create("verify.hpp")
		if err != nil {
			panic(err)
		}
		err = vk.ExportWasm(f)
		if err != nil {
			panic(err)
		}
	}

	// create a valid proof
	var witness cubic.Circuit
	witness.X.Assign(3)
	witness.Y.Assign(35)
	proof, err := groth16.Prove(r1cs, pk, &witness)
	if err != nil {
		panic(err)
	}

	// get proof bytes
	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	// solidity contract inputs
	var (
		a     [2]*big.Int
		b     [2][2]*big.Int
		c     [2]*big.Int
		input [1]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	// public witness
	input[0] = new(big.Int).SetUint64(35)

	// print
	fmt.Println("a[0]:", a[0].String())
	fmt.Println("a[1]:", a[1].String())
	fmt.Println("b[0][0] :", b[0][0].String())
	fmt.Println("b[0][1] :", b[0][1].String())
	fmt.Println("b[1][0] :", b[1][0].String())
	fmt.Println("b[1][1] :", b[1][1].String())
	fmt.Println("c[0]:", c[0].String())
	fmt.Println("c[1]:", c[1].String())
	fmt.Println("input[0]:", input[0].String())

	err = groth16.Verify(proof, vk, &witness)
	if err != nil {
		panic(err)
	}
}
