package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gurvy"
	bls381fr "github.com/consensys/gurvy/bls381/fr"
	bn256fr "github.com/consensys/gurvy/bn256/fr"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage is ./benchmark [nbHashes list]")
		os.Exit(-1)
	}
	ns := strings.Split(os.Args[1], ",")
	curveIDs := []gurvy.ID{gurvy.BN256, gurvy.BLS381}

	// write to stdout
	w := csv.NewWriter(os.Stdout)
	if err := w.Write(benchData{}.headers()); err != nil {
		panic(err)
	}

	for _, curveID := range curveIDs {
		for _, _n := range ns {
			n, err := strconv.Atoi(_n)
			if err != nil {
				panic(err)
			}
			// generate dummy circuit and solution
			pk, r1cs := generateCircuit(n, curveID)
			input := generateSolution(n, curveID)

			// measure proving time
			start := time.Now()
			// p := profile.Start(profile.TraceProfile, profile.ProfilePath("."), profile.NoShutdownHook)
			_, _ = groth16.ProveUnsafe(r1cs, pk, &input)
			// p.Stop()

			took := time.Since(start)

			// check memory usage, max ram requested from OS
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			bData := benchData{
				Curve:          curveID.String(),
				NbHashes:       n,
				NbCores:        runtime.NumCPU(),
				NbCoefficients: r1cs.GetNbCoefficients(),
				NbConstraints:  r1cs.GetNbConstraints(),
				NbWires:        r1cs.GetNbWires(),
				RunTime:        took.Milliseconds(),
				MaxRAM:         (m.Sys / 1024 / 1024),
				Throughput:     int(float64(r1cs.GetNbConstraints()) / took.Seconds()),
			}
			bData.ThroughputPerCore = bData.Throughput / bData.NbCores

			if err := w.Write(bData.values()); err != nil {
				panic(err)
			}
			w.Flush()
		}
	}

}

// // benchCircuit is a simple circuit that checks X*X*X*X*X... == Y
// type benchCircuit struct {
// 	X frontend.Variable
// 	Y frontend.Variable `gnark:",public"`
// 	n int
// }

type benchCircuit struct {
	ExpectedResult []frontend.Variable `gnark:"ExpectedHash,public"`
	Data           []frontend.Variable
	n              int // nb hashes
}

func (circuit *benchCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	for i := 0; i < circuit.n; i++ {
		result := mimc.Hash(cs, circuit.Data[i])
		cs.AssertIsEqual(result, circuit.ExpectedResult[i])
	}
	return nil
}

func generateCircuit(nbHashes int, curveID gurvy.ID) (groth16.ProvingKey, r1cs.R1CS) {
	var circuit benchCircuit
	circuit.n = nbHashes
	circuit.ExpectedResult = make([]frontend.Variable, nbHashes)
	circuit.Data = make([]frontend.Variable, nbHashes)

	r1cs, err := frontend.Compile(curveID, &circuit)
	if err != nil {
		panic(err)
	}

	// dummy setup will not compute a verifying key and just sets random value in the proving key
	pk := groth16.DummySetup(r1cs)
	return pk, r1cs
}

func generateSolution(nbHashes int, curveID gurvy.ID) (witness benchCircuit) {
	witness.n = nbHashes
	witness.ExpectedResult = make([]frontend.Variable, nbHashes)
	witness.Data = make([]frontend.Variable, nbHashes)

	switch curveID {
	case gurvy.BN256:
		var sample bn256fr.Element

		for j := 0; j < nbHashes; j++ {
			sample.SetRandom() // so the multi exp is not trivial
			witness.ExpectedResult[j].Assign(sample)
			sample.SetRandom()
			witness.Data[j].Assign(sample)
		}
	case gurvy.BLS381:
		var sample bls381fr.Element

		for j := 0; j < nbHashes; j++ {
			sample.SetRandom() // so the multi exp is not trivial
			witness.ExpectedResult[j].Assign(sample)
			sample.SetRandom()
			witness.Data[j].Assign(sample)
		}
	default:
		panic("not implemented")
	}

	return
}

type benchData struct {
	Curve             string
	NbHashes          int
	NbConstraints     int
	NbWires           int
	NbCoefficients    int
	MaxRAM            uint64
	RunTime           int64
	NbCores           int
	Throughput        int
	ThroughputPerCore int
}

func (bData benchData) headers() []string {
	return []string{"curve", "nbHashes", "nbConstraints", "nbWires", "nbCoefficients", "ram(mb)", "time(ms)", "nbCores", "throughput(constraints/s)", "througputPerCore(constraints/s)"}
}
func (bData benchData) values() []string {
	return []string{
		bData.Curve,
		strconv.Itoa(bData.NbHashes),
		strconv.Itoa(bData.NbConstraints),
		strconv.Itoa(bData.NbWires),
		strconv.Itoa(bData.NbCoefficients),
		strconv.Itoa(int(bData.MaxRAM)),
		strconv.Itoa(int(bData.RunTime)),
		strconv.Itoa(bData.NbCores),
		strconv.Itoa(bData.Throughput),
		strconv.Itoa(bData.ThroughputPerCore),
	}
}
