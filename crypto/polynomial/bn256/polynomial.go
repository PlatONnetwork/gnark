// Copyright 2020 ConsenSys Software Inc.
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

package bn256

import (
	"github.com/consensys/gurvy/bn256/fr"
)

// Poly polynomial represented by coefficients bn256 fr field.
type Poly []fr.Element

// Degree returns the degree of the polynomial, which is the length of Data.
func (p Poly) Degree() uint64 {
	res := uint64(len(p) - 1)
	return res
}

// Eval evaluates p at v
func (p Poly) Eval(v interface{}) interface{} {
	var res, _v fr.Element
	_v.Set(v.(*fr.Element))
	s := len(p)
	res.Set(&p[s-1])
	for i := s - 2; i >= 0; i-- {
		res.Mul(&res, &_v)
		res.Add(&res, &p[i])
	}
	return &res
}