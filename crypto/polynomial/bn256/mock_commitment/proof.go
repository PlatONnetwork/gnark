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

package mockcommitment

import (
	"io"
)

// MockProof empty struct
type MockProof struct{}

// WriteTo mock impementation
func (mp *MockProof) WriteTo(w io.Writer) (n int64, err error) {
	return 0, nil
}

// ReadFrom mock impementation
func (mp *MockProof) ReadFrom(r io.Reader) (n int64, err error) {
	return 0, nil
}