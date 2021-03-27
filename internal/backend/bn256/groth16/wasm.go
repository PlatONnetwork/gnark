package groth16

const wasmTemplate = `
#pragma once
#include <vector>
#include <string_view>
#include "platon/crypto/bn256/bn256.hpp"

namespace platon {
namespace crypto {
namespace bn256 {
namespace g16 {

bool PairingProd4(const G1 &a1, const G2 &a2, const G1 &b1, const G2 &b2,
                  const G1 &c1, const G2 &c2, const G1 &d1, const G2 &d2) {
  std::array<G1, 4> g1{a1, b1, c1, d1};
  std::array<G2, 4> g2{a2, b2, c2, d2};
  return bn256::pairing(g1, g2) == 0;
}

class Verifier{
public:

    static constexpr std::uint256_t PRIME_Q = std::uint256_t(std::string_view("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"));
    static constexpr std::uint256_t SNARK_SCALAR_FIELD = std::uint256_t(std::string_view("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"));
    
    struct VerifyingKey{
        G1 alpha;
        G2 beta;
        G2 gamma;
        G2 delta;
        std::vector<G1> gamma_abc;
    };

    struct Proof{
        G1 a;
        G2 b;
        G1 c;
    };

    VerifyingKey GetVerifyingKey() {
        VerifyingKey vk;
        vk.alpha = G1("{{.G1.Alpha.X.String}}"_uint256, "{{.G1.Alpha.Y.String}}"_uint256);
        vk.beta = G2("{{.G2.Beta.X.A1.String}}"_uint256, "{{.G2.Beta.X.A0.String}}"_uint256, "{{.G2.Beta.Y.A1.String}}"_uint256, "{{.G2.Beta.Y.A0.String}}"_uint256);
        vk.gamma = G2("{{.G2.Gamma.X.A1.String}}"_uint256, "{{.G2.Gamma.X.A0.String}}"_uint256, "{{.G2.Gamma.Y.A1.String}}"_uint256, "{{.G2.Gamma.Y.A0.String}}"_uint256);
        vk.delta = G2("{{.G2.Delta.X.A1.String}}"_uint256, "{{.G2.Delta.X.A0.String}}"_uint256, "{{.G2.Delta.Y.A1.String}}"_uint256, "{{.G2.Delta.Y.A0.String}}"_uint256);
        {{- range $i, $ki := .G1.K }}   
		vk.gamma_abc.push_back(G1("{{$ki.X.String}}"_uint256, "{{$ki.Y.String}}"_uint256));
		{{- end}}

        return vk;
    }

	bool VerifyTx(const std::array<std::uint256_t, 2> &a, const std::array<std::array<std::uint256_t, 2>, 2> &b, 
			const std::array<std::uint256_t, 2> &c, const std::vector<std::uint256_t> &inputs){
		Proof proof{G1(a[0], a[1]), G2(b[0][0], b[0][1], b[1][0], b[1][1]), G1(c[0], c[1])};

		VerifyingKey vk = GetVerifyingKey();

		// Compute the linear combination vk_x
		G1 vk_x = G1{0, 0};

		// Make sure that every input is less than the snark scalar field
		int length = inputs.size();
		for (int i = 0; i < length; i++){
			if (inputs[i] > SNARK_SCALAR_FIELD) platon_revert();
            vk_x = Addition(vk_x, ScalarMul(vk.gamma_abc[i + 1], inputs[i]));
		}
		vk_x = Addition(vk_x, vk.gamma_abc[0]);

		// result
        return PairingProd4(proof.a, proof.b, Neg(vk_x), vk.gamma,
                               Neg(proof.c), vk.delta, Neg(vk.alpha), vk.beta);
	}
};

}  // namespace g16
}  // namespace bn256
}  // namespace crypto
}  // namespace platon
`
