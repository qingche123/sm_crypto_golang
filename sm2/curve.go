/*
 * Package sm2 implements the Chinese SM2 Algorithm, according to "go/src/crypto/ecdsa".
 * author: weizhang <d5c5ceb0@gmail.com>
 * 2017.02.26
 */

package sm2

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var initonce sync.Once
var p256_sm2 *elliptic.CurveParams

func initAll() {
	initP256_sm2()
}

func initP256_sm2() {
	// See FIPS 186-3, section D.2.4
	p256_sm2 = &elliptic.CurveParams{Name: "SM2-P-256"}
	p256_sm2.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	p256_sm2.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	p256_sm2.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	p256_sm2.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	p256_sm2.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	p256_sm2.BitSize = 256
}

// P256_sm2 returns a Curve which implements sm2.
//
// The cryptographic operations are implemented using constant-time algorithms.
func P256_sm2() elliptic.Curve {
	initonce.Do(initAll)
	return p256_sm2
}
