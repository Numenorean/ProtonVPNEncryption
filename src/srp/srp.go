package srp

import (
	"bytes" //nolint[gosec]
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"

	"github.com/jameskeane/bcrypt"

	"golang.org/x/crypto/openpgp/clearsign"
)

//nolint[gochecknoglobals]
var (
	ErrDataAfterModulus = errors.New("pm-srp: extra data after modulus")
	RandReader          = rand.Reader
)

// ReadClearSignedMessage reads the clear text from signed message and verifies
// signature. There must be no data appended after signed message in input string.
// The message must be sign by key corresponding to `modulusPubkey`.
func ReadClearSignedMessage(signedMessage string) (string, error) {
	modulusBlock, rest := clearsign.Decode([]byte(signedMessage))
	if len(rest) != 0 {
		return "", ErrDataAfterModulus
	}

	return string(modulusBlock.Bytes), nil
}

// SrpProofs object
type SrpProofs struct { //nolint[golint]
	ClientProof, ClientEphemeral, ExpectedServerProof []byte
}

// SrpAuth stores byte data for the calculation of SRP proofs
type SrpAuth struct { //nolint[golint]
	Modulus, ServerEphemeral, HashedPassword []byte
}

// NewSrpAuth creates new SrpAuth from strings input. Salt and server ephemeral are in
// base64 format. Modulus is base64 with signature attached. The signature is
// verified against server key. The version controls password hash algorithm.
func NewSrpAuth(version int, username, password, salt, signedModulus, serverEphemeral string) (auth *SrpAuth, err error) {
	data := &SrpAuth{}

	// Modulus
	var modulus string
	modulus, err = ReadClearSignedMessage(signedModulus)
	if err != nil {
		return
	}
	data.Modulus, err = base64.StdEncoding.DecodeString(modulus)
	if err != nil {
		return
	}

	// Password
	var decodedSalt []byte
	if version >= 3 {
		decodedSalt, err = base64.StdEncoding.DecodeString(salt)
		if err != nil {
			return
		}
	}
	data.HashedPassword, err = HashPassword(version, password, username, decodedSalt, data.Modulus)
	if err != nil {
		return
	}

	// Server ephermeral
	data.ServerEphemeral, err = base64.StdEncoding.DecodeString(serverEphemeral)
	if err != nil {
		return
	}

	return data, nil
}

// GenerateSrpProofs calculates SPR proofs.
func (s *SrpAuth) GenerateSrpProofs(length int) (res *SrpProofs, err error) { //nolint[funlen]
	toInt := func(arr []byte) *big.Int {
		var reversed = make([]byte, len(arr))
		for i := 0; i < len(arr); i++ {
			reversed[len(arr)-i-1] = arr[i]
		}
		return big.NewInt(0).SetBytes(reversed)
	}

	fromInt := func(num *big.Int) []byte {
		var arr = num.Bytes()
		var reversed = make([]byte, length/8)
		for i := 0; i < len(arr); i++ {
			reversed[len(arr)-i-1] = arr[i]
		}
		return reversed
	}

	generator := big.NewInt(2)
	multiplier := toInt(ExpandHash(append(fromInt(generator), s.Modulus...)))

	modulus := toInt(s.Modulus)
	serverEphemeral := toInt(s.ServerEphemeral)
	hashedPassword := toInt(s.HashedPassword)

	modulusMinusOne := big.NewInt(0).Sub(modulus, big.NewInt(1))

	if modulus.BitLen() != length {
		return nil, errors.New("pm-srp: SRP modulus has incorrect size")
	}

	multiplier = multiplier.Mod(multiplier, modulus)

	if multiplier.Cmp(big.NewInt(1)) <= 0 || multiplier.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("pm-srp: SRP multiplier is out of bounds")
	}

	if generator.Cmp(big.NewInt(1)) <= 0 || generator.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("pm-srp: SRP generator is out of bounds")
	}

	if serverEphemeral.Cmp(big.NewInt(1)) <= 0 || serverEphemeral.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("pm-srp: SRP server ephemeral is out of bounds")
	}

	// Check primality
	// Doing exponentiation here is faster than a full call to ProbablyPrime while
	// still perfectly accurate by Pocklington's theorem
	if big.NewInt(0).Exp(big.NewInt(2), modulusMinusOne, modulus).Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("pm-srp: SRP modulus is not prime")
	}

	// Check safe primality
	if !big.NewInt(0).Rsh(modulus, 1).ProbablyPrime(10) {
		return nil, errors.New("pm-srp: SRP modulus is not a safe prime")
	}

	var clientSecret, clientEphemeral, scramblingParam *big.Int
	for {
		for {
			clientSecret, err = rand.Int(RandReader, modulusMinusOne)
			if err != nil {
				return
			}

			if clientSecret.Cmp(big.NewInt(int64(length*2))) > 0 { // Very likely
				break
			}
		}

		clientEphemeral = big.NewInt(0).Exp(generator, clientSecret, modulus)
		scramblingParam = toInt(ExpandHash(append(fromInt(clientEphemeral), fromInt(serverEphemeral)...)))
		if scramblingParam.Cmp(big.NewInt(0)) != 0 { // Very likely
			break
		}
	}

	subtracted := big.NewInt(0).Sub(serverEphemeral, big.NewInt(0).Mod(big.NewInt(0).Mul(big.NewInt(0).Exp(generator, hashedPassword, modulus), multiplier), modulus))
	if subtracted.Cmp(big.NewInt(0)) < 0 {
		subtracted.Add(subtracted, modulus)
	}
	exponent := big.NewInt(0).Mod(big.NewInt(0).Add(big.NewInt(0).Mul(scramblingParam, hashedPassword), clientSecret), modulusMinusOne)
	sharedSession := big.NewInt(0).Exp(subtracted, exponent, modulus)

	clientProof := ExpandHash(bytes.Join([][]byte{fromInt(clientEphemeral), fromInt(serverEphemeral), fromInt(sharedSession)}, []byte{}))
	serverProof := ExpandHash(bytes.Join([][]byte{fromInt(clientEphemeral), clientProof, fromInt(sharedSession)}, []byte{}))

	return &SrpProofs{ClientEphemeral: fromInt(clientEphemeral), ClientProof: clientProof, ExpectedServerProof: serverProof}, nil
}

func BCryptHash(password string, salt string) (string, error) {
	return bcrypt.Hash(password, salt)
}

// ExpandHash extends the byte data for SRP flow
func ExpandHash(data []byte) []byte {
	part0 := sha512.Sum512(append(data, 0))
	part1 := sha512.Sum512(append(data, 1))
	part2 := sha512.Sum512(append(data, 2))
	part3 := sha512.Sum512(append(data, 3))
	return bytes.Join([][]byte{
		part0[:],
		part1[:],
		part2[:],
		part3[:],
	}, []byte{})
}

// HashPassword returns the hash of password argument. Based on version number
// following arguments are used in addition to password:
// * 0, 1, 2: userName and modulus
// * 3, 4: salt and modulus
func HashPassword(authVersion int, password, userName string, salt, modulus []byte) ([]byte, error) {
	return hashPasswordVersion3(password, salt, modulus)
}

func hashPasswordVersion3(password string, salt, modulus []byte) (res []byte, err error) {
	encodedSalt := base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding).EncodeToString(append(salt, []byte("proton")...))
	crypted, err := BCryptHash(password, "$2a$10$"+encodedSalt)
	crypted = strings.Replace(crypted, "$2a", "$2y", 1)
	if err != nil {
		return
	}

	return ExpandHash(append([]byte(crypted), modulus...)), nil
}
