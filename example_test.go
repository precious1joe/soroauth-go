package soroauth

import (
	"context"
	"fmt"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// ExampleDecodeAuthorizationEntry shows the entry point for a base64 entry that
// came from somewhere else. The limits it applies are documented on the
// function and on MaxDecodeDepth and MaxDecodeInputBytes.
func ExampleDecodeAuthorizationEntry() {
	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}
	var key xdr.Uint256
	key[0] = 1
	accountID := xdr.AccountId{
		Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
		Ed25519: &key,
	}
	address := xdr.ScAddress{
		Type:      xdr.ScAddressTypeScAddressTypeAccount,
		AccountId: &accountID,
	}

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   address,
				Nonce:                     7,
				SignatureExpirationLedger: 100,
				Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: &contractID,
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		fmt.Println("encode:", err)
		return
	}

	decoded, err := DecodeAuthorizationEntry(encoded)
	if err != nil {
		fmt.Println("decode:", err)
		return
	}

	info, err := Inspect(decoded)
	if err != nil {
		fmt.Println("inspect:", err)
		return
	}
	fmt.Printf("%s nonce=%d expires=%d function=%s\n",
		info.CredentialType, info.Nonce, info.ValidUntilLedger, info.RootFunction)

	// Output: address_v2 nonce=7 expires=100 function=transfer
}

// ExampleNewPasskeySigner shows how to configure a passkey signer with required
// user presence (UP) and user verification (UV) flags to enforce hardware or biometric
// authorization constraints before signing a Soroban authorization entry.
func ExampleNewPasskeySigner() {
	// A dummy 37-byte authenticator data block where flag 0x01 (UP) and 0x04 (UV) are set.
	authData := make([]byte, 37)
	authData[32] = 0x05

	signer := NewPasskeySigner(
		"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
		authData,
		func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			return scBytes([]byte("mock-webauthn-signature")), nil
		},
		RequireUserPresence(true),
		RequireUserVerification(true),
	)

	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: signer address: GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
}

// ExampleVerifyAll shows how to verify a batch of authorization entries
// concurrently with custom configuration and per-entry reporting.
func ExampleVerifyAll() {
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		},
	}

	results, err := VerifyAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry}, network.TestNetworkPassphrase, WithConcurrency(2))
	if err != nil {
		fmt.Println("verify error:", err)
		return
	}

	for _, res := range results {
		fmt.Printf("entry %d address=%q err=%v\n", res.Index, res.Address, res.Error)
		break
	}

	// Output: entry 0 address="" err=<nil>
}
