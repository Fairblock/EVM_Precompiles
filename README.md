# Decryption Precompiles for EVM Chains

To make on‑chain decryption effortless, we provide decryption precompiles that can be integrated into EVM chains.
The precompiles allow developers and traditional EVM smart contracts to integrate with Fairblock FairyRing network, thus unlocking the power of a dynamic confidentiality network.
Our IBE scheme runs on the pairing‑friendly BLS12‑381 curve which is used for Ethereum staking signatures, many SNARK systems, and other cryptographic protocols. Therefore, having BLS12‑381 precompiles allows applications to perform fast and gas‑efficient cryptographic operations on chain.


## Steps To add the precompiles to an EVM chain
We provide decryption precompiles in both Go and Rust which can be added to the base EVM code along with the rest of the precompiles.
### Rust Precompiles
For the Rust based chains, we have our decryption code written in Rust so it can be deployed as a precompile by adding it along with the rest of the precompiles in the client code.

### Golang Precompiles
For chains using go-ethereum, the Go version of our precompiles should be added to `core/vm/contracts.go`. Below are the required changes:

</details>

* Add in the necessary imports for the encrypted package.

```go
import (
   "bytes"
   enc "github.com/FairBlock/DistributedIBE/encryption"
   bls "github.com/drand/kyber-bls12381"
)
```

* Add the `decrypt()` function to the file by simply copying and pasting the below at the bottom of the file.

```go
func (c *decryption) decrypt(privateKeyByte []byte, cipherBytes []byte, id string) ([]byte, error) {
	
	suite := bls.NewBLS12381Suite()
	privateKeyPoint := suite.G2().Point()

	err := privateKeyPoint.UnmarshalBinary(privateKeyByte)
	if err != nil {
		return []byte("Decrypt: Error unmarshalling private key"), err
	}

	pkPoint := suite.G1().Point()
	err = pkPoint.UnmarshalBinary(c.pk)
	if err != nil {
		return []byte("Decrypt: Error unmarshalling stored public key"), err
	}

	hG2, ok := suite.G2().Point().(kyber.HashablePoint)
	if !ok {
		return []byte("Decrypt: Invalid point"), err
	}
	idByte := []byte(id)
	Qid := hG2.Hash(idByte)

	p1 := suite.Pair(pkPoint, Qid)
	p2 := suite.Pair(suite.G1().Point().Base(), privateKeyPoint)

	if !p1.Equal(p2) {
		return []byte("Decrypt: Invalid private key"), err
	}

	var destPlainText bytes.Buffer
	var cipherBuffer bytes.Buffer
	_, err = cipherBuffer.Write(cipherBytes)
	if err != nil {
		return []byte("Decrypt: Error reading ciphertext"), err
	}

	err = enc.Decrypt(privateKeyPoint, privateKeyPoint, &destPlainText, &cipherBuffer)
	if err != nil {
		return []byte("Decrypt: Decryption error"), err
	}

	return destPlainText.Bytes(), nil
}
```

* Add the decryption structures by copying and pasting the below to the bottom of the `contracts.go` file as well. Make sure to replace the required gas amount with the desired value.

```go
type decryption struct {
	pk []byte
}

func (c *decryption) Get() ([]byte, error) {
	return c.pk, nil
}

func (c *decryption) Set(_pk []byte) (bool, error) {
	suite := bls.NewBLS12381Suite()
	pkPoint := suite.G1().Point()

	// Unmarshal the public key
	err := pkPoint.UnmarshalBinary(_pk)
	if err != nil {
		return false, err
	}

	// Store the public key
	c.pk = _pk

	return true, nil
}

func (c *decryption) RequiredGas(input []byte) uint64 {
    // Replace this with the desired value
	return <Required_Gas_Amount>
}

func (c *decryption) Run(input []byte) ([]byte, error) {
	// Determine the method to execute based on the first byte
	switch input[0] {
	case 0x01: // Call the Set method
		pk := input[1:] // extract public key from input
		success, err := c.Set(pk)
		if err != nil {
			return nil, err
		}
		if success {
			return []byte{0x01}, nil
		}
		return []byte{0x00}, nil

	case 0x02: // Call the Get method
		return c.Get()

	case 0x03: // Call the Decrypt method

		// Extract the private key (first 96 bytes)
		if len(input) < 97 {
			return nil, fmt.Errorf("input too short, missing private key")
		}
		privateKeyByte := input[1:97]
		input = input[97:]

		// Extract the length of the ciphertext (next 4 bytes)
		if len(input) < 4 {
			return nil, fmt.Errorf("input too short, missing ciphertext length")
		}
		cipherLength := binary.BigEndian.Uint32(input[:4])
		input = input[4:]

		// Extract the length of the id (next 4 bytes)
		if len(input) < 4 {
			return nil, fmt.Errorf("input too short, missing id length")
		}
		idLength := binary.BigEndian.Uint32(input[:4])
		input = input[4:]

		if len(input) < int(cipherLength+idLength) {
			return nil, fmt.Errorf("input too short for the provided ciphertext and id lengths")
		}

		// Extract the ciphertext and id
		cipherBytes := input[:cipherLength]
		id := string(input[cipherLength : cipherLength+idLength])

		return c.decrypt(privateKeyByte, cipherBytes, id)

	default:
		return nil, fmt.Errorf("invalid method selector")
	}
}
```

* Add decryption to the appropriate `PrecompiledContract` vars: `PrecompiledContractsIstanbul`, `PrecompiledContractsBerlin`, `PrecompiledContractsCancun`. Simply paste the following into the respective `PrecompiledContract` vars 

```go
 common.BytesToAddress([]byte{0x94}):&decryption{},
```
Below is the summary of how this precompile works:

- The `decrypt()`function
  - For all of the precompiles, there’s an entry point, the RUN function at the bottom.
  - This function routes the call based on the first byte of the inputs. There are three functionalities. One to set the public key in the precompile, One to get the public key, and one to perform the decryption. 
  - In case of the decryption, the inputs are concatenated together: the first 96 bytes is the decryption key. The next 8 bytes include the length of the ciphertext and the identity. And the rest is the concatenation of the ciphertext and identity.
  - DistributedIBE is the library that provides the ibe decryption function.
- The precompile address will be `0x94` as established in the respective `PrecompileContract`.
