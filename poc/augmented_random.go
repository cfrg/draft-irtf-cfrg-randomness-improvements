package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/cipher"
    "encoding/hex"
    "golang.org/x/crypto/hkdf"
    "encoding/base64"
)

type WrappedRandom struct {
    tag string
    count uint64
    privateKey *rsa.PrivateKey
}

func extract(b []byte, n int) ([]byte, error) {
    hkdf := hkdf.New(hash.sha256.New, b, nil, nil)
    output := make([]byte, n)
    _, err := io.ReadFull(hkdf, output)
    if err != nil {
        return nil, err
    }
    return output, nil
}

func stretch(key, nonce, output []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    stream := cipher.NewCTR(block, nonce)
    stream.XORKeyStream(output, output)

    return output, nil
}

func (r *WrappedRandom) Read(b []byte) (n int, err error) {
    // PRF(KDF(G(x) || H(Sig(sk, tag1))), tag2)
    tag1 := r.tag
    tag2 := string(r.count)
    r.count += 1

    h := sha256.New()
	h.Write(tag1)
	hashed := h.Sum(nil)

    signature, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA256, hashed[:])
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
        return 0, err
    }

    randomBuffer := make([]byte, len(b))
    _, err := rand.Read(randomBuffer)
    // Note that err == nil only if we read len(b) bytes.
    if err != nil {
        return 0, err
    }

    // TODO(caw): `signature` may be cached now

    h := crypto.SHA256.New()
    h.Write(signature)
    hashedSignature := h.Sum(nil)

    kdfInput := append(randomBuffer, hashedSignature)
    key, err := extract(kdfInput, 32)
    if err != nil {
        fmt.Printf(os.Stderr, "Error extracting randomness: %s\n", err)
        return 0, err
    }

    mac := hmac.New(sha256.New, key)
	mac.Write(tag2)
	output := mac.Sum(nil)

    return len(output), output
}

/*
func GenerateRandomBytes(n int) ([]byte, error) {
    b := make([]byte, n)
    _, err := rand.Read(b)
    if err != nil {
        return nil, err
    }

    return b, nil
}
*/

func main() {
    reader := rand.Reader
	bitSize := 2048
    key, err := rsa.GenerateKey(reader, bitSize)
    if err != nil {
        fmt.Printf(os.Stderr, "Error generating private key: %s\n", err)
        return -1
    }

    random := WrappedRandom{"Device Info || Protocol Info", 0, key}

    for i := 0; i < 10; i++ {
        tmpBuffer := make([]byte, 32)
        output, err := random.Read(tmpBuffer)
        if err != nil {
            fmt.Printf("Error generating random bytes: %s\n", err)
            return -1
        }
        fmt.Printf("%s\n", hex.EncodeToString(output))
    }
}
