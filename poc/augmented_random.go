package main

import (
    "time"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/aes"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/cipher"
    "encoding/hex"
    "encoding/binary"
    "io"
    "fmt"
    "os"
    "golang.org/x/crypto/hkdf"
)

type WrappedRandom struct {
    tag string
    count uint64
    privateKey *rsa.PrivateKey
}

func extract(b []byte, n int) ([]byte, error) {
    hkdf := hkdf.New(sha256.New, b, nil, nil)
    output := make([]byte, n)
    _, err := io.ReadFull(hkdf, output)
    if err != nil {
        return nil, err
    }
    return output, nil
}

func stretch(key, nonce, output []byte) (error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    stream := cipher.NewCTR(block, nonce)
    stream.XORKeyStream(output, output)

    return nil
}

func (r *WrappedRandom) generateTags() (tag1, tag2 []byte) {
    tag1 = []byte(r.tag)
    tag2 = make([]byte, aes.BlockSize)
    binary.BigEndian.PutUint64(tag2, r.count)
    r.count += 1

    return tag1, tag2
}

func (r *WrappedRandom) sign(b []byte) (output []byte, err error) {
    h := sha256.New()
    h.Write(b)
    hashed := h.Sum(nil)

    signature, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA256, hashed[:])
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
        return nil, err
    }

    return signature, nil
}

func (r *WrappedRandom) signToDigest(b []byte) (output []byte, err error) {
    signature, err := r.sign(b)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
        return nil, err
    }

    h := crypto.SHA256.New()
    h.Write(signature)
    hashedSignature := h.Sum(nil)

    return hashedSignature, nil
}


func (r *WrappedRandom) Read(b []byte) (n int, err error) {
    tag1, tag2 := r.generateTags()
    signature, err := r.sign(tag1)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
        return 0, err
    }

    randomBuffer := make([]byte, 32)
    _, err = rand.Read(randomBuffer)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error sampling from PRNG: %s\n", err)
        return 0, err
    }

    // key = KDF(G(x) || Sig(sk, tag1))
    kdfInput := append(randomBuffer, signature...)
    key, err := extract(kdfInput, 32)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error extracting key: %s\n", err)
        return 0, err
    }

    // Encrypt input with derived key based on Sig(sk, tag1) and nonce based on tag2
    err = stretch(key, tag2, b)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating random output: %s\n", err)
        return 0, err
    }

    return len(b), nil
}

// PRF(KDF(G(x) || H(Sig(sk, tag1))), tag2)
func (r *WrappedRandom) GenerateRandomBytes() (output []byte, err error) {
    tag1, tag2 := r.generateTags()
    hashedSignature, err := r.signToDigest(tag1)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
        return nil, err
    }

    randomBuffer := make([]byte, 32)
    _, err = rand.Read(randomBuffer)
    // Note that err == nil only if we read len(b) bytes.
    if err != nil {
        return nil, err
    }

    kdfInput := append(randomBuffer, hashedSignature...)
    key, err := extract(kdfInput, 32)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error extracting randomness: %s\n", err)
        return nil, err
    }

    mac := hmac.New(sha256.New, key)
	mac.Write(tag2)
	output = mac.Sum(nil)

    return output, nil
}

func main() {
    reader := rand.Reader
	bitSize := 2048
    key, err := rsa.GenerateKey(reader, bitSize)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating private key: %s\n", err)
        panic(err)
    }

    random := WrappedRandom{"Device Info || Protocol Info", 0, key}

    fmt.Println("Native:")
    for i := 0; i < 10; i++ {
        start := time.Now()
        sample := make([]byte, 32)
        _, err := rand.Read(sample)
        elapsed := time.Since(start)
        if err != nil {
            fmt.Fprintf(os.Stderr, "rand.Read() error: %s\n", err)
            panic(err)
        }
        fmt.Printf("%s: %s\n", hex.EncodeToString(sample), elapsed)
    }

    fmt.Println("Construction #1:")
    for i := 0; i < 10; i++ {
        start := time.Now()
        sample, err := random.GenerateRandomBytes()
        elapsed := time.Since(start)
        if err != nil {
            fmt.Fprintf(os.Stderr, "random.GenerateRandomBytes() error: %s\n", err)
            panic(err)
        }
        fmt.Printf("%s: %s\n", hex.EncodeToString(sample), elapsed)
    }

    fmt.Println("Construction #2:")
    for i := 0; i < 10; i++ {
        start := time.Now()
        sample := make([]byte, 32)
        _, err := random.Read(sample)
        elapsed := time.Since(start)
        if err != nil {
            fmt.Fprintf(os.Stderr, "random.Read() error: %s\n", err)
            panic(err)
        }
        fmt.Printf("%s: %s\n", hex.EncodeToString(sample), elapsed)
    }
}
