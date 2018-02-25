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
    tag []byte
    count uint64
    privateKey *rsa.PrivateKey
    signature []byte
}

func NewWrappedRandom(info string, key *rsa.PrivateKey) *WrappedRandom {
    return &WrappedRandom{[]byte(info), 0, key, nil}
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

func (r *WrappedRandom) generateNonce() (tag []byte) {
    tag = make([]byte, aes.BlockSize)
    binary.BigEndian.PutUint64(tag, r.count)
    r.count += 1

    return tag
}

func (r *WrappedRandom) produceSignature() (output []byte, err error) {
    if r.signature != nil {
        return r.signature, nil
    }

    h := sha256.New()
    h.Write(r.tag)
    hashed := h.Sum(nil)

    r.signature, err = rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA256, hashed[:])
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
        return nil, err
    }

    return r.signature, nil
}

func (r *WrappedRandom) produceSignatureDigest() (output []byte, err error) {
    signature, err := r.produceSignature()
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
    nonce := r.generateNonce()
    signature, err := r.produceSignature()
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
    err = stretch(key, nonce, b)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating random output: %s\n", err)
        return 0, err
    }

    return len(b), nil
}

// PRF(KDF(G(x) || H(Sig(sk, tag1))), tag2)
func (r *WrappedRandom) GenerateRandomBytes() (output []byte, err error) {
    tag := r.generateNonce()
    hashedSignature, err := r.produceSignatureDigest()
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
	mac.Write(tag)
	output = mac.Sum(nil)

    return output, nil
}

func main() {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating private key: %s\n", err)
        panic(err)
    }

    // Use the native wrapper 
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

    random1 := NewWrappedRandom("Device Info || Protocol Info", privateKey)
    fmt.Println("Construction #1:")
    for i := 0; i < 10; i++ {
        start := time.Now()
        sample, err := random1.GenerateRandomBytes()
        elapsed := time.Since(start)
        if err != nil {
            fmt.Fprintf(os.Stderr, "random.GenerateRandomBytes() error: %s\n", err)
            panic(err)
        }
        fmt.Printf("%s: %s\n", hex.EncodeToString(sample), elapsed)
    }

    random2 := NewWrappedRandom("Device Info || Protocol Info", privateKey)
    fmt.Println("Construction #2:")
    for i := 0; i < 10; i++ {
        start := time.Now()
        sample := make([]byte, 32)
        _, err := random2.Read(sample)
        elapsed := time.Since(start)
        if err != nil {
            fmt.Fprintf(os.Stderr, "random.Read() error: %s\n", err)
            panic(err)
        }
        fmt.Printf("%s: %s\n", hex.EncodeToString(sample), elapsed)
    }
}
