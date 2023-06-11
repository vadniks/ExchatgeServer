
package crypto

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
    "ExchatgeServer/utils"
    "github.com/jamesruan/sodium"
    "unsafe"
)

const PublicKeySize uint = 32
const macSize uint = 16
const nonceSize uint = 24
const sessionKeySize = PublicKeySize

type crypto struct {
    blockSize uint
    unpaddedSize uint
    paddedSize uint
    encryptedSize uint
    serverKeys sodium.KXKP
}
var this *crypto

type KeyPair struct {
    Key1 []byte // public key or receive key
    Key2 []byte // secret key or send key
}

func PublicAndSecretKeys(publicKey []byte, secretKey []byte) *KeyPair { return &KeyPair{Key1: publicKey, Key2: secretKey} }
func SessionKeys(receiveKey []byte, sendKey []byte) *KeyPair { return &KeyPair{Key1: receiveKey, Key2: sendKey} }

func (keys *KeyPair) PublicKey() []byte { return keys.Key1 }
func (keys *KeyPair) SecretKey() []byte { return keys.Key2 }
func (keys *KeyPair) ReceiveKey() []byte { return keys.Key1 }
func (keys *KeyPair) SendKey() []byte { return keys.Key2 }

func GenerateServerKeys() *KeyPair {
    keys := sodium.MakeKXKP()
    return PublicAndSecretKeys(keys.PublicKey.Bytes, keys.SecretKey.Bytes)
}

func Initialize(serverKeys *KeyPair, blockSize uint, unpaddedSize uint) {
    utils.Assert(blockSize > 0 && unpaddedSize > 0)

    dividend := unpaddedSize + 1
    paddedSize := blockSize * (dividend / blockSize + 1)

    this = &crypto{
        blockSize,
        unpaddedSize,
        paddedSize,
        paddedSize + macSize + nonceSize,
        sodium.KXKP{
            PublicKey: sodium.KXPublicKey{Bytes: serverKeys.PublicKey()},
            SecretKey: sodium.KXSecretKey{Bytes: serverKeys.SecretKey()},
        },
    }
}

func GenerateSessionKeys(clientPublicKey []byte) *KeyPair {
    utils.Assert(len(clientPublicKey) == int(PublicKeySize))
    keys, err := this.serverKeys.ServerSessionKeys(sodium.KXPublicKey{Bytes: clientPublicKey})

    return func() *KeyPair {
        if err != nil { return nil } else { return SessionKeys(keys.Rx.Bytes, keys.Tx.Bytes) }
    }()
}

func Encrypt(sessionKeys *KeyPair, bytes []byte) []byte { return encrypt(addPadding(bytes), sessionKeys.SendKey()) }

func addPadding(bytes []byte) []byte {
    utils.Assert(uint(len(bytes)) == this.unpaddedSize)

    padded := make([]byte, this.paddedSize)
    copy(padded, bytes)

    var generatedPaddedSize uint64
    if C.sodium_pad(
        (*C.ulong) (&generatedPaddedSize),
        (*C.uchar) (&padded[0]),
        (C.ulong) (this.unpaddedSize),
        (C.ulong) (this.blockSize),
        (C.ulong) (this.paddedSize),
    ) != 0 { return nil }

    if generatedPaddedSize != uint64(this.paddedSize) { return nil }
    return padded
}

func encrypt(bytes []byte, key []byte) []byte {
    bytesLength := len(bytes)
    utils.Assert(uint(bytesLength) == this.paddedSize && len(key) == int(sessionKeySize))

    nonce := sodium.SecretBoxNonce{}
    sodium.Randomize(&nonce)

    ciphered := sodium.Bytes(bytes).SecretBox(nonce, sodium.SecretBoxKey{Bytes: key})
    encrypted := make([]byte, this.encryptedSize)

    copy(encrypted, ciphered)
    copy(unsafe.Slice(&(encrypted[uint(bytesLength) +macSize]), nonceSize), nonce.Bytes)

    return encrypted
}

func Decrypt(sessionKeys *KeyPair, bytes []byte) []byte { return removePadding(decrypt(bytes, sessionKeys.ReceiveKey())) }

func decrypt(bytes []byte, key []byte) []byte {
    bytesLength := len(bytes)
    utils.Assert(uint(bytesLength) == this.encryptedSize)

    encryptedWithoutNonceSize := this.encryptedSize - nonceSize

    nonce := sodium.SecretBoxNonce{Bytes: sodium.Bytes(bytes[encryptedWithoutNonceSize:])}
    boxKey := sodium.SecretBoxKey{Bytes: key}

    decrypted, err := sodium.Bytes(bytes[:encryptedWithoutNonceSize]).SecretBoxOpen(nonce, boxKey)
    if err == nil { return decrypted } else { return nil }
}

func removePadding(bytes []byte) []byte {
    utils.Assert(uint(len(bytes)) == this.paddedSize)

    padded := make([]byte, this.paddedSize)
    copy(padded, bytes)

    var generatedUnpaddedSize uint64
    if C.sodium_unpad(
        (*C.ulong) (&generatedUnpaddedSize),
        (*C.uchar) (&padded[0]),
        (C.ulong) (this.paddedSize),
        (C.ulong) (this.blockSize),
    ) != 0 { return nil }

    if generatedUnpaddedSize != uint64(this.unpaddedSize) { return nil }

    unpadded := make([]byte, this.unpaddedSize)
    copy(unpadded, padded[:this.unpaddedSize])

    return unpadded
}
