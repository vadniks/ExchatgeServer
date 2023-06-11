
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
var this *crypto

type crypto struct {
    blockSize uint
    unpaddedSize uint
    paddedSize uint
    encryptedSize uint
    sessionKeys sodium.KXKP
}

func Initialize(blockSize uint, unpaddedSize uint) {
    if blockSize == 0 || unpaddedSize == 0 { utils.JustThrow() }

    dividend := unpaddedSize + 1
    paddedSize := blockSize * (dividend / blockSize + 1)

    this = &crypto{
        blockSize,
        unpaddedSize,
        paddedSize,
        paddedSize + macSize + nonceSize,
        sodium.MakeKXKP(),
    }
}

func Encrypt(bytes []byte) []byte { return encrypt(addPadding(bytes)) }

func addPadding(bytes []byte) []byte {
    if uint(len(bytes)) != this.unpaddedSize { utils.JustThrow() }

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

func encrypt(bytes []byte) []byte {
    bytesLength := len(bytes)
    if uint(bytesLength) != this.paddedSize { utils.JustThrow() }

    nonce := sodium.SecretBoxNonce{}
    sodium.Randomize(&nonce)

    ciphered := sodium.Bytes(bytes).SecretBox(nonce, sodium.SecretBoxKey{Bytes: this.sessionKeys.SecretKey.Bytes})
    encrypted := make([]byte, this.encryptedSize)

    copy(encrypted, ciphered)
    copy(unsafe.Slice(&(encrypted[uint(bytesLength) +macSize]), nonceSize), nonce.Bytes)

    return encrypted
}

func Decrypt(bytes []byte) []byte { return removePadding(decrypt(bytes)) }

func decrypt(bytes []byte) []byte {
    bytesLength := len(bytes)
    if uint(bytesLength) != this.encryptedSize { utils.JustThrow() }

    encryptedWithoutNonceSize := this.encryptedSize - nonceSize

    nonce := sodium.SecretBoxNonce{Bytes: sodium.Bytes(bytes[encryptedWithoutNonceSize:])}
    key := sodium.SecretBoxKey{Bytes: this.sessionKeys.SecretKey.Bytes}

    decrypted, err := sodium.Bytes(bytes[:encryptedWithoutNonceSize]).SecretBoxOpen(nonce, key)
    if err == nil { return decrypted } else { return nil }
}

func removePadding(bytes []byte) []byte {
    if uint(len(bytes)) != this.paddedSize { utils.JustThrow() }

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
