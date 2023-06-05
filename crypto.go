
package main

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C" // jamesruan/sodium doesn't have sodium_pad and sodium_unpad functions so the native implementation will be used directly

import (
    "github.com/jamesruan/sodium"
    "unsafe"
)

const PublicKeySize uint = 32
const _MacSize uint = 16 // where the f*** is private modifier? Absence of the private modifier is so dumb, and I f***in' hate it!
const _NonceSize uint = 24 // consider anything that starts with an underscore is file-private
const _SessionKeySize = PublicKeySize

type CryptoState struct {
    blockSize uint
    unpaddedSize uint
    _paddedSize uint
    encryptedSize uint
    _sessionKeys sodium.KXKP
}

func newCryptoState(blockSize uint, unpaddedSize uint) *CryptoState {
    if blockSize == 0 || unpaddedSize == 0 { justThrow() } // where the f*** is throw keyword?

    dividend := unpaddedSize + 1 // where the f*** are runtime constants?
    paddedSize := blockSize * (dividend / blockSize + 1)

    return &CryptoState{
        blockSize,
        unpaddedSize,
        paddedSize,
        paddedSize + _MacSize + _NonceSize,
        sodium.MakeKXKP(),
    }
}

func (state *CryptoState) encrypt(bytes []byte) []byte { return state._encrypt(state._addPadding(bytes)) } // TODO: test

func (state *CryptoState) _addPadding(bytes []byte) []byte {
    if uint(len(bytes)) != state.unpaddedSize { justThrow() }

    padded := make([]byte, state._paddedSize)
    copy(padded, bytes)

    var generatedPaddedSize uint64
    if C.sodium_pad(
        (*C.ulong) (&generatedPaddedSize),
        (*C.uchar) (&padded[0]),
        (C.ulong) (state.unpaddedSize),
        (C.ulong) (state.blockSize),
        (C.ulong) (state._paddedSize),
    ) != 0 { return nil }

    if generatedPaddedSize != uint64(state._paddedSize) { return nil }
    return padded
}

func (state *CryptoState) _encrypt(bytes []byte) []byte {
    bytesLength := len(bytes)
    if uint(bytesLength) != state._paddedSize { justThrow() }

    nonce := sodium.SecretBoxNonce{}
    sodium.Randomize(&nonce)

    ciphered := sodium.Bytes(bytes).SecretBox(nonce, sodium.SecretBoxKey(state._sessionKeys.SecretKey))
    encrypted := make([]byte, state.encryptedSize)

    copy(encrypted, ciphered)
    copy(unsafe.Slice(&(encrypted[bytesLength]), _NonceSize), nonce.Bytes)

    return encrypted
}

func (state *CryptoState) decrypt(bytes []byte) []byte { return state._removePadding(state._decrypt(bytes)) } // TODO: test

func (state *CryptoState) _decrypt(bytes []byte) []byte {
    bytesLength := len(bytes)
    if uint(bytesLength) != state.encryptedSize { justThrow() }

    encryptedWithoutNonceSize := state.encryptedSize - _NonceSize

    nonce := sodium.SecretBoxNonce{Bytes: sodium.Bytes(bytes[encryptedWithoutNonceSize:])}
    key := sodium.SecretBoxKey(state._sessionKeys.PublicKey)
    decrypted, err := sodium.Bytes(bytes[:encryptedWithoutNonceSize]).SecretBoxOpen(nonce, key)

    if err != nil { return decrypted } else { return nil }
}

func (state *CryptoState) _removePadding(bytes []byte) []byte {
    if uint(len(bytes)) != state._paddedSize { justThrow() }

    padded := make([]byte, state._paddedSize)
    copy(padded, bytes)

    var generatedUnpaddedSize uint64
    if C.sodium_unpad(
        (*C.ulong) (&generatedUnpaddedSize),
        (*C.uchar) (&padded[0]),
        (C.ulong) (state._paddedSize),
        (C.ulong) (state.blockSize),
    ) != 0 { return nil }

    if generatedUnpaddedSize != uint64(state.unpaddedSize) { return nil }

    unpadded := make([]byte, state.unpaddedSize)
    copy(unpadded, padded[:state.unpaddedSize])

    return unpadded
}
