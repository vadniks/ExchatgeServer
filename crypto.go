
package main

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
    "github.com/jamesruan/sodium"
    "unsafe"
) // jamesruan/sodium doesn't have sodium_pad and sodium_unpad functions, here goes my favourite C!

const PublicKeySize uint = 32
const _MacSize uint = 16 // where the f*** is private modifier? Absence of the private modifier is so dumb, and I f***'n hate it!
const _NonceSize uint = 24 // consider anything that starts with an underscore is file-private
const _SessionKeySize = PublicKeySize

type CryptoState struct {
    blockSize uint
    unpaddedSize  uint
    _paddedSize   uint
    encryptedSize uint
    _sessionKeys sodium.KXKP
}

func newCryptoState(blockSize uint, unpaddedSize uint) *CryptoState {
    if blockSize == 0 || unpaddedSize == 0 { justThrow() } // where the f*** is throw keyword?

    dividend := unpaddedSize + 1 // where the f*** are runtime constants?
    paddedSize := blockSize * (dividend / blockSize +
        (func() uint { if dividend % blockSize > 0 { return 1 } else { return 0 } }())) // where the f*** is ternary operator?
    // The language designers won't give me the ternary operator? - Okay, I'll do it in creepy way!

    return &CryptoState{
        blockSize,
        unpaddedSize,
        paddedSize,
        paddedSize + _MacSize + _NonceSize,
        sodium.MakeKXKP(),
    }
}

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

func (state *CryptoState) encrypt(bytes []byte) []byte {
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
