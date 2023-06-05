
package main

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C" // jamesruan/sodium doesn't have sodium_pad and sodium_unpad functions, here goes my favourite C!

const PublicKeySize uint = 32
const MacSize uint = 16 // where the f*** is private modifier?
const NonceSize uint = 24

type CryptoState struct {
    blockSize uint
    unpaddedSize uint
    paddedSize uint
    encryptedSize uint
}

func newCryptoState(blockSize uint, unpaddedSize uint) *CryptoState {
    if blockSize == 0 || unpaddedSize == 0 { throw("") } // where the f*** is throw keyword?

    dividend := unpaddedSize + 1 // where the f*** are runtime constants?
    paddedSize := blockSize * (dividend / blockSize +
        (func() uint { if dividend % blockSize > 0 { return 1 } else { return 0 } }())) // where the f*** is ternary operator?
    // The language designers won't give me the ternary operator? - Okay, I'll do it in creepy way!

    return &CryptoState{
        blockSize,
        unpaddedSize,
        paddedSize,
        paddedSize + MacSize + NonceSize,
    }
}

func (state *CryptoState) addPadding(bytes []byte) []byte {
   padded := make([]byte, state.paddedSize)
   copy(padded, bytes)

   var generatedPaddedSize uint64
   if C.sodium_pad(
       (*C.ulong) (&generatedPaddedSize),
       (*C.uchar) (&padded[0]),
       (C.ulong) (state.unpaddedSize),
       (C.ulong) (state.blockSize),
       (C.ulong) (state.paddedSize),
   ) != 0 { return nil }

   if generatedPaddedSize != uint64(state.paddedSize) { return nil }
   return padded
}
