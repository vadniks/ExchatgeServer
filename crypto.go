
package main

import "errors"

const PublicKeySize uint = 32
const MacSize uint = 16 // where the f*** is private modifier?
const NonceSize uint = 24

type CryptoState struct {
    blockSize uint
    unpaddedSize uint
    paddedSize uint
    encryptedSize uint
}

func newCryptState(blockSize uint, unpaddedSize uint) *CryptoState {
    if blockSize == 0 || unpaddedSize == 0 { _ = errors.New("") } // where the f*** is throw keyword?

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
