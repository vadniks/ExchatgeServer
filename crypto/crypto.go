
package crypto

import "C"
import (
    "ExchatgeServer/utils"
    "github.com/jamesruan/sodium"
    "unsafe"
)

const KeySize uint = 32
const macSize uint = 16
const nonceSize uint = 24
const HashSize uint = 128

//sodium.SignPublicKey{Bytes: []byte{255, 23, 21, 243, 148, 177, 186, 0, 73, 34, 173, 130, 234, 251, 83, 130, 138, 54, 215, 5, 170, 139, 175, 148, 71, 215, 74, 172, 27, 225, 26, 249}}, // goes to clients // TODO: embed public key into client's code
var signSecretKey = sodium.SignSecretKey{Bytes: []byte{211, 211, 189, 184, 216, 122, 65, 203, 37, 173, 133, 45, 240, 193, 227, 57, 78, 211, 86, 225, 75, 172, 30, 182, 194, 11, 249, 233, 74, 149, 198, 232, 255, 23, 21, 243, 148, 177, 186, 0, 73, 34, 173, 130, 234, 251, 83, 130, 138, 54, 215, 5, 170, 139, 175, 148, 71, 215, 74, 172, 27, 225, 26, 249}}

func GenerateServerKeys() ([]byte, []byte) {
    serverKeys := sodium.MakeKXKP()
    return serverKeys.PublicKey.Bytes, serverKeys.SecretKey.Bytes
}

func EncryptedSize(unencryptedSize uint) uint { return macSize + unencryptedSize + nonceSize }

func ExchangeKeys(serverPublicKey []byte, serverSecretKey []byte, clientPublicKey []byte) []byte { // returns nillable encryptionKey
    utils.Assert(
        len(serverPublicKey) == int(KeySize) &&
        len(serverSecretKey) == int(KeySize) &&
        len(clientPublicKey) == int(KeySize),
    )

    keys := sodium.KXKP{
        PublicKey: sodium.KXPublicKey{Bytes: serverPublicKey},
        SecretKey: sodium.KXSecretKey{Bytes: serverSecretKey},
    }
    sessionKeys, err := keys.ServerSessionKeys(sodium.KXPublicKey{Bytes: clientPublicKey})

    if err == nil {
        return sessionKeys.Rx.Bytes
    } else {
        return nil
    }
}

func Encrypt(bytes []byte, key []byte) []byte {
    bytesSize := uint(len(bytes))
    utils.Assert(bytesSize > 0 && uint(len(key)) == KeySize)

    nonce := sodium.SecretBoxNonce{}
    sodium.Randomize(&nonce)

    ciphered := sodium.Bytes(bytes).SecretBox(nonce, sodium.SecretBoxKey{Bytes: key})
    encrypted := make([]byte, EncryptedSize(bytesSize))

    copy(encrypted, ciphered)
    copy(unsafe.Slice(&(encrypted[bytesSize + macSize]), nonceSize), nonce.Bytes)

    return encrypted
}

func Decrypt(bytes []byte, key []byte) []byte {
    bytesSize := uint(len(bytes))
    utils.Assert(bytesSize > 0 && len(key) == int(KeySize))

    encryptedWithoutNonceSize := bytesSize - nonceSize

    nonce := sodium.SecretBoxNonce{Bytes: sodium.Bytes(bytes[encryptedWithoutNonceSize:])}
    boxKey := sodium.SecretBoxKey{Bytes: key}

    decrypted, err := sodium.Bytes(bytes[:encryptedWithoutNonceSize]).SecretBoxOpen(nonce, boxKey)
    if err == nil { return decrypted } else { return nil }
}

func Hash(bytes []byte) []byte {
    utils.Assert(len(bytes) > 0)
    return sodium.PWHashStore(string(bytes)).Value()
}

func CompareWithHash(hash []byte, unhashed []byte) bool {
    utils.Assert(len(hash) > 0 && len(unhashed) > 0)
    return sodium.LoadPWHashStr(hash).PWHashVerify(string(unhashed)) == nil
}

func SignMessage(bytes []byte) []byte {
    utils.Assert(len(bytes) > 0)
    return sodium.Bytes(bytes).Sign(signSecretKey)
}
