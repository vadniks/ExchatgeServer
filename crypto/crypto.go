
package crypto

import (
    "ExchatgeServer/utils"
    "bytes"
    "github.com/jamesruan/sodium"
    "unsafe"
)

const KeySize uint = 32
const HeaderSize uint = 24
const encryptedAdditionalBytesSize = 17
const macSize uint = 16
const nonceSize uint = 24
const HashSize uint = 128
const SignatureSize uint = 64
const intSize = 4
const tokenUnencryptedValueSize = 2 * intSize // 8
const tokenTrailingSize uint = 16
const TokenSize = tokenUnencryptedValueSize + 40 + tokenTrailingSize // 48 + 16 = 64 = 2 encrypted ints + mac + nonce + missing bytes to reach signatureSize so the server can tokenize itself via signature whereas for clients server encrypts 2 ints (connectionId, userId)

type Crypto struct {
    encoderBuffer *bytes.Buffer
    decoderBuffer *bytes.Buffer
    encoder sodium.SecretStreamEncoder
    decoder sodium.SecretStreamDecoder
}

var signSecretKey = sodium.SignSecretKey{Bytes: []byte{
    211, 211, 189, 184, 216, 122, 65, 203,
    37, 173, 133, 45, 240, 193, 227, 57,
    78, 211, 86, 225, 75, 172, 30, 182,
    194, 11, 249, 233, 74, 149, 198, 232,
    255, 23, 21, 243, 148, 177, 186, 0,
    73, 34, 173, 130, 234, 251, 83, 130,
    138, 54, 215, 5, 170, 139, 175, 148,
    71, 215, 74, 172, 27, 225, 26, 249,
}}

var tokenEncryptionKey = func() []byte {
    key := new(sodium.SecretBoxKey)
    sodium.Randomize(key)
    utils.Assert(len(key.Bytes) == int(KeySize))
    return key.Bytes
}()

func GenerateServerKeys() ([]byte, []byte) {
    serverKeys := sodium.MakeKXKP()
    return serverKeys.PublicKey.Bytes, serverKeys.SecretKey.Bytes
}

func EncryptedSize(unencryptedSize uint) uint { return unencryptedSize + encryptedAdditionalBytesSize }
func SignedSize(unsignedSize uint) uint { return unsignedSize + SignatureSize }

func ExchangeKeys(serverPublicKey []byte, serverSecretKey []byte, clientPublicKey []byte) ([]byte, []byte) { // returns nillable serverKey & clientKey
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
        return sessionKeys.Rx.Bytes, sessionKeys.Tx.Bytes
    } else {
        return nil, nil
    }
}

func CreateEncoderStream(serverKey []byte) ([]byte, *Crypto) { // returns server stream header
    utils.Assert(len(serverKey) == int(KeySize))

    encoderBuffer := new(bytes.Buffer)
    crypto := &Crypto{
        encoderBuffer,
        new(bytes.Buffer),
        sodium.MakeSecretStreamXCPEncoder(sodium.SecretStreamXCPKey{Bytes: serverKey}, encoderBuffer),
        nil,
    }

    return crypto.encoder.Header().Bytes, crypto
}

func (crypto *Crypto) CreateDecoderStream(clientKey []byte, clientStreamHeader []byte) bool { // returns true on success
    utils.Assert(len(clientKey) == int(KeySize) && len(clientStreamHeader) == int(HeaderSize))

    var err error
    crypto.decoder, err = sodium.MakeSecretStreamXCPDecoder(
        sodium.SecretStreamXCPKey{Bytes: clientKey},
        crypto.decoderBuffer,
        sodium.SecretStreamXCPHeader{Bytes: clientStreamHeader},
    )
    return err == nil
}

func (crypto *Crypto) Encrypt(bytes []byte) []byte { // nillable result
    bytesSize := uint(len(bytes))
    utils.Assert(bytesSize > 0 && crypto.encoder != nil && crypto.decoder != nil)

    writtenCount, err := crypto.encoder.Write(bytes)
    if writtenCount != int(bytesSize) || err != nil { return nil }

    encrypted := make([]byte, EncryptedSize(bytesSize))
    writtenCount, err = crypto.encoderBuffer.Read(encrypted)
    if writtenCount != int(bytesSize) || err != nil { return nil }

    return encrypted
}

func (crypto *Crypto) Decrypt(bytes []byte) []byte {
    bytesSize := uint(len(bytes))
    utils.Assert(bytesSize > 0 && crypto.encoder != nil && crypto.decoder != nil)
    crypto.decoderBuffer.Write(bytes)

    decrypted := make([]byte, bytesSize)
    writtenCount, err := crypto.decoderBuffer.Read(decrypted)
    if writtenCount != int(bytesSize) || err != nil { return nil }

    return decrypted
}

func Hash(bytes []byte) []byte {
    utils.Assert(len(bytes) > 0)
    return sodium.PWHashStore(string(bytes)).Value()
}

func CompareWithHash(hash []byte, unhashed []byte) bool {
    utils.Assert(len(hash) > 0 && len(unhashed) > 0)
    return sodium.LoadPWHashStr(hash).PWHashVerify(string(unhashed)) == nil
}

func Sign(bytes []byte) []byte {
    bytesSize := len(bytes)
    utils.Assert(bytesSize > 0)

    result := sodium.Bytes(bytes).Sign(signSecretKey)
    utils.Assert(len(result) == int(SignatureSize) + bytesSize)

    return result
}

func encryptSingle(bytes []byte, key []byte) []byte { // encrypts only one message, compared with Encrypt, which encrypts a set of related messages
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

func decryptSingle(bytes []byte, key []byte) []byte { // same as encryptSingle
    bytesSize := uint(len(bytes))
    utils.Assert(bytesSize > 0 && len(key) == int(KeySize))

    encryptedWithoutNonceSize := bytesSize - nonceSize

    nonce := sodium.SecretBoxNonce{Bytes: sodium.Bytes(bytes[encryptedWithoutNonceSize:])}
    boxKey := sodium.SecretBoxKey{Bytes: key}

    decrypted, err := sodium.Bytes(bytes[:encryptedWithoutNonceSize]).SecretBoxOpen(nonce, boxKey)
    if err == nil { return decrypted } else { return nil }
}

//goland:noinspection GoRedundantConversion for (*byte) as without this it won't compile
func MakeToken(connectionId uint32, userId uint32) [TokenSize]byte {
    bytes := make([]byte, tokenUnencryptedValueSize)

    copy(bytes, unsafe.Slice((*byte) (unsafe.Pointer(&connectionId)), intSize))
    copy(unsafe.Slice(&(bytes[intSize]), intSize), unsafe.Slice((*byte) (unsafe.Pointer(&userId)), intSize))

    encrypted := encryptSingle(bytes, tokenEncryptionKey)
    utils.Assert(len(encrypted) == int(TokenSize - tokenTrailingSize))

    withTrailing := [TokenSize]byte{}
    copy(unsafe.Slice(&(withTrailing[0]), TokenSize), encrypted)

    return withTrailing
}

//goland:noinspection GoRedundantConversion for (*byte) as without this it won't compile
func OpenToken(withTrailing [TokenSize]byte) (*uint32, *uint32) { // nillable results
    token := withTrailing[:TokenSize - tokenTrailingSize]
    utils.Assert(len(token) == int(EncryptedSize(tokenUnencryptedValueSize)))

    decrypted := decryptSingle(token, tokenEncryptionKey)
    if decrypted == nil || len(decrypted) != tokenUnencryptedValueSize { return nil, nil }

    connectionId := new(uint32); userId := new(uint32)
    copy(unsafe.Slice((*byte) (unsafe.Pointer(connectionId)), intSize), decrypted)
    copy(unsafe.Slice((*byte) (unsafe.Pointer(userId)), intSize), unsafe.Slice(&(decrypted[intSize]), intSize))

    return connectionId, userId
}

func MakeServerToken(messageBodySize uint) [TokenSize]byte { // letting clients to verify server's signature
    //goland:noinspection GoBoolExpressions - just to make sure
    utils.Assert(TokenSize == SignatureSize)

    unsigned := make([]byte, tokenUnencryptedValueSize)
    for i, _ := range unsigned { unsigned[i] = (1 << 8) - 1 } // 255

    signed := Sign(unsigned)
    utils.Assert(len(signed) - tokenUnencryptedValueSize == int(SignatureSize))

    var arr [TokenSize]byte
    copy(unsafe.Slice(&(arr[0]), messageBodySize), signed[:SignatureSize]) // only signature goes into token as clients know what's the signed constant value is

    return arr
}
