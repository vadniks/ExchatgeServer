/*
 * Exchatge - a secured realtime message exchanger (server).
 * Copyright (C) 2023-2024  Vadim Nikolaev (https://github.com/vadniks)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package crypto

import (
    "bytes"
    "testing"
    "time"
    "unsafe"
)

func TestKeyExchange(t *testing.T) {
    serverPublicKey, serverSecretKey := GenerateServerKeys() // just generates a key pair
    clientPublicKey, clientSecretKey := GenerateServerKeys()

    serverKey, clientKey := ExchangeKeys(serverPublicKey, serverSecretKey, clientPublicKey) // server
    if !(len(serverKey) == int(KeySize) && len(clientKey) == int(KeySize)) { t.Error() }

    clientKey2, serverKey2 := exposedTest_exchangeKeysAsClient(clientPublicKey, clientSecretKey, serverPublicKey) // client
    if !(len(clientKey2) == int(KeySize) && len(serverKey2) == int(KeySize)) { t.Error() }

    if !(bytes.Equal(clientKey, clientKey2) && bytes.Equal(serverKey2, serverKey2)) { t.Error() }
}

func TestCoderStreams(t *testing.T) { // fmt.Printf("%v", key)
    clientKey := []byte{131, 3, 162, 82, 136, 103, 195, 49, 233, 142, 113, 208, 245, 145, 10, 229, 91, 199, 28, 252, 214, 171, 8, 249, 51, 93, 38, 178, 143, 222, 61, 17}
    serverKey := []byte{45, 188, 222, 137, 223, 50, 85, 239, 153, 62, 106, 87, 202, 63, 149, 150, 233, 242, 46, 12, 124, 105, 252, 169, 19, 233, 209, 152, 183, 234, 91, 104}
    if len(clientKey) != len(serverKey) || len(clientKey) != int(KeySize) { t.Error() }

    header, coders1 := CreateEncoderStream(serverKey)
    if !coders1.CreateDecoderStream(serverKey, header) { t.Error() }

    text := make([]byte, 10)
    exposedTest_randomize(text)

    encrypted := coders1.Encrypt(text)
    if len(encrypted) == 0 { t.Error() }
    if uint(len(encrypted)) != EncryptedSize(uint(len(text))) { t.Error() }

    decrypted := coders1.Decrypt(encrypted)
    if len(decrypted) == 0 { t.Error() }

    if !bytes.Equal(text, decrypted) { t.Error() }
}

func TestPasswordHash(t *testing.T) {
    text := make([]byte, 10)
    exposedTest_randomize(text)

    hashed := Hash(text)
    if len(hashed) == 0 { t.Error() }

    if !CompareWithHash(hashed, text) { t.Error() }
}

func TestSingleCrypt(t *testing.T) {
    const size = 10
    buffer := make([]byte, size + KeySize)
    exposedTest_randomize(buffer)

    text := unsafe.Slice(&(buffer[0]), size)
    key := unsafe.Slice(&(buffer[size]), KeySize)

    encrypted := encryptSingle(text, key)
    if len(encrypted) == 0 { t.Error() }
    if uint(len(encrypted)) != encryptedSingleSize(size) { t.Error() }

    decrypted := decryptSingle(encrypted, key)
    if len(decrypted) == 0 { t.Error() }

    if !bytes.Equal(text, decrypted) { t.Error() }
}

func TestToken(t *testing.T) {
    connectionId := uint32(time.Now().UnixMilli() & 0x7fffffff)
    userId := uint32(time.Now().UnixMilli() & 0x7fffffff)

    token := MakeToken(connectionId, userId)
    xConnectionId, xUserId := OpenToken(token)

    if xConnectionId == nil || xUserId == nil { t.Error() }
    if connectionId != *xConnectionId || userId != *xUserId { t.Error() }
}

func TestServerToken(t *testing.T) {
    Initialize(make([]byte, SecretKeySize))

    const size = 160
    token := MakeServerToken(size)

    value := uint64(0xffffffffffffffff)
    //goland:noinspection GoRedundantConversion
    signature := Sign(unsafe.Slice((*byte) (unsafe.Pointer(&value)), unsafe.Sizeof(value)))[:SignatureSize]

    if !bytes.Equal(token[:], signature) { t.Error() }
}
