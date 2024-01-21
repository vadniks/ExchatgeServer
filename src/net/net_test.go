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

package net

import (
    "bytes"
    "testing"
    "unsafe"
)

func TestPackMessage(t *testing.T) {
    first := true
    begin:

    token := [64]byte{}
    for i := range token { token[i] = 7 }

    var body []byte
    if first { body = []byte{8, 8} } else { body = nil }

    var size uint32
    if first { size = 2 } else { size = 0 }

    packed := ((*netT) (nil)).packMessage(&message{
        flag: 0,
        timestamp: 1,
        size: size,
        index: 3,
        count: 4,
        from: 5,
        to: 6,
        token: token,
        body: body,
    })

    if *((*int32) (unsafe.Pointer(&(packed[0])))) != 0 { t.Error() }
    if *((*uint64) (unsafe.Pointer(&(packed[4])))) != 1 { t.Error() }
    if *((*uint32) (unsafe.Pointer(&(packed[4 + 8])))) != size { t.Error() }
    if *((*uint32) (unsafe.Pointer(&(packed[4 * 2 + 8])))) != 3 { t.Error() }
    if *((*uint32) (unsafe.Pointer(&(packed[4 * 3 + 8])))) != 4 { t.Error() }
    if *((*uint32) (unsafe.Pointer(&(packed[4 * 4 + 8])))) != 5 { t.Error() }
    if *((*uint32) (unsafe.Pointer(&(packed[4 * 5 + 8])))) != 6 { t.Error() }
    if !bytes.Equal(token[:], packed[(4 * 6 + 8):(4 * 6 + 8 + 64)]) { t.Error() }

    if first { if !bytes.Equal(body, packed[(4 * 6 + 8 + 64):]) { t.Error() } } else { if len(packed) != 96 { t.Error() } }

    if first {
        first = false
        goto begin
    }
}

// TODO: test if body is null

func TestUnpackMessage(t *testing.T) {
    first := true
    begin:

    var packed []byte
    if first {
        packed = []byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8}
    } else {
        packed = []byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}
    }

    unpacked := ((*netT) (nil)).unpackMessage(packed)

    if unpacked.flag != 0 { t.Error() }
    if unpacked.timestamp != 1 { t.Error() }
    if unpacked.size != func() uint32 { if first { return 2 } else { return 0 } }() { t.Error() }
    if unpacked.index != 3 { t.Error() }
    if unpacked.count != 4 { t.Error() }
    if unpacked.from != 5 { t.Error() }
    if unpacked.to != 6 { t.Error() }

    for _, i := range unpacked.token { if i != 7 { t.Error() } }

    if first {
        if len(unpacked.body) != 2 { t.Error() }
        for _, i := range unpacked.body { if i != 8 { t.Error() } }
    } else {
        if unpacked.body != nil { t.Error() }
    }

    if first {
        first = false
        goto begin
    }
}
