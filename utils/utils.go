
package utils

import "time"

func JustThrow() { panic(any("")) }
func Assert(condition bool) { if !condition { JustThrow() } }
func CurrentTimeMillis() uint64 { return uint64(time.Now().UnixMilli()) }
