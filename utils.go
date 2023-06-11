
package main

import (
    "fmt"
    "os"
    "runtime/debug"
)

func throw(msg string) {
    _, _ = fmt.Fprintln(os.Stderr, msg)
    debug.PrintStack()
    os.Exit(1)
}

func justThrow() { throw("") }
