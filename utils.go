
package main

import (
    "fmt"
    "os"
    "runtime/debug"
)

// Why the f*** this language doesn't support function overloading?
func throw(msg string) { // Gimme optional/nullable function parameters
    _, _ = fmt.Fprintln(os.Stderr, msg)
    debug.PrintStack()
    os.Exit(1)
} // No throw keyword? - I'll define a creepy alternative to it!

func justThrow() { throw("") }
