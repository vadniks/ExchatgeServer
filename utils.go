
package main

import (
    "fmt"
    "os"
)

// Why the f*** this language doesn't support function overloading?
func throw(msg string) { // Gimme optional/nullable function parameters
    fmt.Fprintln(os.Stderr, msg)
    os.Exit(1)
} // No throw keyword? - I'll define a creepy alternative to it!
