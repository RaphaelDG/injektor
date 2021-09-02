package main

import (
    "C"
    "fmt"
    "os"
)

func main() {
    fmt.Println("from main")
}

//export Test
func Test() string {

	f, err := os.Create("C:\\data.txt")

    if err != nil {
        fmt.Println(err)
    }

    defer f.Close()
    return "this is a test"
}


