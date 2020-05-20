package main

import (
  "fmt"
  "flag"
)

func main() {
  prePtr := flag.Bool("pre", false, "Run the pre stage")
  postPtr := flag.Bool("post", false, "Run the post stage")

  flag.Parse()

  if *prePtr {
    fmt.Println("pre")
    pre()
  }

  if *postPtr {
    fmt.Println("post")
    post()
  }

}
