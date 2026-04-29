package main

import (
"crypto/md5"
"crypto/sha1"
"crypto/tls"
"os/exec"
)

func main() {
userInput := "echo test"
exec.Command("sh", "-c", userInput)
_ = md5.New()
_ = sha1.New()
_ = &tls.Config{InsecureSkipVerify: true}
}
