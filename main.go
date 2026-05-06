package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	rv2 "math/rand/v2"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var want string
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, `
Usage: %s benchmark|<prefix>

benchmark - Report how many keypairs are generated per second
<prefix>  - Generate keys until a public key matches the provided hex prefix

Example: %s f00dee
984064 keypairs per second
...
977920 keypairs per second
f00dee499adc9ba5b8aed38cfea63b1127a2ebe0d13dd8139552006102cb3bef   3f5c06a5e49523b732216c6ff1b06701d9e95d195747e739b5365db88f10176bf00dee499adc9ba5b8aed38cfea63b1127a2ebe0d13dd8139552006102cb3bef
`, os.Args[0], os.Args[0])
		os.Exit(1)
	}
	if os.Args[1] != "benchmark" {
		want = strings.ToLower(os.Args[1])
		for _, rune := range want {
			if !strings.ContainsRune("0123456789abcdef", rune) {
				fmt.Fprintf(os.Stderr, "invalid hex string %q\n", os.Args[1])
				os.Exit(1)
			}
		}
	}

	var count int64
	wg := sync.WaitGroup{}
	for range runtime.NumCPU() {
		wg.Go(func() {
			var seed [32]byte
			rand.Reader.Read(seed[:])
			r := rv2.NewChaCha8(seed)
			for {
				if ctx.Err() != nil {
					return
				}
				for range 1024 {
					pub, priv, err := ed25519.GenerateKey(r)
					if err != nil {
						log.Fatal(err)
					}
					if want != "" {
						pubHex := hex.EncodeToString(pub)
						if strings.HasPrefix(pubHex, want) {
							cancel()
							fmt.Println(pubHex, " ", hex.EncodeToString(priv))
						}
					}
				}
				atomic.AddInt64(&count, 1024)
			}
		})
	}

	var lastCount int64
	for {
		time.Sleep(time.Second)
		current := atomic.LoadInt64(&count)
		fmt.Printf("%d keypairs per second\n", current-lastCount)
		lastCount = current
		if ctx.Err() != nil {
			break
		}
	}

	wg.Wait()
}
