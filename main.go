package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
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

	"filippo.io/edwards25519"
)

// PubKey derives a public key from an MC-format private key
func PubKey(pubKeyFull *[64]byte) (string, error) {
	sb := pubKeyFull[:32]
	s, err := edwards25519.NewScalar().SetBytesWithClamping(sb)
	if err != nil {
		return "", err
	}
	pub := edwards25519.NewGeneratorPoint().ScalarBaseMult(s)
	return hex.EncodeToString(pub.Bytes()), nil
}

// GenKey generates a new private key. Normally this is taking a 32 byte seed
// value, using SHA512 to expand it to 64 bytes, and setting/clearing certain
// bits to ensure it's a valid key. The SHA512 distributes the entropy available
// in the seed across all 64 bits. For performance we skip this step, expecting
// r to be a cryptographically-strong PRNG providing good entropy.
func GenKey(r io.Reader, key *[64]byte) error {
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return err
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return nil
}

type KeyPair struct {
	Pub, Priv string
}

func main() {
	// arrange for clean shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// want is a prefix we're searching for
	var want string
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, `
Usage: %s benchmark|<prefix>

benchmark - Report how many keypairs are generated per second
<prefix>  - Generate keys until a public key matches the provided hex prefix

Example: %s f00dee
1032192 keypairs per second
...
740352 keypairs per second

Generated 8891392 keypairs in 9.05811275s (987932/s)

Public:  f00deed3f4a7b056f7f8917dde584af8f4a3eaa7fafc9d1eb96fee84842cdf54
Private: b894d85bd17b790746514ff28fc4a14ee9cef363e33d58ab32ba8d8e31c4bf77bba89c8c0ba5ee204fd07155b6002c8a2c166591988083e1c7e40b4b20529513
`, os.Args[0], os.Args[0])
		os.Exit(1)
	}
	// validate and normalize the desired prefix
	if os.Args[1] != "benchmark" {
		want = strings.ToLower(os.Args[1])
		for _, rune := range want {
			if !strings.ContainsRune("0123456789abcdef", rune) {
				fmt.Fprintf(os.Stderr, "invalid hex string %q\n", os.Args[1])
				os.Exit(1)
			}
		}
	}

	// how we'll receive the matching key pair
	var result KeyPair
	var setResult sync.Once

	// for performance monitoring
	var count int64
	start := time.Now()

	// launch one worker per core
	wg := sync.WaitGroup{}
	for range runtime.NumCPU() {
		wg.Go(func() {
			// for performance, give each worker its own PRNG, seeded with
			// cryptographic-quality entropy
			var seed [32]byte
			rand.Reader.Read(seed[:])
			r := rv2.NewChaCha8(seed)
			var privKey [64]byte
			for {
				// check for a request to stop
				if ctx.Err() != nil {
					return
				}
				// make a batch of attempts
				for range 1024 {
					// generate a private key (raw)
					if err := GenKey(r, &privKey); err != nil {
						log.Fatal(err)
					}
					// derive the public key (hex-encoded)
					pub, err := PubKey(&privKey)
					if err != nil {
						log.Fatal(err)
					}
					if want != "" {
						// we're searching for a prefix match
						if strings.HasPrefix(pub, want) {
							cancel()

							// set the result one time
							setResult.Do(func() {
								result = KeyPair{
									Pub:  pub,
									Priv: hex.EncodeToString(privKey[:]),
								}
							})
						}
					}
				}
				// add attempt counts to the counter
				atomic.AddInt64(&count, 1024)
			}
		})
	}

	// the workers are in the background. Print performance output
	var lastCount int64
	for {
		time.Sleep(time.Second)
		current := atomic.LoadInt64(&count)
		fmt.Printf("%d keypairs per second\n", current-lastCount)
		lastCount = current
		if ctx.Err() != nil {
			break // the user has asked to exit
		}
	}

	// wait for the workers
	wg.Wait()
	// calculate and print final performance numbers
	duration := time.Since(start)
	fmt.Printf("\nGenerated %d keypairs in %s (%d/s)\n", lastCount, duration, lastCount/int64(duration.Seconds()))
	// if we found a match, print it out
	if result.Pub != "" {
		fmt.Printf(`
Public:  %s
Private: %s
`, result.Pub, result.Priv)
	}
}
