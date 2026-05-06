# mckey - MeshCore Key Prefix Generator

`mckey` is a tool that generates ed25519 key pairs until it finds one or more where
the hex-encoded public key matches a given prefix. It's written in pure Go and spawns
one worker per CPU core available. It's very fast though it doesn't take advantage
of GPU resources.

## Usage

```sh
./mckey benchmark
984064 keypairs per second
1027072 keypairs per second
1027072 keypairs per second
1006592 keypairs per second
1018880 keypairs per second
1004544 keypairs per second
^C
```

In `benchmark` mode, `mckey` will generate keypairs indefintely, reporting how many
keypairs it's producing per second.

```sh
./mckey f00dee
984064 keypairs per second
983040 keypairs per second
985088 keypairs per second
1006592 keypairs per second
982016 keypairs per second
991232 keypairs per second
988160 keypairs per second
994304 keypairs per second
980992 keypairs per second
999424 keypairs per second
974848 keypairs per second
979968 keypairs per second
976896 keypairs per second
982016 keypairs per second
977920 keypairs per second
f00dee499adc9ba5b8aed38cfea63b1127a2ebe0d13dd8139552006102cb3bef   3f5c06a5e49523b732216c6ff1b06701d9e95d195747e739b5365db88f10176bf00dee499adc9ba5b8aed38cfea63b1127a2ebe0d13dd8139552006102cb3bef
```

In "prefix" mode, `mckey` will generate keypairs until the hex-encoded public key
matches the provided hex prefix. Each prefix character will increase the average
search time by 16. If it took 10 seconds to find a four-character prefix match,
it will take about 160 second seconds to find a five-character prefix match, and
so on.

## Building

You need the Go toolchain installed.

### Windows

```sh
go build -o mckey.exe -trimpath *.go
```

### Not-Windows

```sh
go build -o mckey -trimpath -ldflags="-s -w" *.go
```