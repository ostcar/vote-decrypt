package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/OpenSlides/vote-decrypt/crypto"
	"github.com/OpenSlides/vote-decrypt/decrypt"
	"github.com/OpenSlides/vote-decrypt/grpc"
	"github.com/OpenSlides/vote-decrypt/store"
	"golang.org/x/sys/unix"
)

func main() {
	ctx, cancel := interruptContext()
	defer cancel()

	if err := run(ctx); err != nil {
		log.Printf("Error: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// TODO: set port and vote_data path via flags or environment
	random := rand.Reader

	if len(os.Args) < 2 {
		return fmt.Errorf("Usage: %s main_key_file", os.Args[0])
	}

	mainKey, err := readMainKey(os.Args[1])
	if err != nil {
		return fmt.Errorf("getting main key: %w", err)
	}

	decrypter := decrypt.New(
		crypto.New(mainKey, random),
		store.New("vote_data"),
	)

	if err := grpc.RunServer(ctx, decrypter, ":9014"); err != nil {
		return fmt.Errorf("running grpc server: %w", err)
	}

	return nil

}

// interruptContext works like signal.NotifyContext. It returns a context that
// is canceled, when a signal is received.
//
// It listens on os.Interrupt and unix.SIGTERM. If the signal is received two
// times, os.Exit(2) is called.
func interruptContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, unix.SIGTERM)
		<-sig
		cancel()
		<-sig
		os.Exit(2)
	}()
	return ctx, cancel
}

// readMainKey reads the first 32 bytes from the given file. It returns an
// error, if the file is shorter.
func readMainKey(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("open main file: %w", err)
	}
	defer f.Close()

	key := make([]byte, 32)
	if _, err := io.ReadFull(f, key); err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}

	return key, nil
}
