package main

import (
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
)

// generateOnionAddress mengubah public key Ed25519 menjadi format alamat Onion v3
func generateOnionAddress(pubKey ed25519.PublicKey) string {
	// Versi alamat Onion v3 adalah 0x03
	version := []byte{0x03}
	prefix := []byte(".onion checksum")

	// Menghitung Checksum = 2 byte pertama dari SHA3-256(".onion checksum" || pubkey || version)
	var checksumData []byte
	checksumData = append(checksumData, prefix...)
	checksumData = append(checksumData, pubKey...)
	checksumData = append(checksumData, version...)

	hasher := sha3.New256()
	hasher.Write(checksumData)
	checksumFull := hasher.Sum(nil)
	checksum := checksumFull[:2]

	// Menggabungkan byte alamat = pubkey || checksum || version
	var addrBytes []byte
	addrBytes = append(addrBytes, pubKey...)
	addrBytes = append(addrBytes, checksum...)
	addrBytes = append(addrBytes, version...)

	// Mengenkode ke format Base32 dan mengubahnya menjadi huruf kecil
	encoded := base32.StdEncoding.EncodeToString(addrBytes)
	return strings.ToLower(encoded)
}

// worker adalah goroutine yang akan terus mencari keypair hingga menemukan prefix yang cocok
func worker(prefix string, wg *sync.WaitGroup, found *int32, resultChan chan<- ed25519.PrivateKey) {
	defer wg.Done()

	for atomic.LoadInt32(found) == 0 { // Looping selama belum ada yang menemukan
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			continue
		}

		addr := generateOnionAddress(pub)

		if strings.HasPrefix(addr, prefix) {
			// Memastikan hanya satu goroutine yang melaporkan keberhasilan
			if atomic.CompareAndSwapInt32(found, 0, 1) {
				resultChan <- priv
			}
			return
		}
	}
}

// savePrivateKey menyimpan private key ke format yang dibaca oleh daemon Tor (hs_ed25519_secret_key)
func savePrivateKey(priv ed25519.PrivateKey, filename string) error {
	// Header khusus untuk file secret key Tor v3
	header := []byte("== ed25519v1-secret: type0 ==\x00\x00\x00")

	var fileData []byte
	fileData = append(fileData, header...)
	fileData = append(fileData, priv...)

	// Menyimpan dengan permission 0600 (sangat penting untuk Tor)
	return os.WriteFile(filename, fileData, 0600)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Cara penggunaan: go run vanity_onion.go <prefix>")
		fmt.Println("Contoh: go run vanity_onion.go test")
		os.Exit(1)
	}

	prefix := strings.ToLower(os.Args[1])

	// Validasi input (Base32 hanya menggunakan huruf a-z dan angka 2-7)
	for _, char := range prefix {
		if (char < 'a' || char > 'z') && (char < '2' || char > '7') {
			fmt.Println("Error: Prefix tidak valid. Gunakan hanya huruf a-z dan angka 2-7.")
			os.Exit(1)
		}
	}

	fmt.Printf("Mencari alamat onion dengan awalan: %s\n", prefix)

	numCPU := runtime.NumCPU()
	fmt.Printf("Menggunakan %d core CPU...\n", numCPU)

	var wg sync.WaitGroup
	var found int32 = 0
	resultChan := make(chan ed25519.PrivateKey, 1)

	startTime := time.Now()

	// Menjalankan worker sebanyak jumlah CPU
	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go worker(prefix, &wg, &found, resultChan)
	}

	// Menunggu hasil dari worker pertama yang berhasil
	privKey := <-resultChan
	wg.Wait()

	duration := time.Since(startTime)

	// Menampilkan hasil
	pubKey := privKey.Public().(ed25519.PublicKey)
	onionAddr := generateOnionAddress(pubKey) + ".onion"

	fmt.Printf("\nBerhasil ditemukan dalam %s!\n", duration)
	fmt.Printf("Onion Address : %s\n", onionAddr)

	// Menyimpan file key
	err := savePrivateKey(privKey, "hs_ed25519_secret_key")
	if err != nil {
		fmt.Printf("Gagal menyimpan private key: %v\n", err)
	} else {
		fmt.Println("Private key telah disimpan di file: 'hs_ed25519_secret_key'")
		fmt.Println("\nAnda bisa meletakkan file ini di direktori HiddenServiceDir Tor Anda.")
	}
}
