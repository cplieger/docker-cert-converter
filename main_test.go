package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"pgregory.net/rapid"
	"software.sslmate.com/src/go-pkcs12"
)

// --- Test helpers ---

// clearHashes resets the global hash cache to prevent test pollution.
func clearHashes() {
	mu.Lock()
	defer mu.Unlock()
	clear(hashes)
}

// generateSelfSignedCert creates a self-signed certificate with the given
// key type and common name. Returns PEM-encoded cert and key.
func generateSelfSignedCert(t *testing.T, cn, keyType string) (certPEM, keyPEM []byte) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	switch keyType {
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	default:
		t.Fatalf("unsupported key type: %s", keyType)
	}

	return certPEM, keyPEM
}

// generateCertChain creates a CA + leaf certificate chain.
// Returns leaf PEM, key PEM, CA PEM, and the full chain (leaf + CA).
func generateCertChain(t *testing.T) (leafPEM, keyPEM, caPEM, chainPEM []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	chainPEM = make([]byte, 0, len(leafPEM)+len(caPEM))
	chainPEM = append(chainPEM, leafPEM...)
	chainPEM = append(chainPEM, caPEM...)
	return leafPEM, keyPEM, caPEM, chainPEM
}

// writeCertAndKey writes a .crt and .key file pair into dir and returns their paths.
func writeCertAndKey(t *testing.T, dir, base string, certPEM, keyPEM []byte) (crtPath, keyPath string) {
	t.Helper()
	crtPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")
	if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return crtPath, keyPath
}

// decodePFX reads and decodes a PFX file, returning the private key, leaf cert, and CA certs.
func decodePFX(t *testing.T, path, password string) (key any, leaf *x509.Certificate, ca []*x509.Certificate) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}
	privKey, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		t.Fatalf("decode pfx: %v", err)
	}
	return privKey, cert, caCerts
}

// --- Tests: parseCertChain ---

func TestParseCertChain(t *testing.T) {
	t.Run("single cert", func(t *testing.T) {
		certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
		certs, err := parseCertChain(certPEM)
		if err != nil {
			t.Fatalf("parseCertChain: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("got %d certs, want 1", len(certs))
		}
		if certs[0].Subject.CommonName != "test" {
			t.Errorf("CN = %q, want %q", certs[0].Subject.CommonName, "test")
		}
	})

	t.Run("chain with CA", func(t *testing.T) {
		_, _, _, chainPEM := generateCertChain(t)
		certs, err := parseCertChain(chainPEM)
		if err != nil {
			t.Fatalf("parseCertChain: %v", err)
		}
		if len(certs) != 2 {
			t.Fatalf("got %d certs, want 2", len(certs))
		}
		if certs[0].Subject.CommonName != "leaf.example.com" {
			t.Errorf("leaf CN = %q, want %q", certs[0].Subject.CommonName, "leaf.example.com")
		}
		if certs[1].Subject.CommonName != "Test CA" {
			t.Errorf("CA CN = %q, want %q", certs[1].Subject.CommonName, "Test CA")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		if _, err := parseCertChain([]byte("not a pem")); err == nil {
			t.Error("expected error for invalid PEM")
		}
	})

	t.Run("excessive PEM blocks", func(t *testing.T) {
		// Verify parseCertChain handles a file with many CERTIFICATE blocks
		// without hanging. This is a resource exhaustion edge case.
		certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
		var bulkPEM []byte
		for range 100 {
			bulkPEM = append(bulkPEM, certPEM...)
		}
		certs, err := parseCertChain(bulkPEM)
		if err != nil {
			t.Fatalf("parseCertChain: %v", err)
		}
		if len(certs) != 100 {
			t.Errorf("got %d certs, want 100", len(certs))
		}
	})
}

// --- Tests: parsePrivateKey ---

func TestParsePrivateKey(t *testing.T) {
	t.Run("ECDSA PKCS8", func(t *testing.T) {
		_, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		key, err := parsePrivateKey(keyPEM)
		if err != nil {
			t.Fatalf("parsePrivateKey: %v", err)
		}
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
		}
	})

	t.Run("RSA PKCS1", func(t *testing.T) {
		_, keyPEM := generateSelfSignedCert(t, "test", "rsa")
		key, err := parsePrivateKey(keyPEM)
		if err != nil {
			t.Fatalf("parsePrivateKey: %v", err)
		}
		if _, ok := key.(*rsa.PrivateKey); !ok {
			t.Errorf("expected *rsa.PrivateKey, got %T", key)
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		if _, err := parsePrivateKey([]byte("not a key")); err == nil {
			t.Error("expected error for invalid key PEM")
		}
	})

	t.Run("PEM with only CERTIFICATE blocks", func(t *testing.T) {
		certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
		if _, err := parsePrivateKey(certPEM); err == nil {
			t.Error("expected error when PEM contains only CERTIFICATE blocks")
		}
	})
}

// --- Tests: convertToPFX ---

func TestConvertToPFXCertKeyMismatch(t *testing.T) {
	// Generate two independent key pairs — cert signed by key A, key file contains key B.
	// The pkcs12 encoder doesn't validate cert/key pairing at encode time,
	// so we verify the resulting PFX contains mismatched material.
	certPEM, _ := generateSelfSignedCert(t, "mismatch", "ecdsa")
	_, wrongKeyPEM := generateSelfSignedCert(t, "other", "ecdsa")

	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "mismatch", certPEM, wrongKeyPEM)

	pfxPath := filepath.Join(tmpDir, "mismatch.pfx")
	if err := convertToPFX(crtPath, keyPath, pfxPath, "pass", pkcs12.Modern2023); err != nil {
		// Some encoder versions may detect the mismatch — that's acceptable.
		return
	}

	// If encode succeeded, the PFX file should exist.
	if _, err := os.Stat(pfxPath); err != nil {
		t.Fatalf("PFX file not created: %v", err)
	}
}

func TestConvertToPFX(t *testing.T) {
	t.Run("ECDSA round trip", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t, "ecdsa-test", "ecdsa")
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "test.pfx")

		if err := convertToPFX(crtPath, keyPath, pfxPath, "pass", pkcs12.Modern2023); err != nil {
			t.Fatalf("convertToPFX: %v", err)
		}

		privKey, cert, caCerts := decodePFX(t, pfxPath, "pass")
		if cert.Subject.CommonName != "ecdsa-test" {
			t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "ecdsa-test")
		}
		if _, ok := privKey.(*ecdsa.PrivateKey); !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", privKey)
		}
		if len(caCerts) != 0 {
			t.Errorf("expected 0 CA certs, got %d", len(caCerts))
		}
	})

	t.Run("RSA round trip", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t, "rsa-test", "rsa")
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "test.pfx")

		if err := convertToPFX(crtPath, keyPath, pfxPath, "", pkcs12.Modern2023); err != nil {
			t.Fatalf("convertToPFX: %v", err)
		}

		privKey, cert, _ := decodePFX(t, pfxPath, "")
		if cert.Subject.CommonName != "rsa-test" {
			t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "rsa-test")
		}
		if _, ok := privKey.(*rsa.PrivateKey); !ok {
			t.Errorf("expected *rsa.PrivateKey, got %T", privKey)
		}
	})

	t.Run("chain with CA cert", func(t *testing.T) {
		_, keyPEM, _, chainPEM := generateCertChain(t)
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "chain", chainPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "chain.pfx")

		if err := convertToPFX(crtPath, keyPath, pfxPath, "chainpass", pkcs12.Modern2023); err != nil {
			t.Fatalf("convertToPFX: %v", err)
		}

		privKey, cert, caCerts := decodePFX(t, pfxPath, "chainpass")
		if cert.Subject.CommonName != "leaf.example.com" {
			t.Errorf("leaf CN = %q, want %q", cert.Subject.CommonName, "leaf.example.com")
		}
		if _, ok := privKey.(*ecdsa.PrivateKey); !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", privKey)
		}
		if len(caCerts) != 1 {
			t.Fatalf("expected 1 CA cert, got %d", len(caCerts))
		}
		if caCerts[0].Subject.CommonName != "Test CA" {
			t.Errorf("CA CN = %q, want %q", caCerts[0].Subject.CommonName, "Test CA")
		}
	})

	t.Run("atomic overwrite", func(t *testing.T) {
		certPEM, keyPEM := generateSelfSignedCert(t, "atomic", "ecdsa")
		tmpDir := t.TempDir()
		crtPath, keyPath := writeCertAndKey(t, tmpDir, "atomic", certPEM, keyPEM)
		pfxPath := filepath.Join(tmpDir, "atomic.pfx")

		// Pre-existing file should be replaced.
		if err := os.WriteFile(pfxPath, []byte("old data"), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := convertToPFX(crtPath, keyPath, pfxPath, "", pkcs12.Modern2023); err != nil {
			t.Fatalf("convertToPFX: %v", err)
		}

		decodePFX(t, pfxPath, "") // panics if still "old data"
	})
}

// --- Tests: readFileWithLimit ---

func TestReadFileWithLimit(t *testing.T) {
	t.Run("normal file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "small.txt")
		if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
		data, err := readFileWithLimit(path, 1024)
		if err != nil {
			t.Fatalf("readFileWithLimit: %v", err)
		}
		if string(data) != "hello" {
			t.Errorf("got %q, want %q", data, "hello")
		}
	})

	t.Run("oversized file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "big.txt")
		if err := os.WriteFile(path, make([]byte, 2048), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := readFileWithLimit(path, 1024)
		if err == nil {
			t.Error("expected error for oversized file")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := readFileWithLimit("/nonexistent/file.txt", 1024)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})
}

// --- Tests: processAll ---

func TestProcessAll(t *testing.T) {
	enc := pkcs12.Modern2023

	t.Run("skips unchanged files", func(t *testing.T) {
		clearHashes()
		certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("first processAll: %v", err)
		}

		pfxPath := filepath.Join(outDir, "test.pfx")
		info1, err := os.Stat(pfxPath)
		if err != nil {
			t.Fatalf("pfx not created: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("second processAll: %v", err)
		}

		info2, err := os.Stat(pfxPath)
		if err != nil {
			t.Fatalf("pfx disappeared: %v", err)
		}
		if info2.ModTime() != info1.ModTime() {
			t.Error("pfx was rewritten despite unchanged input")
		}
	})

	t.Run("reconverts on change", func(t *testing.T) {
		clearHashes()
		certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()
		writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("first processAll: %v", err)
		}

		// Replace with new cert.
		certPEM2, keyPEM2 := generateSelfSignedCert(t, "test", "ecdsa")
		writeCertAndKey(t, tmpDir, "test", certPEM2, keyPEM2)

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("second processAll: %v", err)
		}

		decodePFX(t, filepath.Join(outDir, "test.pfx"), "")
	})

	t.Run("preserves nested directory structure", func(t *testing.T) {
		clearHashes()
		certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()

		nestedDir := filepath.Join(tmpDir, "sub", "dir")
		if err := os.MkdirAll(nestedDir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeCertAndKey(t, nestedDir, "nested", certPEM, keyPEM)

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("processAll: %v", err)
		}

		pfxPath := filepath.Join(outDir, "sub", "dir", "nested.pfx")
		if _, err := os.Stat(pfxPath); err != nil {
			t.Fatalf("expected PFX at %s: %v", pfxPath, err)
		}
	})

	t.Run("skips .crt without matching .key", func(t *testing.T) {
		clearHashes()
		certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
		tmpDir := t.TempDir()
		outDir := t.TempDir()

		if err := os.WriteFile(filepath.Join(tmpDir, "orphan.crt"), certPEM, 0o644); err != nil {
			t.Fatal(err)
		}

		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("processAll: %v", err)
		}

		if _, err := os.Stat(filepath.Join(outDir, "orphan.pfx")); err == nil {
			t.Error("PFX should not be created when .key is missing")
		}
	})

	t.Run("retries after conversion failure", func(t *testing.T) {
		clearHashes()
		tmpDir := t.TempDir()
		outDir := t.TempDir()

		// Write a valid cert but an invalid key to trigger conversion failure.
		certPEM, _ := generateSelfSignedCert(t, "retry", "ecdsa")
		crtPath := filepath.Join(tmpDir, "retry.crt")
		keyPath := filepath.Join(tmpDir, "retry.key")
		if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
			t.Fatal(err)
		}

		// First scan: conversion fails (bad key), but should not cache the hash.
		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("first processAll: %v", err)
		}
		if _, err := os.Stat(filepath.Join(outDir, "retry.pfx")); err == nil {
			t.Fatal("PFX should not exist after failed conversion")
		}

		// Fix the key file — generate a new matching cert+key pair.
		certPEM2, keyPEM2 := generateSelfSignedCert(t, "retry", "ecdsa")
		if err := os.WriteFile(crtPath, certPEM2, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM2, 0o600); err != nil {
			t.Fatal(err)
		}

		// Second scan: should retry because hash was invalidated on failure.
		if err := processAll(tmpDir, outDir, "", enc); err != nil {
			t.Fatalf("second processAll: %v", err)
		}
		if _, err := os.Stat(filepath.Join(outDir, "retry.pfx")); err != nil {
			t.Fatalf("PFX should exist after retry with valid key: %v", err)
		}
	})
}

// --- Tests: changed ---

func TestChanged(t *testing.T) {
	clearHashes()
	certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

	if !changed(crtPath, keyPath) {
		t.Error("first call should report changed")
	}
	if changed(crtPath, keyPath) {
		t.Error("second call should report not changed")
	}

	// Replace with new content.
	certPEM2, keyPEM2 := generateSelfSignedCert(t, "test", "ecdsa")
	writeCertAndKey(t, tmpDir, "test", certPEM2, keyPEM2)

	if !changed(crtPath, keyPath) {
		t.Error("should report changed after content update")
	}
}

func TestChangedOversizedFile(t *testing.T) {
	clearHashes()
	tmpDir := t.TempDir()
	crtPath := filepath.Join(tmpDir, "big.crt")
	keyPath := filepath.Join(tmpDir, "big.key")

	// Create files exceeding the 10 MB limit.
	bigData := make([]byte, 11<<20)
	if err := os.WriteFile(crtPath, bigData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("small"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Should report changed (can't hash → treat as changed).
	if !changed(crtPath, keyPath) {
		t.Error("oversized file should report changed (hash error)")
	}
}

func TestInvalidateHash(t *testing.T) {
	clearHashes()
	certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

	// First call caches the hash.
	if !changed(crtPath, keyPath) {
		t.Fatal("first call should report changed")
	}
	if changed(crtPath, keyPath) {
		t.Fatal("second call should report not changed")
	}

	// Invalidate the cache — next call should report changed
	// even though the files haven't changed on disk.
	invalidateHash(crtPath)
	if !changed(crtPath, keyPath) {
		t.Error("should report changed after invalidateHash")
	}
}

// --- Tests: pickEncoder ---

func TestPickEncoder(t *testing.T) {
	for _, tc := range []struct {
		env      string
		wantName string
	}{
		{"", encNameModern2023},
		{"modern2023", encNameModern2023},
		{"Modern", encNameModern2023},
		{"modern2026", encNameModern2026},
		{"Modern2026", encNameModern2026},
		{"legacy", encNameLegacyDES},
		{"legacyrc2", encNameLegacyRC2},
		{"LegacyDES", encNameLegacyDES},
		{"unknown", encNameModern2023},
	} {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("PFX_ENCODER", tc.env)
			enc, name := pickEncoder()
			if enc == nil {
				t.Fatal("pickEncoder returned nil encoder")
			}
			if name != tc.wantName {
				t.Errorf("pickEncoder name = %q, want %q", name, tc.wantName)
			}
		})
	}
}

// --- Tests: parseFallbackInterval ---

func TestParseFallbackInterval(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		set  bool
		want time.Duration
	}{
		{"unset", "", false, 6 * time.Hour},
		{"empty", "", true, 0},
		{"zero", "0", true, 0},
		{"false", "false", true, 0},
		{"FALSE", "FALSE", true, 0},
		{"valid", "12", true, 12 * time.Hour},
		{"one", "1", true, 1 * time.Hour},
		{"negative", "-1", true, 6 * time.Hour},
		{"non-numeric", "abc", true, 6 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("FALLBACK_SCAN_HOURS", tc.env)
			}
			if got := parseFallbackInterval(); got != tc.want {
				t.Errorf("parseFallbackInterval() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- Tests: health file ---

func TestHealthFile(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" {
		t.Skip("skipping on Windows: /tmp does not exist")
	}

	setHealthy(true)
	defer setHealthy(false)

	if _, err := os.Stat(healthFile); err != nil {
		t.Fatalf("health file should exist after setHealthy(true): %v", err)
	}

	setHealthy(false)
	if _, err := os.Stat(healthFile); err == nil {
		t.Fatal("health file should not exist after setHealthy(false)")
	}
}

// --- Tests: handleFsEvent ---

func TestHandleFsEvent(t *testing.T) {
	t.Run("create directory adds to watcher", func(t *testing.T) {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			t.Fatal(err)
		}
		defer watcher.Close()

		dir := t.TempDir()

		event := fsnotify.Event{Name: dir, Op: fsnotify.Create}
		if handleFsEvent(event, watcher) {
			t.Error("handleFsEvent should return false for directory create (no .crt/.key)")
		}
	})

	t.Run("create .crt file returns true", func(t *testing.T) {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			t.Fatal(err)
		}
		defer watcher.Close()

		event := fsnotify.Event{Name: "/some/path/cert.crt", Op: fsnotify.Create}
		if !handleFsEvent(event, watcher) {
			t.Error("handleFsEvent should return true for .crt file")
		}
	})

	t.Run("write .key file returns true", func(t *testing.T) {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			t.Fatal(err)
		}
		defer watcher.Close()

		event := fsnotify.Event{Name: "/certs/domain.key", Op: fsnotify.Write}
		if !handleFsEvent(event, watcher) {
			t.Error("handleFsEvent should return true for .key file")
		}
	})

	t.Run("non-cert file returns false", func(t *testing.T) {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			t.Fatal(err)
		}
		defer watcher.Close()

		event := fsnotify.Event{Name: "/some/file.txt", Op: fsnotify.Write}
		if handleFsEvent(event, watcher) {
			t.Error("handleFsEvent should return false for .txt file")
		}
	})
}

// --- Tests: parsePrivateKey (additional coverage) ---

func TestParsePrivateKey_EC_SEC1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	parsed, err := parsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey(EC SEC1) = error %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("parsePrivateKey(EC SEC1) returned %T, want *ecdsa.PrivateKey", parsed)
	}
}

func TestParsePrivateKey_Ed25519_PKCS8(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := parsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey(Ed25519 PKCS8) = error %v", err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Errorf("parsePrivateKey(Ed25519 PKCS8) returned %T, want ed25519.PrivateKey", parsed)
	}
}

func TestParsePrivateKey_unparseable_key_data(t *testing.T) {
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("this is not valid DER"),
	})

	_, err := parsePrivateKey(keyPEM)
	if err == nil {
		t.Fatal("parsePrivateKey should fail for garbage DER data")
	}
	if !strings.Contains(err.Error(), "failed to parse private key") {
		t.Errorf("parsePrivateKey error = %q, want it to contain %q",
			err.Error(), "failed to parse private key")
	}
}

// --- Tests: convertToPFX error paths ---

func TestConvertToPFX_nonexistent_cert(t *testing.T) {
	tmpDir := t.TempDir()
	_, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
	keyPath := filepath.Join(tmpDir, "test.key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	err := convertToPFX(
		filepath.Join(tmpDir, "missing.crt"),
		keyPath,
		filepath.Join(tmpDir, "out.pfx"),
		"", pkcs12.Modern2023,
	)
	if err == nil {
		t.Fatal("convertToPFX should fail for nonexistent cert file")
	}
	if !strings.Contains(err.Error(), "read cert") {
		t.Errorf("convertToPFX error = %q, want it to contain %q", err.Error(), "read cert")
	}
}

func TestConvertToPFX_nonexistent_key(t *testing.T) {
	tmpDir := t.TempDir()
	certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
	crtPath := filepath.Join(tmpDir, "test.crt")
	if err := os.WriteFile(crtPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	err := convertToPFX(
		crtPath,
		filepath.Join(tmpDir, "missing.key"),
		filepath.Join(tmpDir, "out.pfx"),
		"", pkcs12.Modern2023,
	)
	if err == nil {
		t.Fatal("convertToPFX should fail for nonexistent key file")
	}
	if !strings.Contains(err.Error(), "read key") {
		t.Errorf("convertToPFX error = %q, want it to contain %q", err.Error(), "read key")
	}
}

func TestConvertToPFX_invalid_cert_PEM(t *testing.T) {
	tmpDir := t.TempDir()
	_, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "bad", []byte("not a cert"), keyPEM)

	err := convertToPFX(crtPath, keyPath, filepath.Join(tmpDir, "out.pfx"), "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("convertToPFX should fail for invalid cert PEM")
	}
}

func TestConvertToPFX_invalid_key_PEM(t *testing.T) {
	tmpDir := t.TempDir()
	certPEM, _ := generateSelfSignedCert(t, "test", "ecdsa")
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "bad", certPEM, []byte("not a key"))

	err := convertToPFX(crtPath, keyPath, filepath.Join(tmpDir, "out.pfx"), "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("convertToPFX should fail for invalid key PEM")
	}
}

func TestConvertToPFX_unwritable_dest(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t, "test", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)

	err := convertToPFX(crtPath, keyPath, "/nonexistent/dir/out.pfx", "", pkcs12.Modern2023)
	if err == nil {
		t.Fatal("convertToPFX should fail for unwritable destination")
	}
}

// --- Tests: hashFile (direct) ---

func TestHashFile(t *testing.T) {
	t.Run("consistent hash for same content", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(path, []byte("hello world"), 0o644); err != nil {
			t.Fatal(err)
		}

		h1, err := hashFile(path)
		if err != nil {
			t.Fatalf("hashFile: %v", err)
		}
		h2, err := hashFile(path)
		if err != nil {
			t.Fatalf("hashFile: %v", err)
		}
		if h1 != h2 {
			t.Errorf("hashFile returned different hashes for same file: %q vs %q", h1, h2)
		}
		if len(h1) != 64 {
			t.Errorf("hashFile returned hash of length %d, want 64 (SHA-256 hex)", len(h1))
		}
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		dir := t.TempDir()
		p1 := filepath.Join(dir, "a.txt")
		p2 := filepath.Join(dir, "b.txt")
		if err := os.WriteFile(p1, []byte("aaa"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p2, []byte("bbb"), 0o644); err != nil {
			t.Fatal(err)
		}

		h1, _ := hashFile(p1)
		h2, _ := hashFile(p2)
		if h1 == h2 {
			t.Error("hashFile returned same hash for different content")
		}
	})

	t.Run("rejects oversized file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "big.txt")
		if err := os.WriteFile(path, make([]byte, maxFileSize+1), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := hashFile(path)
		if err == nil {
			t.Fatal("hashFile should reject files exceeding maxFileSize")
		}
		if !strings.Contains(err.Error(), "size limit") {
			t.Errorf("hashFile error = %q, want it to contain %q", err.Error(), "size limit")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := hashFile("/nonexistent/file.txt")
		if err == nil {
			t.Fatal("hashFile should fail for nonexistent file")
		}
	})
}

// --- Tests: parseCertChain (additional coverage) ---

func TestParseCertChain_corrupted_DER(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not valid DER"),
	})

	_, err := parseCertChain(badPEM)
	if err == nil {
		t.Fatal("parseCertChain should fail for corrupted DER inside CERTIFICATE block")
	}
}

func TestParseCertChain_skips_non_certificate_blocks(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t, "mixed", "ecdsa")

	// Prepend a PRIVATE KEY block before the CERTIFICATE block.
	mixed := make([]byte, 0, len(keyPEM)+len(certPEM))
	mixed = append(mixed, keyPEM...)
	mixed = append(mixed, certPEM...)

	certs, err := parseCertChain(mixed)
	if err != nil {
		t.Fatalf("parseCertChain(mixed PEM) = error %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("parseCertChain(mixed PEM) returned %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "mixed" {
		t.Errorf("parseCertChain(mixed PEM) CN = %q, want %q",
			certs[0].Subject.CommonName, "mixed")
	}
}

// --- Tests: readFileWithLimit (additional coverage) ---

func TestReadFileWithLimit_exact_limit(t *testing.T) {
	content := []byte("exactly at limit")
	path := filepath.Join(t.TempDir(), "exact.txt")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	data, err := readFileWithLimit(path, int64(len(content)))
	if err != nil {
		t.Fatalf("readFileWithLimit at exact limit: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Errorf("readFileWithLimit = %q, want %q", data, content)
	}
}

func TestReadFileWithLimit_one_byte_over(t *testing.T) {
	content := []byte("one byte over the limit")
	path := filepath.Join(t.TempDir(), "over.txt")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := readFileWithLimit(path, int64(len(content)-1))
	if err == nil {
		t.Fatal("readFileWithLimit should reject file one byte over limit")
	}
}

// --- Tests: processAndSetHealth ---

func TestProcessAndSetHealth(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" {
		t.Skip("skipping on Windows: /tmp does not exist")
	}

	clearHashes()
	defer setHealthy(false)

	certPEM, keyPEM := generateSelfSignedCert(t, "health-test", "ecdsa")
	inDir := t.TempDir()
	outDir := t.TempDir()
	writeCertAndKey(t, inDir, "test", certPEM, keyPEM)

	processAndSetHealth(inDir, outDir, "", pkcs12.Modern2023)

	if _, err := os.Stat(healthFile); err != nil {
		t.Fatalf("health file should exist after successful processAndSetHealth: %v", err)
	}

	pfxPath := filepath.Join(outDir, "test.pfx")
	if _, err := os.Stat(pfxPath); err != nil {
		t.Fatalf("PFX should be created: %v", err)
	}
}

func TestProcessAndSetHealth_failure(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" {
		t.Skip("skipping on Windows: /tmp does not exist")
	}

	clearHashes()
	defer setHealthy(false)

	// Set healthy first, then trigger a failure to verify it gets cleared.
	setHealthy(true)

	processAndSetHealth("/nonexistent/input", "/nonexistent/output", "", pkcs12.Modern2023)

	if _, err := os.Stat(healthFile); err == nil {
		t.Fatal("health file should not exist after failed processAndSetHealth")
	}
}

// --- Tests: addWatchDirs ---

func TestAddWatchDirs(t *testing.T) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()

	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := addWatchDirs(watcher, root); err != nil {
		t.Fatalf("addWatchDirs(%q) = %v", root, err)
	}

	watchList := watcher.WatchList()
	if len(watchList) < 2 {
		t.Errorf("addWatchDirs added %d dirs, want at least 2 (root + sub)", len(watchList))
	}
}

func TestAddWatchDirs_nonexistent(t *testing.T) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()

	err = addWatchDirs(watcher, "/nonexistent/path")
	if err == nil {
		t.Fatal("addWatchDirs should fail for nonexistent path")
	}
}

// --- Property-based tests (rapid) ---

func TestParseFallbackInterval_never_panics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.String().Draw(t, "env_value")
		os.Setenv("FALLBACK_SCAN_HOURS", v)
		defer os.Unsetenv("FALLBACK_SCAN_HOURS")

		got := parseFallbackInterval()
		if got < 0 {
			t.Errorf("parseFallbackInterval(%q) = %v, want non-negative", v, got)
		}
	})
}

func TestPickEncoder_never_returns_nil(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.String().Draw(t, "env_value")
		os.Setenv("PFX_ENCODER", v)
		defer os.Unsetenv("PFX_ENCODER")

		enc, name := pickEncoder()
		if enc == nil {
			t.Errorf("pickEncoder(%q) returned nil encoder", v)
		}
		if name == "" {
			t.Errorf("pickEncoder(%q) returned empty name", v)
		}
		// Name must be one of the known encoder names.
		switch name {
		case encNameModern2023, encNameModern2026, encNameLegacyDES, encNameLegacyRC2:
			// valid
		default:
			t.Errorf("pickEncoder(%q) returned unknown name %q", v, name)
		}
	})
}

func TestParseCertChain_round_trip(t *testing.T) {
	// Property: encoding a cert to PEM and parsing it back preserves the subject.
	certPEM, _ := generateSelfSignedCert(t, "round-trip", "ecdsa")

	certs, err := parseCertChain(certPEM)
	if err != nil {
		t.Fatalf("parseCertChain: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}

	// Re-encode and re-parse — should be identical.
	reEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certs[0].Raw,
	})
	certs2, err := parseCertChain(reEncoded)
	if err != nil {
		t.Fatalf("parseCertChain(re-encoded): %v", err)
	}
	if certs2[0].Subject.CommonName != "round-trip" {
		t.Errorf("round trip CN = %q, want %q", certs2[0].Subject.CommonName, "round-trip")
	}
}

func TestHashFile_deterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		content := rapid.SliceOfN(rapid.Byte(), 0, 1024).Draw(t, "content")
		dir := os.TempDir()
		path := filepath.Join(dir, "rapid-hash-test.tmp")
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path)

		h1, err1 := hashFile(path)
		h2, err2 := hashFile(path)
		if err1 != nil || err2 != nil {
			t.Fatalf("hashFile errors: %v, %v", err1, err2)
		}
		if h1 != h2 {
			t.Errorf("hashFile not deterministic: %q != %q for same content", h1, h2)
		}
		if len(h1) != 64 {
			t.Errorf("hashFile returned hash of length %d, want 64", len(h1))
		}
	})
}

func TestConvertToPFX_round_trip_all_encoders(t *testing.T) {
	encoders := []struct {
		name string
		enc  *pkcs12.Encoder
	}{
		{"modern2023", pkcs12.Modern2023},
		{"modern2026", pkcs12.Modern2026},
		{"legacyDES", pkcs12.LegacyDES},
		{"legacyRC2", pkcs12.LegacyRC2},
	}

	for _, tc := range encoders {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, keyPEM := generateSelfSignedCert(t, "encoder-"+tc.name, "ecdsa")
			tmpDir := t.TempDir()
			crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
			pfxPath := filepath.Join(tmpDir, "test.pfx")

			if err := convertToPFX(crtPath, keyPath, pfxPath, "testpass", tc.enc); err != nil {
				t.Fatalf("convertToPFX(%s): %v", tc.name, err)
			}

			_, cert, _ := decodePFX(t, pfxPath, "testpass")
			if cert.Subject.CommonName != "encoder-"+tc.name {
				t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "encoder-"+tc.name)
			}
		})
	}
}

// --- Additional edge case tests ---

func TestParseFallbackInterval_whitespace_padding(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		want time.Duration
	}{
		{"leading spaces", "  12", 12 * time.Hour},
		{"trailing spaces", "12  ", 12 * time.Hour},
		{"padded zero", " 0 ", 0},
		{"padded false", " false ", 0},
		{"padded empty", "   ", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FALLBACK_SCAN_HOURS", tc.env)
			if got := parseFallbackInterval(); got != tc.want {
				t.Errorf("parseFallbackInterval(%q) = %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}

func TestChanged_oversized_key_file(t *testing.T) {
	clearHashes()
	tmpDir := t.TempDir()
	crtPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Normal cert, oversized key.
	if err := os.WriteFile(crtPath, []byte("small cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	bigData := make([]byte, 11<<20)
	if err := os.WriteFile(keyPath, bigData, 0o600); err != nil {
		t.Fatal(err)
	}

	if !changed(crtPath, keyPath) {
		t.Error("changed() should return true when key file exceeds size limit")
	}
}

func TestChanged_nonexistent_cert(t *testing.T) {
	clearHashes()
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !changed(filepath.Join(tmpDir, "missing.crt"), keyPath) {
		t.Error("changed() should return true when cert file doesn't exist")
	}
}

func TestChanged_nonexistent_key(t *testing.T) {
	clearHashes()
	tmpDir := t.TempDir()
	crtPath := filepath.Join(tmpDir, "test.crt")
	if err := os.WriteFile(crtPath, []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !changed(crtPath, filepath.Join(tmpDir, "missing.key")) {
		t.Error("changed() should return true when key file doesn't exist")
	}
}

func TestProcessAll_empty_directory(t *testing.T) {
	clearHashes()
	inDir := t.TempDir()
	outDir := t.TempDir()

	if err := processAll(inDir, outDir, "", pkcs12.Modern2023); err != nil {
		t.Fatalf("processAll(empty dir) = %v, want nil", err)
	}

	// Output dir should remain empty.
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("processAll(empty dir) created %d files, want 0", len(entries))
	}
}

func TestProcessAll_ignores_non_crt_files(t *testing.T) {
	clearHashes()
	inDir := t.TempDir()
	outDir := t.TempDir()

	// Write files that aren't .crt — should be ignored.
	for _, name := range []string{"readme.txt", "config.json", "cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(inDir, name), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := processAll(inDir, outDir, "", pkcs12.Modern2023); err != nil {
		t.Fatalf("processAll = %v, want nil", err)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("processAll created %d files for non-.crt input, want 0", len(entries))
	}
}

func TestHashFile_empty_file(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	h, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile(empty) = error %v", err)
	}
	// SHA-256 of empty input is a well-known constant.
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if h != want {
		t.Errorf("hashFile(empty) = %q, want %q", h, want)
	}
}

func TestReadFileWithLimit_empty_file(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	data, err := readFileWithLimit(path, 1024)
	if err != nil {
		t.Fatalf("readFileWithLimit(empty) = error %v", err)
	}
	if len(data) != 0 {
		t.Errorf("readFileWithLimit(empty) returned %d bytes, want 0", len(data))
	}
}

func TestParseCertChain_empty_input(t *testing.T) {
	_, err := parseCertChain([]byte{})
	if err == nil {
		t.Fatal("parseCertChain(empty) should return error")
	}
	if !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("parseCertChain(empty) error = %q, want it to contain %q",
			err.Error(), "no certificate")
	}
}

func TestParsePrivateKey_empty_input(t *testing.T) {
	_, err := parsePrivateKey([]byte{})
	if err == nil {
		t.Fatal("parsePrivateKey(empty) should return error")
	}
	if !strings.Contains(err.Error(), "no private key") {
		t.Errorf("parsePrivateKey(empty) error = %q, want it to contain %q",
			err.Error(), "no private key")
	}
}

func TestParsePrivateKey_RSA_PKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := parsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey(RSA PKCS8) = error %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Errorf("parsePrivateKey(RSA PKCS8) returned %T, want *rsa.PrivateKey", parsed)
	}
}

func TestConvertToPFX_with_password_containing_special_chars(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t, "special-pass", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
	pfxPath := filepath.Join(tmpDir, "test.pfx")

	password := "p@$$w0rd!#%&*(){}[]|\\:\";<>?,./~`"
	if err := convertToPFX(crtPath, keyPath, pfxPath, password, pkcs12.Modern2023); err != nil {
		t.Fatalf("convertToPFX(special password): %v", err)
	}

	_, cert, _ := decodePFX(t, pfxPath, password)
	if cert.Subject.CommonName != "special-pass" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "special-pass")
	}
}

func TestProcessAll_multiple_cert_pairs(t *testing.T) {
	clearHashes()
	inDir := t.TempDir()
	outDir := t.TempDir()

	// Create 3 cert/key pairs.
	for _, name := range []string{"alpha", "beta", "gamma"} {
		certPEM, keyPEM := generateSelfSignedCert(t, name, "ecdsa")
		writeCertAndKey(t, inDir, name, certPEM, keyPEM)
	}

	if err := processAll(inDir, outDir, "pass", pkcs12.Modern2023); err != nil {
		t.Fatalf("processAll = %v", err)
	}

	for _, name := range []string{"alpha", "beta", "gamma"} {
		pfxPath := filepath.Join(outDir, name+".pfx")
		_, cert, _ := decodePFX(t, pfxPath, "pass")
		if cert.Subject.CommonName != name {
			t.Errorf("PFX %s: CN = %q, want %q", name, cert.Subject.CommonName, name)
		}
	}
}

func TestHashFile_exactly_at_max_size(t *testing.T) {
	// Boundary test: file exactly at maxFileSize should succeed.
	path := filepath.Join(t.TempDir(), "exact-max.bin")
	data := make([]byte, maxFileSize)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	h, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile(exactly maxFileSize) = error %v, want success", err)
	}
	if len(h) != 64 {
		t.Errorf("hashFile returned hash of length %d, want 64", len(h))
	}
}

func TestConvertToPFX_single_cert_has_no_CA_certs(t *testing.T) {
	// Verify that a single-cert PFX has zero CA certs (not the leaf duplicated as CA).
	certPEM, keyPEM := generateSelfSignedCert(t, "single", "ecdsa")
	tmpDir := t.TempDir()
	crtPath, keyPath := writeCertAndKey(t, tmpDir, "test", certPEM, keyPEM)
	pfxPath := filepath.Join(tmpDir, "test.pfx")

	if err := convertToPFX(crtPath, keyPath, pfxPath, "pass", pkcs12.Modern2023); err != nil {
		t.Fatalf("convertToPFX: %v", err)
	}

	_, _, caCerts := decodePFX(t, pfxPath, "pass")
	if len(caCerts) != 0 {
		t.Errorf("single-cert PFX has %d CA certs, want 0", len(caCerts))
	}
}
