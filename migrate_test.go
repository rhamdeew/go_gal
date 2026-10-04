package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// encryptFileNameV1ForTest produces a legacy v1 encrypted name:
// hex(IV + CFB(name) + CFB(validation tag restarted from IV))
func encryptFileNameV1ForTest(t *testing.T, name, passwordHash string) string {
	t.Helper()
	block, err := createAESCipher(passwordHash)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatal(err)
	}
	encName := make([]byte, len(name))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(encName, []byte(name))
	encTag := make([]byte, 4)
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(encTag, []byte("GOCR"))

	out := append(append(append([]byte{}, iv...), encName...), encTag...)
	return hex.EncodeToString(out)
}

// writeV1File writes legacy v1 content; with firstByte >= 0 it retries until the
// random IV starts with that byte
func writeV1File(t *testing.T, path string, data []byte, passwordHash string, firstByte int) {
	t.Helper()
	for {
		if err := encryptAndSaveFileV1(data, path, passwordHash); err != nil {
			t.Fatal(err)
		}
		if firstByte < 0 {
			return
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 1)
		f.Read(b)
		f.Close()
		if int(b[0]) == firstByte {
			return
		}
	}
}

func TestRunMigration(t *testing.T) {
	// Not parallel: points the global gallery directories at a temp dir
	origGallery, origThumbs := galleryDir, thumbnailsDir
	root := t.TempDir()
	galleryDir = filepath.Join(root, "gallery")
	thumbnailsDir = filepath.Join(root, "thumbnails")
	defer func() { galleryDir, thumbnailsDir = origGallery, origThumbs }()

	password := "migration-test-password"
	oldHash := hashPasswordLegacy(password)
	newHash := hashPassword(password)

	longName := strings.Repeat("я", 48) + ".jpg" // 100 bytes: fits v1, too long for v2 untrimmed
	type item struct {
		dir       string // plaintext parent dir, "" for root
		name      string
		content   string
		firstByte int // force the v1 IV's first byte, -1 for random
	}
	items := []item{
		{"", "plain.jpg", "plain content", -1},
		{"", "magic.jpg", "content whose IV starts with the v2 magic byte", int(fileFormatV2Magic)},
		{"", longName, "long name content", -1},
		{"Отпуск", "nested.mp4", "nested content", -1},
	}

	// Build the v1 gallery with a thumbnail for every file at the matching path
	encDirName := encryptFileNameV1ForTest(t, "Отпуск", oldHash) + encryptedExt
	for _, base := range []string{galleryDir, thumbnailsDir} {
		if err := os.MkdirAll(filepath.Join(base, encDirName), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, it := range items {
		rel := encryptFileNameV1ForTest(t, it.name, oldHash) + encryptedExt
		if it.dir != "" {
			rel = filepath.Join(encDirName, rel)
		}
		writeV1File(t, filepath.Join(galleryDir, rel), []byte(it.content), oldHash, it.firstByte)
		writeV1File(t, filepath.Join(thumbnailsDir, rel), []byte("thumb:"+it.content), oldHash, it.firstByte)
	}

	if err := runMigration(password); err != nil {
		t.Fatalf("runMigration() error = %v", err)
	}

	// Collect migrated files: decrypt every path component and content with the new key
	listEnc := func(base string) map[string]string {
		result := map[string]string{} // encrypted rel path -> decrypted "dir/name"
		filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(base, path)
			var parts []string
			for _, p := range strings.Split(rel, string(filepath.Separator)) {
				name, err := decryptFileName(strings.TrimSuffix(p, encryptedExt), newHash)
				if err != nil {
					t.Errorf("%s: name %s not readable with new key: %v", base, p, err)
					return nil
				}
				parts = append(parts, name)
			}
			result[rel] = strings.Join(parts, "/")
			return nil
		})
		return result
	}
	gallery := listEnc(galleryDir)
	thumbs := listEnc(thumbnailsDir)

	if len(gallery) != len(items) {
		t.Fatalf("gallery has %d files after migration, want %d", len(gallery), len(items))
	}

	var names []string
	for rel, name := range gallery {
		names = append(names, name)

		// Thumbnail must sit at exactly the same encrypted path
		if _, ok := thumbs[rel]; !ok {
			t.Errorf("thumbnail for %q not found at matching path", name)
		}

		data, err := decryptFile(filepath.Join(galleryDir, rel), newHash)
		if err != nil {
			t.Errorf("content of %q not readable with new key: %v", name, err)
			continue
		}
		if !strings.Contains(string(data), "content") {
			t.Errorf("content of %q = %q, unexpected", name, data)
		}

		if len(rel) > 0 {
			for _, p := range strings.Split(rel, string(filepath.Separator)) {
				if len(p) > 255 {
					t.Errorf("path component is %d bytes, exceeds 255", len(p))
				}
			}
		}
	}

	sort.Strings(names)
	for _, want := range []string{"magic.jpg", "plain.jpg", "Отпуск/nested.mp4"} {
		if i := sort.SearchStrings(names, want); i >= len(names) || names[i] != want {
			t.Errorf("missing %q after migration, got %v", want, names)
		}
	}
	foundLong := false
	for _, n := range names {
		if strings.HasPrefix(n, "яяя") && strings.HasSuffix(n, ".jpg") {
			foundLong = true
		}
	}
	if !foundLong {
		t.Errorf("long-named file missing after migration, got %v", names)
	}

	// Running again must be a no-op
	if err := runMigration(password); err != nil {
		t.Errorf("second runMigration() error = %v", err)
	}
	if again := listEnc(galleryDir); len(again) != len(items) {
		t.Errorf("second run changed file count to %d", len(again))
	}
}
