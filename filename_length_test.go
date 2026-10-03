package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestEncryptFileNameFitsFilesystemLimit(t *testing.T) {
	t.Parallel()

	passwordHash := hashPassword("test-password")

	tests := []struct {
		name     string
		filename string
	}{
		{"Cyrillic 106 bytes", "КАК КОУЧИ, ИНФОЦЫГАНЕ И PDF'ы ЗАГУБИЛИ ИНСТАГРАМ＊ [tZ32h0Q8px8].mp4"},
		{"Cyrillic 124 bytes", "Читерство в автоспорте! Истории нарушения правил в гонках [PRct_nIcyuI].mp4"},
		{"ASCII exactly at limit", strings.Repeat("a", maxFileNameBytes-4) + ".mp4"},
		{"ASCII 1000 bytes", strings.Repeat("a", 1000) + ".mp4"},
		{"Long extension", "video." + strings.Repeat("x", 200)},
		{"Short name", "clip.mp4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encrypted, err := encryptFileName(tt.filename, passwordHash)
			if err != nil {
				t.Fatalf("encryptFileName() error = %v", err)
			}

			onDisk := encrypted + encryptedExt
			if len(onDisk) > 255 {
				t.Errorf("on-disk name is %d bytes, exceeds 255", len(onDisk))
			}

			decrypted, err := decryptFileName(encrypted, passwordHash)
			if err != nil {
				t.Fatalf("decryptFileName() error = %v", err)
			}
			if !utf8.ValidString(decrypted) {
				t.Errorf("decrypted name is not valid UTF-8: %q", decrypted)
			}
			if len(tt.filename) <= maxFileNameBytes && decrypted != tt.filename {
				t.Errorf("short name changed: got %q, want %q", decrypted, tt.filename)
			}
			if len(tt.filename) > maxFileNameBytes && strings.HasSuffix(tt.filename, ".mp4") && !strings.HasSuffix(decrypted, ".mp4") {
				t.Errorf("extension lost: %q", decrypted)
			}
		})
	}
}
