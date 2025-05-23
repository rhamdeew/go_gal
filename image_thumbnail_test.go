package main

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"
)

func TestGenerateImageThumbnail(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		data     []byte
		wantErr  bool
	}{
		{
			name:     "JPEG image",
			filename: "test.jpg",
			data:     createTestJPEG(),
			wantErr:  false,
		},
		{
			name:     "PNG image",
			filename: "test.png",
			data:     createTestPNG(),
			wantErr:  false,
		},
		{
			name:     "GIF image",
			filename: "test.gif",
			data:     createTestGIF(),
			wantErr:  false,
		},
		{
			name:     "Unsupported format",
			filename: "test.bmp",
			data:     []byte("invalid image data"),
			wantErr:  true,
		},
		{
			name:     "Invalid JPEG data",
			filename: "test.jpg",
			data:     []byte("invalid jpeg data"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thumbnailData, err := generateImageThumbnail(tt.data, tt.filename)

			if tt.wantErr {
				if err == nil {
					t.Errorf("generateImageThumbnail() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("generateImageThumbnail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(thumbnailData) == 0 {
				t.Error("generateImageThumbnail() returned empty thumbnail data")
			}

			// Verify the thumbnail is valid JPEG
			_, err = jpeg.Decode(bytes.NewReader(thumbnailData))
			if err != nil {
				t.Errorf("Generated thumbnail is not valid JPEG: %v", err)
			}
		})
	}
}

func TestCreateThumbnail(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name     string
		filename string
		data     []byte
		wantErr  bool
	}{
		{
			name:     "Image file",
			filename: "test.jpg",
			data:     createTestJPEG(),
			wantErr:  false,
		},
		{
			name:     "Video file (no ffmpeg)",
			filename: "test.mp4",
			data:     []byte("fake video data"),
			wantErr:  true, // Will fail because ffmpeg not available in test environment
		},
		{
			name:     "Unsupported file type",
			filename: "test.txt",
			data:     []byte("text file"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thumbnailData, err := createThumbnail(tt.data, tt.filename, passwordHash)

			if tt.wantErr {
				if err == nil {
					t.Errorf("createThumbnail() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("createThumbnail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(thumbnailData) == 0 {
				t.Error("createThumbnail() returned empty thumbnail data")
			}
		})
	}
}

func TestIsImageFile(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"test.jpg", true},
		{"test.jpeg", true},
		{"test.png", true},
		{"test.gif", true},
		{"test.webp", true},
		{"TEST.JPG", true}, // Test case insensitivity
		{"test.txt", false},
		{"test.mp4", false},
		{"test", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := isImageFile(tt.filename)
			if result != tt.expected {
				t.Errorf("isImageFile(%s) = %v, want %v", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestIsVideoFile(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"test.mp4", true},
		{"test.mov", true},
		{"test.avi", true},
		{"test.mkv", true},
		{"test.webm", true},
		{"test.3gp", true},
		{"test.flv", true},
		{"test.wmv", true},
		{"test.m4v", true},
		{"TEST.MP4", true}, // Test case insensitivity
		{"test.jpg", false},
		{"test.txt", false},
		{"test", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := isVideoFile(tt.filename)
			if result != tt.expected {
				t.Errorf("isVideoFile(%s) = %v, want %v", tt.filename, result, tt.expected)
			}
		})
	}
}

// Helper functions to create test images

func createTestJPEG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))

	// Fill with a simple pattern
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			img.Set(x, y, image.NewRGBA(image.Rect(0, 0, 1, 1)).At(0, 0))
		}
	}

	var buf bytes.Buffer
	jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85})
	return buf.Bytes()
}

func createTestPNG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func createTestGIF() []byte {
	// Create a simple palette
	palette := color.Palette{
		color.RGBA{0x00, 0x00, 0x00, 0xff}, // Black
		color.RGBA{0xff, 0xff, 0xff, 0xff}, // White
		color.RGBA{0xff, 0x00, 0x00, 0xff}, // Red
		color.RGBA{0x00, 0xff, 0x00, 0xff}, // Green
	}

	img := image.NewPaletted(image.Rect(0, 0, 100, 100), palette)

	// Fill with a simple pattern
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			if (x+y)%2 == 0 {
				img.SetColorIndex(x, y, 0) // Black
			} else {
				img.SetColorIndex(x, y, 1) // White
			}
		}
	}

	var buf bytes.Buffer
	gif.Encode(&buf, img, nil)
	return buf.Bytes()
}
