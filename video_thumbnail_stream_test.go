package main

import (
	"bytes"
	"image/jpeg"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func TestGenerateVideoThumbnailFromReader(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed")
	}

	// Build a short test clip with ffmpeg itself
	videoPath := filepath.Join(t.TempDir(), "clip.mp4")
	cmd := exec.Command("ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc=duration=2:size=320x240:rate=10",
		"-pix_fmt", "yuv420p", "-y", videoPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to create test video: %v: %s", err, out)
	}
	videoData, err := os.ReadFile(videoPath)
	if err != nil {
		t.Fatal(err)
	}

	// Run concurrently to catch shared temp file collisions
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			thumb, err := generateVideoThumbnailFromReader(bytes.NewReader(videoData), "clip.mp4")
			if err != nil {
				errs <- err
				return
			}
			img, err := jpeg.Decode(bytes.NewReader(thumb))
			if err != nil {
				errs <- err
				return
			}
			if b := img.Bounds(); b.Dx() != 200 || b.Dy() != 200 {
				t.Errorf("thumbnail size = %dx%d, want 200x200", b.Dx(), b.Dy())
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("generateVideoThumbnailFromReader() error = %v", err)
	}
}

func TestGenerateVideoThumbnailShortClip(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not installed")
	}

	// Shorter than the 1s seek offset: must fall back to the first frame
	videoPath := filepath.Join(t.TempDir(), "short.mp4")
	cmd := exec.Command("ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc=duration=0.5:size=320x240:rate=10",
		"-pix_fmt", "yuv420p", "-y", videoPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to create test video: %v: %s", err, out)
	}
	f, err := os.Open(videoPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := generateVideoThumbnailFromReader(f, "short.mp4"); err != nil {
		t.Errorf("short clip thumbnail error = %v", err)
	}
}
