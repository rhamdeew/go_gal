package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/nfnt/resize"
	"golang.org/x/image/webp"
)

// Global variables
var (
	// Get executable directory for loading templates
	execDir = func() string {
		execPath, err := os.Executable()
		if err != nil {
			log.Println("Warning: Could not determine executable path, using current directory")
			return "."
		}
		return filepath.Dir(execPath)
	}()
	templates *template.Template
	store     = func() *sessions.CookieStore {
		sessionKey := os.Getenv("GO_GAL_SESSION_KEY")
		if sessionKey == "" {
			log.Println("Warning: Using default session key. For production, set GO_GAL_SESSION_KEY environment variable.")
			sessionKey = "gocrypto-gallery-session-key"
		}
		return sessions.NewCookieStore([]byte(sessionKey))
	}()
	saltBytes = func() []byte {
		salt := os.Getenv("GO_GAL_SALT")
		if salt == "" {
			log.Println("Warning: Using default salt. For production, set GO_GAL_SALT environment variable.")
			salt = "gallery-salt"
		}
		return []byte(salt)
	}()
	galleryDir   = filepath.Join(execDir, "gallery")
	thumbnailsDir = filepath.Join(execDir, "thumbnails")
	encryptedExt = ".enc" // Extension for encrypted files
)

// Initialize the cookie store with proper options
func init() {
	// Initialize templates - this will be skipped in tests
	templatesPath := filepath.Join(execDir, "templates", "*.html")
	var err error
	templates, err = template.ParseGlob(templatesPath)
	if err != nil {
		// In test environment, create a minimal template
		if strings.Contains(execDir, "go-build") || strings.Contains(execDir, "test") {
			log.Println("Running in test environment, using mock templates")
			templates = template.Must(template.New("login.html").Parse(`<html><body>Login Form {{if .Error}}{{.Error}}{{end}}</body></html>`))
			template.Must(templates.New("gallery.html").Parse(`<html><body>Gallery {{if .Error}}{{.Error}}{{end}}</body></html>`))
		} else {
			// In production, this is a fatal error
			log.Fatalf("Failed to parse templates from %s: %v", templatesPath, err)
		}
	}

	// Detect if SSL/TLS is enabled through environment variable
	sslEnabled := os.Getenv("GO_GAL_SSL_ENABLED") == "true"

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   15 * 60, // 15 minutes
		HttpOnly: true,
		Secure:   sslEnabled, // Only set to true when running with HTTPS
		SameSite: http.SameSiteLaxMode,
	}
}

// GalleryItem represents a file or folder in the gallery
type GalleryItem struct {
	Name    string
	IsDir   bool
	Path    string
	EncPath string // Encrypted path name (for display)
}

// PageData contains data for template rendering
type PageData struct {
	CurrentPath string
	Items       []GalleryItem
	Error       string
	Breadcrumbs []Breadcrumb
}

// Breadcrumb represents a path segment in the navigation
type Breadcrumb struct {
	Name string // Decrypted display name
	Path string // Encrypted path for URL
}

// buildBreadcrumbs creates a breadcrumb trail with decrypted directory names
func buildBreadcrumbs(currentPath string, passwordHash string) []Breadcrumb {
	breadcrumbs := []Breadcrumb{
		{Name: "Home", Path: "/"},
	}

	if currentPath == "" || currentPath == "/" {
		return breadcrumbs
	}

	// Split path into segments
	segments := strings.Split(strings.Trim(currentPath, "/"), "/")
	cumulativePath := ""

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		// Build cumulative path for URL
		if cumulativePath == "" {
			cumulativePath = segment
		} else {
			cumulativePath = cumulativePath + "/" + segment
		}

		// Try to decrypt the segment name
		// Remove .enc extension if present
		encSegment := segment
		if strings.HasSuffix(encSegment, encryptedExt) {
			encSegment = strings.TrimSuffix(encSegment, encryptedExt)
		}

		decryptedName, err := decryptFileName(encSegment, passwordHash)
		if err != nil {
			// If decryption fails, use the encrypted name (truncated for display)
			displayName := encSegment
			if len(displayName) > 20 {
				displayName = displayName[:17] + "..."
			}
			decryptedName = displayName
		}

		breadcrumbs = append(breadcrumbs, Breadcrumb{
			Name: decryptedName,
			Path: "/" + cumulativePath,
		})
	}

	return breadcrumbs
}

func main() {
	// Parse command-line flags
	port := flag.String("port", "8080", "Port to listen on")
	host := flag.String("host", "localhost", "Host IP address to bind to")
	enableSSL := flag.Bool("ssl", false, "Enable HTTPS with self-signed certificates")
	certFile := flag.String("cert", "cert.pem", "Path to SSL certificate file")
	keyFile := flag.String("key", "key.pem", "Path to SSL key file")
	flag.Parse()

	// Set SSL environment variable based on command-line flag
	if *enableSSL {
		if err := os.Setenv("GO_GAL_SSL_ENABLED", "true"); err != nil {
			log.Printf("Warning: Failed to set GO_GAL_SSL_ENABLED environment variable: %v", err)
		}
	}

	// Create gallery directory if it doesn't exist
	if _, err := os.Stat(galleryDir); os.IsNotExist(err) {
		err = os.MkdirAll(galleryDir, 0750)
		if err != nil {
			log.Fatalf("Failed to create gallery directory: %v", err)
		}
		log.Printf("Created gallery directory at: %s", galleryDir)
	}

	// Create thumbnails directory if it doesn't exist
	if _, err := os.Stat(thumbnailsDir); os.IsNotExist(err) {
		err = os.MkdirAll(thumbnailsDir, 0750)
		if err != nil {
			log.Fatalf("Failed to create thumbnails directory: %v", err)
		}
		log.Printf("Created thumbnails directory at: %s", thumbnailsDir)
	}

	r := mux.NewRouter()

	// Define routes
	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/gallery/{path:.*}", galleryHandler)
	r.HandleFunc("/upload", uploadHandler).Methods("POST")
	r.HandleFunc("/createdir", createDirHandler).Methods("POST")
	r.HandleFunc("/delete", deleteHandler).Methods("POST")
	r.HandleFunc("/view/{path:.*}", viewHandler)
	r.HandleFunc("/thumbnail/{path:.*}", thumbnailHandler)
	r.HandleFunc("/logout", logoutHandler)

	// Serve favicon and manifest from root paths (browser defaults)
	r.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(execDir, "static", "images", "favicon.ico"))
	})
	r.HandleFunc("/site.webmanifest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/manifest+json")
		http.ServeFile(w, r, filepath.Join(execDir, "static", "images", "site.webmanifest"))
	})

	// Set up static file server for CSS, JS
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join(execDir, "static")))))

	// Construct server address from flags
	serverAddr := fmt.Sprintf("%s:%s", *host, *port)

	// Start the server
	if *enableSSL {
		// Check if certificate files exist, if not generate them
		_, err1 := os.Stat(*certFile)
		_, err2 := os.Stat(*keyFile)

		if os.IsNotExist(err1) || os.IsNotExist(err2) {
			log.Println("SSL certificates not found, generating self-signed certificates...")
			err := generateSelfSignedCert(*certFile, *keyFile)
			if err != nil {
				log.Fatalf("Failed to generate SSL certificates: %v", err)
			}
			log.Printf("Generated self-signed certificates at %s and %s", *certFile, *keyFile)
		}

		// Configure TLS
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		server := &http.Server{
			Addr:              serverAddr,
			Handler:           r,
			TLSConfig:         tlsConfig,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		fmt.Printf("Server started with HTTPS at https://%s:%s\n", *host, *port)
		log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))
	} else {
		fmt.Printf("Server started at http://%s:%s\n", *host, *port)
		server := &http.Server{
			Addr:              serverAddr,
			Handler:           r,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		log.Fatal(server.ListenAndServe())
	}
}

// generateSelfSignedCert generates a self-signed certificate and key
func generateSelfSignedCert(certPath, keyPath string) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Set certificate properties
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Go Crypto Gallery"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Add IP address to the certificate
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	// Write certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return err
	}

	// Write private key to file
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	err = pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return err
	}

	return nil
}

// isImageFile checks if a file is an image based on its extension
func isImageFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp":
		return true
	}
	return false
}

// isVideoFile checks if a file is a video based on its extension
func isVideoFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".mp4", ".mov", ".avi", ".mkv", ".webm", ".3gp", ".flv", ".wmv", ".m4v":
		return true
	}
	return false
}

// generateImageThumbnail creates a thumbnail from an image
func generateImageThumbnail(imageData []byte, filename string) ([]byte, error) {
	// Decode the image
	var img image.Image
	var err error

	ext := strings.ToLower(filepath.Ext(filename))
	reader := strings.NewReader(string(imageData))

	switch ext {
	case ".jpg", ".jpeg":
		img, err = jpeg.Decode(reader)
	case ".png":
		img, err = png.Decode(reader)
	case ".gif":
		img, err = gif.Decode(reader)
	case ".webp":
		img, err = webp.Decode(reader)
	default:
		return nil, fmt.Errorf("unsupported image format: %s", ext)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %v", err)
	}

	// Resize the image to thumbnail size (200x200 max, maintaining aspect ratio)
	thumbnail := resize.Thumbnail(200, 200, img, resize.Lanczos3)

	// Encode as JPEG for consistent thumbnail format
	var buf bytes.Buffer
	err = jpeg.Encode(&buf, thumbnail, &jpeg.Options{Quality: 85})
	if err != nil {
		return nil, fmt.Errorf("failed to encode thumbnail: %v", err)
	}

	return buf.Bytes(), nil
}

// generateVideoThumbnail creates a thumbnail from a video using ffmpeg
func generateVideoThumbnail(videoPath, outputPath string) error {
	// Check if ffmpeg is available
	_, err := exec.LookPath("ffmpeg")
	if err != nil {
		return fmt.Errorf("ffmpeg not found in PATH, cannot generate video thumbnails")
	}

	// Use ffmpeg to extract a frame at 1 second
	cmd := exec.Command("ffmpeg",
		"-i", videoPath,
		"-ss", "00:00:01.000",
		"-vframes", "1",
		"-vf", "scale=200:200:force_original_aspect_ratio=decrease,pad=200:200:(ow-iw)/2:(oh-ih)/2",
		"-y", // Overwrite output file
		outputPath)

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("ffmpeg failed: %v", err)
	}

	return nil
}

// createThumbnail generates and saves an encrypted thumbnail
func createThumbnail(originalData []byte, filename string, passwordHash string) ([]byte, error) {
	var thumbnailData []byte
	var err error

	if isImageFile(filename) {
		thumbnailData, err = generateImageThumbnail(originalData, filename)
		if err != nil {
			return nil, fmt.Errorf("failed to generate image thumbnail: %v", err)
		}
	} else if isVideoFile(filename) {
		// For videos, we need to temporarily save the file to process it with ffmpeg
		tempDir := filepath.Join(os.TempDir(), "go_gal_temp")
		err := os.MkdirAll(tempDir, 0755)
		if err != nil {
			return nil, fmt.Errorf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tempDir)

		tempVideoPath := filepath.Join(tempDir, "temp_video"+filepath.Ext(filename))
		tempThumbnailPath := filepath.Join(tempDir, "thumbnail.jpg")

		// Write video data to temp file
		err = os.WriteFile(tempVideoPath, originalData, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to write temp video file: %v", err)
		}

		// Generate thumbnail
		err = generateVideoThumbnail(tempVideoPath, tempThumbnailPath)
		if err != nil {
			return nil, fmt.Errorf("failed to generate video thumbnail: %v", err)
		}

		// Read the generated thumbnail
		thumbnailData, err = os.ReadFile(tempThumbnailPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read generated thumbnail: %v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported file type for thumbnail generation")
	}

	return thumbnailData, nil
}

// generatePlaceholderImage creates a simple placeholder image for videos
func generatePlaceholderImage(filename string) []byte {
	// Create a simple colored rectangle as placeholder
	img := image.NewRGBA(image.Rect(0, 0, 200, 200))

	// Set background color based on file type
	isVideo := isVideoFile(filename)
	var bgR, bgG, bgB uint8

	if isVideo {
		// Blue gradient for videos
		bgR, bgG, bgB = 102, 126, 234
	} else {
		// Gray for images or unknown
		bgR, bgG, bgB = 240, 240, 240
	}

	// Fill background
	for y := 0; y < 200; y++ {
		for x := 0; x < 200; x++ {
			img.Set(x, y, color.RGBA{bgR, bgG, bgB, 255})
		}
	}

	// Create a gradient effect
	for y := 0; y < 200; y++ {
		for x := 0; x < 200; x++ {
			factor := float64(y) / 200.0 * 0.3 // 30% gradient
			newR := uint8(float64(bgR) * (1.0 - factor))
			newG := uint8(float64(bgG) * (1.0 - factor))
			newB := uint8(float64(bgB) * (1.0 - factor))
			img.Set(x, y, color.RGBA{newR, newG, newB, 255})
		}
	}

	// Add a simple border
	borderColor := color.RGBA{uint8(float64(bgR) * 0.7), uint8(float64(bgG) * 0.7), uint8(float64(bgB) * 0.7), 255}

	// Top and bottom borders
	for x := 0; x < 200; x++ {
		img.Set(x, 0, borderColor)
		img.Set(x, 1, borderColor)
		img.Set(x, 198, borderColor)
		img.Set(x, 199, borderColor)
	}

	// Left and right borders
	for y := 0; y < 200; y++ {
		img.Set(0, y, borderColor)
		img.Set(1, y, borderColor)
		img.Set(198, y, borderColor)
		img.Set(199, y, borderColor)
	}

	// Encode as JPEG
	var buf bytes.Buffer
	err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85})
	if err != nil {
		log.Printf("Error encoding placeholder image: %v", err)
		// Return a minimal JPEG if encoding fails
		return []byte{}
	}

	return buf.Bytes()
}

// indexHandler shows the login page or redirects to gallery if already logged in
func indexHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "gallery-session")
	if err != nil {
		log.Printf("Session error in indexHandler: %v", err)
		// Continue to login page if there's a session error
	} else if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		http.Redirect(w, r, "/gallery/", http.StatusSeeOther)
		return
	}

	// Check for error parameters
	errorMsg := ""
	if errParam := r.URL.Query().Get("error"); errParam == "incorrect_password" {
		errorMsg = "Incorrect password. Please try again."
	}

	if err := templates.ExecuteTemplate(w, "login.html", PageData{Error: errorMsg}); err != nil {
		log.Printf("Error executing login template: %v", err)
		http.Error(w, "Error rendering login page", http.StatusInternalServerError)
	}
}

// loginHandler processes the login form
func loginHandler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	if password == "" {
		if err := templates.ExecuteTemplate(w, "login.html", PageData{Error: "Password required"}); err != nil {
			log.Printf("Error executing login template: %v", err)
			http.Error(w, "Error rendering login page", http.StatusInternalServerError)
		}
		return
	}

	// Store password hash in session for later decryption
	// We don't store the actual password
	session, err := store.Get(r, "gallery-session")
	if err != nil {
		log.Printf("Failed to get session: %v", err)
		if err := templates.ExecuteTemplate(w, "login.html", PageData{Error: "Session error, please try again"}); err != nil {
			log.Printf("Error executing login template: %v", err)
			http.Error(w, "Error rendering login page", http.StatusInternalServerError)
		}
		return
	}

	session.Values["password_hash"] = hashPassword(password)
	session.Values["authenticated"] = true

	if err := session.Save(r, w); err != nil {
		log.Printf("Failed to save session: %v", err)
		if err := templates.ExecuteTemplate(w, "login.html", PageData{Error: "Failed to save session"}); err != nil {
			log.Printf("Error executing login template: %v", err)
			http.Error(w, "Error rendering login page", http.StatusInternalServerError)
		}
		return
	}

	http.Redirect(w, r, "/gallery/", http.StatusSeeOther)
}

// galleryHandler shows the contents of the gallery or a specific directory
func galleryHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "gallery-session")
	if err != nil {
		log.Printf("Failed to get session in galleryHandler: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		log.Printf("Authentication failed: ok=%v, auth=%v", ok, auth)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	passwordHash, ok := session.Values["password_hash"].(string)
	if !ok {
		log.Printf("Failed to retrieve password hash from session")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	vars := mux.Vars(r)
	requestPath := vars["path"]
	if requestPath == "" {
		requestPath = "/"
	}

	// Sanitize the path to prevent directory traversal
	cleanPath := filepath.Clean(requestPath)
	cleanPath = strings.Replace(cleanPath, "\\", "/", -1) // Normalize backslashes
	if cleanPath != "/" && strings.HasPrefix(cleanPath, "/") {
		cleanPath = cleanPath[1:] // Remove leading slash for proper joining
	}

	// Ensure we're not accessing anything outside gallery directory
	fsPath := filepath.Join(galleryDir, cleanPath)
	if !strings.HasPrefix(fsPath, galleryDir) {
		if err := templates.ExecuteTemplate(w, "gallery.html", PageData{
			Error:       "Invalid directory path",
			CurrentPath: cleanPath,
			Breadcrumbs: buildBreadcrumbs(cleanPath, passwordHash),
		}); err != nil {
			log.Printf("Error executing template: %v", err)
			http.Error(w, "Error rendering template", http.StatusInternalServerError)
		}
		return
	}

	info, err := os.Stat(fsPath)
	if os.IsNotExist(err) {
		if err := templates.ExecuteTemplate(w, "gallery.html", PageData{
			Error:       "Path does not exist",
			CurrentPath: cleanPath,
			Breadcrumbs: buildBreadcrumbs(cleanPath, passwordHash),
		}); err != nil {
			log.Printf("Error executing template: %v", err)
			http.Error(w, "Error rendering template", http.StatusInternalServerError)
		}
		return
	}

	if !info.IsDir() {
		http.Error(w, "Not a directory", http.StatusBadRequest)
		return
	}

	// Read directory contents
	files, err := os.ReadDir(fsPath)
	if err != nil {
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}

	var items []GalleryItem
	var wrongPasswordDetected bool

	for _, file := range files {
		name := file.Name()

		// For both directories and files, check if they have the encrypted extension
		if strings.HasSuffix(name, encryptedExt) {
			encName := strings.TrimSuffix(name, encryptedExt)
			decryptedName, err := decryptFileName(encName, passwordHash)

			if err != nil {
				// If we have a password verification error, note that
				if strings.Contains(err.Error(), "incorrect password") {
					wrongPasswordDetected = true
				}
				log.Printf("Error decrypting filename %s: %v", name, err)
				continue
			}

			itemPath := filepath.Join(cleanPath, name)
			// Remove leading slash if present
			if itemPath != "/" && strings.HasPrefix(itemPath, "/") {
				itemPath = itemPath[1:]
			}

			items = append(items, GalleryItem{
				Name:    decryptedName,
				IsDir:   file.IsDir(),
				Path:    itemPath,
				EncPath: name,
			})
		}
	}

	// If we detected wrong password and couldn't decrypt any files
	if wrongPasswordDetected && len(items) == 0 {
		// Invalidate the user's session
		session.Values["authenticated"] = false
		session.Values["password_hash"] = ""
		if err := session.Save(r, w); err != nil {
			log.Printf("Error saving session: %v", err)
		}

		// Redirect to login page with error
		http.Redirect(w, r, "/?error=incorrect_password", http.StatusSeeOther)
		return
	}

	if err := templates.ExecuteTemplate(w, "gallery.html", PageData{
		CurrentPath: cleanPath,
		Items:       items,
		Breadcrumbs: buildBreadcrumbs(cleanPath, passwordHash),
	}); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

// viewHandler decrypts and serves a file for viewing with Range request support for videos
func viewHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "gallery-session")
	if err != nil {
		log.Printf("Failed to get session in viewHandler: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		log.Printf("Authentication failed in viewHandler: ok=%v, auth=%v", ok, auth)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	passwordHash, ok := session.Values["password_hash"].(string)
	if !ok {
		log.Printf("Failed to retrieve password hash from session in viewHandler")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	vars := mux.Vars(r)
	requestPath := vars["path"]
	if requestPath == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Sanitize the path to prevent directory traversal
	cleanPath := filepath.Clean(requestPath)
	cleanPath = strings.Replace(cleanPath, "\\", "/", -1) // Normalize backslashes
	if cleanPath != "/" && strings.HasPrefix(cleanPath, "/") {
		cleanPath = cleanPath[1:] // Remove leading slash for proper joining
	}

	// Construct the file path
	filePath := filepath.Join(galleryDir, cleanPath)
	if !strings.HasPrefix(filePath, galleryDir) {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return
	}

	if !strings.HasSuffix(filePath, encryptedExt) {
		filePath += encryptedExt
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Determine content type first
	originalName := strings.TrimSuffix(filepath.Base(requestPath), encryptedExt)
	decryptedName, err := decryptFileName(originalName, passwordHash)
	if err != nil {
		// Check if this is a password error
		if strings.Contains(err.Error(), "incorrect password") {
			// Invalidate the user's session
			session.Values["authenticated"] = false
			session.Values["password_hash"] = ""
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}

			// Redirect to login page with error
			http.Redirect(w, r, "/?error=incorrect_password", http.StatusSeeOther)
			return
		}

		http.Error(w, "Error decrypting filename", http.StatusInternalServerError)
		return
	}

	contentType := "application/octet-stream"
	isVideo := false
	switch strings.ToLower(filepath.Ext(decryptedName)) {
	case ".jpg", ".jpeg":
		contentType = "image/jpeg"
	case ".png":
		contentType = "image/png"
	case ".gif":
		contentType = "image/gif"
	case ".pdf":
		contentType = "application/pdf"
	// Video formats - iPhone, Android and common formats
	case ".mp4":
		contentType = "video/mp4"
		isVideo = true
	case ".mov":
		contentType = "video/quicktime"
		isVideo = true
	case ".avi":
		contentType = "video/x-msvideo"
		isVideo = true
	case ".mkv":
		contentType = "video/x-matroska"
		isVideo = true
	case ".webm":
		contentType = "video/webm"
		isVideo = true
	case ".3gp":
		contentType = "video/3gpp"
		isVideo = true
	case ".flv":
		contentType = "video/x-flv"
		isVideo = true
	case ".wmv":
		contentType = "video/x-ms-wmv"
		isVideo = true
	case ".m4v":
		contentType = "video/x-m4v"
		isVideo = true
	}

	// For video files, use range-aware serving to support Mobile Safari
	if isVideo {
		err = serveVideoFile(w, r, filePath, passwordHash, contentType, decryptedName)
		if err != nil {
			// Check if this is a password error
			if strings.Contains(err.Error(), "incorrect password") {
				// Invalidate the user's session
				session.Values["authenticated"] = false
				session.Values["password_hash"] = ""
				if err := session.Save(r, w); err != nil {
					log.Printf("Error saving session: %v", err)
				}

				// Redirect to login page with error
				http.Redirect(w, r, "/?error=incorrect_password", http.StatusSeeOther)
				return
			}

			http.Error(w, "Error serving video file: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// For non-video files, use the original method (decrypt entire file)
	decryptedData, err := decryptFile(filePath, passwordHash)
	if err != nil {
		// Check if this is a password error
		if strings.Contains(err.Error(), "incorrect password") {
			// Invalidate the user's session
			session.Values["authenticated"] = false
			session.Values["password_hash"] = ""
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}

			// Redirect to login page with error
			http.Redirect(w, r, "/?error=incorrect_password", http.StatusSeeOther)
			return
		}

		http.Error(w, "Error decrypting file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Send the file to the client
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(decryptedData)))
	if _, err := w.Write(decryptedData); err != nil {
		log.Printf("Error writing response: %v", err)
		// Error is already sent to client, nothing more we can do here
	}
}

// serveVideoFile serves video files with Range request support for Mobile Safari compatibility
func serveVideoFile(w http.ResponseWriter, r *http.Request, filePath, passwordHash, contentType, decryptedName string) error {
	// Get the decrypted file size first
	decryptedSize, err := getDecryptedFileSize(filePath, passwordHash)
	if err != nil {
		return err
	}

	// Set content type and basic headers
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", decryptedName))
	// Add headers that Mobile Safari expects for video playback
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Handle Range requests
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		// No range request - serve the entire file
		w.Header().Set("Content-Length", fmt.Sprintf("%d", decryptedSize))
		return streamDecryptedFile(w, filePath, passwordHash, 0, decryptedSize-1)
	}

	// Parse the Range header
	ranges, err := parseRangeHeader(rangeHeader, decryptedSize)
	if err != nil {
		http.Error(w, "Invalid Range header", http.StatusRequestedRangeNotSatisfiable)
		return err
	}

	if len(ranges) == 0 {
		http.Error(w, "Invalid Range header", http.StatusRequestedRangeNotSatisfiable)
		return fmt.Errorf("no valid ranges")
	}

	// For simplicity, only handle single range requests (most common case)
	if len(ranges) > 1 {
		// Multiple ranges not supported for now - serve entire file
		w.Header().Set("Content-Length", fmt.Sprintf("%d", decryptedSize))
		return streamDecryptedFile(w, filePath, passwordHash, 0, decryptedSize-1)
	}

	// Handle single range request
	start := ranges[0].start
	end := ranges[0].end
	if end >= decryptedSize {
		end = decryptedSize - 1
	}

	contentLength := end - start + 1
	w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLength))
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, decryptedSize))
	w.WriteHeader(http.StatusPartialContent)

	return streamDecryptedFile(w, filePath, passwordHash, start, end)
}

// httpRange represents a single HTTP range
type httpRange struct {
	start int64
	end   int64
}

// parseRangeHeader parses HTTP Range header and returns list of ranges
func parseRangeHeader(rangeHeader string, size int64) ([]httpRange, error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, fmt.Errorf("invalid range header format")
	}

	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")
	ranges := strings.Split(rangeSpec, ",")
	var result []httpRange

	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}

		var start, end int64
		var err error

		if strings.HasPrefix(r, "-") {
			// Suffix-byte-range-spec
			suffix := strings.TrimPrefix(r, "-")
			suffixLength, err := strconv.ParseInt(suffix, 10, 64)
			if err != nil {
				continue
			}
			start = size - suffixLength
			if start < 0 {
				start = 0
			}
			end = size - 1
		} else {
			// Range-spec or byte-range-spec
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				continue
			}

			start, err = strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				continue
			}

			if parts[1] == "" {
				// byte-range-spec with no end
				end = size - 1
			} else {
				end, err = strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					continue
				}
			}
		}

		if start >= 0 && start < size && end >= start && end < size {
			result = append(result, httpRange{start: start, end: end})
		}
	}

	return result, nil
}

// getDecryptedFileSize returns the size of the decrypted file without fully decrypting it
func getDecryptedFileSize(filePath, passwordHash string) (int64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}

	// Calculate decrypted size: total file size - IV (16 bytes) - MAC size header (8 bytes) - MAC (32 bytes)
	encryptedSize := fileInfo.Size()
	if encryptedSize < 56 { // Minimum size: 16 (IV) + 8 (MAC size) + 32 (MAC) = 56 bytes
		return 0, fmt.Errorf("encrypted file is too small")
	}

	// The decrypted size is the encrypted size minus the overhead
	return encryptedSize - 56, nil
}

// streamDecryptedFile streams a portion of the decrypted file
func streamDecryptedFile(w io.Writer, filePath, passwordHash string, start, end int64) error {
	// Open the encrypted file
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Read the IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(f, iv); err != nil {
		return fmt.Errorf("file is corrupted or too small: %v", err)
	}

	// Read the HMAC size
	macSizeBuf := make([]byte, 8)
	if _, err := io.ReadFull(f, macSizeBuf); err != nil {
		return fmt.Errorf("file is corrupted (missing HMAC size): %v", err)
	}
	macSize := int(macSizeBuf[0])
	if macSize <= 0 || macSize > 64 {
		return fmt.Errorf("file has invalid MAC size: %d", macSize)
	}

	// Read the HMAC
	mac := make([]byte, macSize)
	if _, err := io.ReadFull(f, mac); err != nil {
		return fmt.Errorf("file is corrupted (missing HMAC): %v", err)
	}

	// For Range requests, we need to verify the entire file's HMAC first
	// This is necessary because we can't verify integrity of partial data
	fileInfo, err := f.Stat()
	if err != nil {
		return err
	}
	encryptedSize := fileInfo.Size() - int64(aes.BlockSize) - 8 - int64(macSize)
	if encryptedSize <= 0 {
		return fmt.Errorf("file is corrupted (no encrypted data)")
	}

	// Read all encrypted data for HMAC verification
	encryptedData := make([]byte, encryptedSize)
	if _, err := io.ReadFull(f, encryptedData); err != nil {
		return fmt.Errorf("file is corrupted (missing encrypted data): %v", err)
	}

	// Verify HMAC
	h := hmac.New(sha256.New, []byte(passwordHash))
	h.Write(encryptedData)
	expectedMAC := h.Sum(nil)
	if !hmac.Equal(mac, expectedMAC) {
		return fmt.Errorf("decryption failed: incorrect password or tampered file")
	}

	// Create cipher for decryption
	block, err := createAESCipher(passwordHash)
	if err != nil {
		return err
	}

	// Calculate which part of the encrypted data we need to decrypt
	// Since we're using CFB mode, we need to decrypt from the beginning up to our end point
	// But we only write the requested range
	endByte := end + 1
	if endByte > encryptedSize {
		endByte = encryptedSize
	}

	// Decrypt the required portion
	stream := cipher.NewCFBDecrypter(block, iv)
	decryptedData := make([]byte, endByte)
	stream.XORKeyStream(decryptedData, encryptedData[:endByte])

	// Write only the requested range
	rangeData := decryptedData[start:endByte]
	_, err = w.Write(rangeData)
	return err
}

// thumbnailHandler decrypts and serves a thumbnail image
func thumbnailHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "gallery-session")
	if err != nil {
		log.Printf("Failed to get session in thumbnailHandler: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		log.Printf("Authentication failed in thumbnailHandler: ok=%v, auth=%v", ok, auth)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	passwordHash, ok := session.Values["password_hash"].(string)
	if !ok {
		log.Printf("Failed to retrieve password hash from session in thumbnailHandler")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	vars := mux.Vars(r)
	requestPath := vars["path"]
	if requestPath == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Sanitize the path to prevent directory traversal
	cleanPath := filepath.Clean(requestPath)
	cleanPath = strings.Replace(cleanPath, "\\", "/", -1) // Normalize backslashes
	if cleanPath != "/" && strings.HasPrefix(cleanPath, "/") {
		cleanPath = cleanPath[1:] // Remove leading slash for proper joining
	}

	// Construct the thumbnail file path
	thumbnailPath := filepath.Join(thumbnailsDir, cleanPath)
	if !strings.HasPrefix(thumbnailPath, thumbnailsDir) {
		http.Error(w, "Invalid thumbnail path", http.StatusBadRequest)
		return
	}

	if !strings.HasSuffix(thumbnailPath, encryptedExt) {
		thumbnailPath += encryptedExt
	}

	// Check if thumbnail exists
	if _, err := os.Stat(thumbnailPath); os.IsNotExist(err) {
		// Thumbnail doesn't exist, try to generate it from the original file
		originalFilePath := filepath.Join(galleryDir, cleanPath)
		if !strings.HasSuffix(originalFilePath, encryptedExt) {
			originalFilePath += encryptedExt
		}

		// Check if original file exists
		if _, err := os.Stat(originalFilePath); os.IsNotExist(err) {
			// Original file doesn't exist, send a generic placeholder
			encFileName := filepath.Base(strings.TrimSuffix(cleanPath, encryptedExt))
			originalFileName, decryptErr := decryptFileName(encFileName, passwordHash)

			var placeholderData []byte
			if decryptErr != nil {
				placeholderData = generatePlaceholderImage("unknown.file")
			} else {
				placeholderData = generatePlaceholderImage(originalFileName)
			}

			w.Header().Set("Content-Type", "image/jpeg")
			w.Header().Set("Cache-Control", "public, max-age=300")
			if _, err := w.Write(placeholderData); err != nil {
				log.Printf("Error writing placeholder response: %v", err)
			}
			return
		}

		// Decrypt the original filename to determine file type
		encFileName := filepath.Base(strings.TrimSuffix(cleanPath, encryptedExt))
		originalFileName, err := decryptFileName(encFileName, passwordHash)
		if err != nil {
			// Can't decrypt filename, check for password error
			if strings.Contains(err.Error(), "incorrect password") {
				session.Values["authenticated"] = false
				session.Values["password_hash"] = ""
				if err := session.Save(r, w); err != nil {
					log.Printf("Error saving session: %v", err)
				}
				http.Redirect(w, r, "/?error=incorrect_password", http.StatusSeeOther)
				return
			}

			// Generate placeholder for unknown file
			placeholderData := generatePlaceholderImage("unknown.file")
			w.Header().Set("Content-Type", "image/jpeg")
			w.Header().Set("Cache-Control", "public, max-age=300")
			if _, err := w.Write(placeholderData); err != nil {
				log.Printf("Error writing placeholder response: %v", err)
			}
			return
		}

		// Check if this is an image or video file that we can generate a thumbnail for
		if isImageFile(originalFileName) || isVideoFile(originalFileName) {
			// Try to decrypt and read the original file
			originalData, err := decryptFile(originalFilePath, passwordHash)
			if err != nil {
				// Check if this is a password error
				if strings.Contains(err.Error(), "incorrect password") {
					session.Values["authenticated"] = false
					session.Values["password_hash"] = ""
					if err := session.Save(r, w); err != nil {
						log.Printf("Error saving session: %v", err)
					}
					http.Redirect(w, r, "/?error=incorrect_password", http.StatusSeeOther)
					return
				}

				log.Printf("Warning: Failed to decrypt original file for thumbnail generation %s: %v", originalFileName, err)
				// Generate placeholder instead
				placeholderData := generatePlaceholderImage(originalFileName)
				w.Header().Set("Content-Type", "image/jpeg")
				w.Header().Set("Cache-Control", "public, max-age=300")
				if _, err := w.Write(placeholderData); err != nil {
					log.Printf("Error writing placeholder response: %v", err)
				}
				return
			}

			// Generate thumbnail from original data
			thumbnailData, err := createThumbnail(originalData, originalFileName, passwordHash)
			if err != nil {
				log.Printf("Warning: Failed to generate thumbnail for existing file %s: %v", originalFileName, err)
				// Generate placeholder instead
				placeholderData := generatePlaceholderImage(originalFileName)
				w.Header().Set("Content-Type", "image/jpeg")
				w.Header().Set("Cache-Control", "public, max-age=300")
				if _, err := w.Write(placeholderData); err != nil {
					log.Printf("Error writing placeholder response: %v", err)
				}
				return
			}

			// Save the generated thumbnail for future use
			thumbnailDir := filepath.Dir(thumbnailPath)
			err = os.MkdirAll(thumbnailDir, 0750)
			if err != nil {
				log.Printf("Warning: Failed to create thumbnail directory: %v", err)
			} else {
				err = encryptAndSaveFile(thumbnailData, thumbnailPath, passwordHash)
				if err != nil {
					log.Printf("Warning: Failed to save generated thumbnail for %s: %v", originalFileName, err)
				} else {
					log.Printf("Generated and saved thumbnail for existing file: %s", originalFileName)
				}
			}

			// Serve the generated thumbnail
			w.Header().Set("Content-Type", "image/jpeg")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			if _, err := w.Write(thumbnailData); err != nil {
				log.Printf("Error writing thumbnail response: %v", err)
			}
			return
		} else {
			// Not an image or video file, generate placeholder
			placeholderData := generatePlaceholderImage(originalFileName)
			w.Header().Set("Content-Type", "image/jpeg")
			w.Header().Set("Cache-Control", "public, max-age=300")
			if _, err := w.Write(placeholderData); err != nil {
				log.Printf("Error writing placeholder response: %v", err)
			}
			return
		}
	}

	// Decrypt and serve the existing thumbnail
	decryptedData, err := decryptFile(thumbnailPath, passwordHash)
	if err != nil {
		// Check if this is a password error
		if strings.Contains(err.Error(), "incorrect password") {
			// Invalidate the user's session
			session.Values["authenticated"] = false
			session.Values["password_hash"] = ""
			if err := session.Save(r, w); err != nil {
				log.Printf("Error saving session: %v", err)
			}

			// Redirect to login page with error
			http.Redirect(w, r, "/?error=incorrect_password", http.StatusSeeOther)
			return
		}

		http.Error(w, "Error decrypting thumbnail: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Send the thumbnail as JPEG
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	if _, err := w.Write(decryptedData); err != nil {
		log.Printf("Error writing thumbnail response: %v", err)
	}
}

// uploadHandler handles file uploads
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "gallery-session")
	if err != nil {
		log.Printf("Failed to get session in uploadHandler: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		log.Printf("Authentication failed in uploadHandler: ok=%v, auth=%v", ok, auth)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	passwordHash, ok := session.Values["password_hash"].(string)
	if !ok {
		log.Printf("Failed to retrieve password hash from session in uploadHandler")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Get the directory to upload to
	currentDir := r.FormValue("currentDir")
	if currentDir == "" {
		currentDir = "/"
	}

	// Sanitize the path to prevent directory traversal
	cleanDir := filepath.Clean(currentDir)
	cleanDir = strings.Replace(cleanDir, "\\", "/", -1) // Normalize backslashes
	if cleanDir != "/" && strings.HasPrefix(cleanDir, "/") {
		cleanDir = cleanDir[1:] // Remove leading slash for proper joining
	}

	targetDir := filepath.Join(galleryDir, cleanDir)
	if !strings.HasPrefix(targetDir, galleryDir) {
		http.Error(w, "Invalid upload directory", http.StatusBadRequest)
		return
	}

	// Check if the target directory exists
	info, err := os.Stat(targetDir)
	if os.IsNotExist(err) {
		http.Error(w, "Upload directory does not exist", http.StatusNotFound)
		return
	}

	// Ensure it's a directory
	if !info.IsDir() {
		http.Error(w, "Upload target is not a directory", http.StatusBadRequest)
		return
	}

	// Parse the multipart form with a reasonable max memory
	err = r.ParseMultipartForm(10 << 20) // 10 MB max memory
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Check if the request contains multiple files or a single file
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		// Fallback to the old "file" field name for backward compatibility
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "No files received", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Process the single file
		fileData, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}

		// Encrypt the filename
		encFileName, err := encryptFileName(header.Filename, passwordHash)
		if err != nil {
			http.Error(w, "Error encrypting filename", http.StatusInternalServerError)
			return
		}

		// Encrypt and save the file
		encryptedPath := filepath.Join(targetDir, encFileName+encryptedExt)
		err = encryptAndSaveFile(fileData, encryptedPath, passwordHash)
		if err != nil {
			http.Error(w, "Error saving encrypted file", http.StatusInternalServerError)
			return
		}

		// Generate and save thumbnail if it's an image or video
		if isImageFile(header.Filename) || isVideoFile(header.Filename) {
			thumbnailData, err := createThumbnail(fileData, header.Filename, passwordHash)
			if err != nil {
				log.Printf("Warning: Failed to generate thumbnail for %s: %v", header.Filename, err)
				// Generate placeholder thumbnail instead
				placeholderData := generatePlaceholderImage(header.Filename)
				thumbnailData = placeholderData
			}

			// Save encrypted thumbnail (either real thumbnail or placeholder)
			thumbnailDir := filepath.Join(thumbnailsDir, cleanDir)
			err = os.MkdirAll(thumbnailDir, 0750)
			if err != nil {
				log.Printf("Warning: Failed to create thumbnail directory: %v", err)
			} else {
				thumbnailPath := filepath.Join(thumbnailDir, encFileName+encryptedExt)
				err = encryptAndSaveFile(thumbnailData, thumbnailPath, passwordHash)
				if err != nil {
					log.Printf("Warning: Failed to save thumbnail for %s: %v", header.Filename, err)
				}
			}
		}
	} else {
		// Process multiple files
		for _, fileHeader := range files {
			// Open the uploaded file
			file, err := fileHeader.Open()
			if err != nil {
				http.Error(w, fmt.Sprintf("Error opening file %s: %v", fileHeader.Filename, err), http.StatusInternalServerError)
				continue
			}
			defer file.Close()

			// Read file data
			fileData, err := io.ReadAll(file)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error reading file %s: %v", fileHeader.Filename, err), http.StatusInternalServerError)
				continue
			}

			// Encrypt the filename
			encFileName, err := encryptFileName(fileHeader.Filename, passwordHash)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error encrypting filename %s: %v", fileHeader.Filename, err), http.StatusInternalServerError)
				continue
			}

			// Encrypt and save the file
			encryptedPath := filepath.Join(targetDir, encFileName+encryptedExt)
			err = encryptAndSaveFile(fileData, encryptedPath, passwordHash)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error saving encrypted file %s: %v", fileHeader.Filename, err), http.StatusInternalServerError)
				continue
			}

			// Generate and save thumbnail if it's an image or video
			if isImageFile(fileHeader.Filename) || isVideoFile(fileHeader.Filename) {
				thumbnailData, err := createThumbnail(fileData, fileHeader.Filename, passwordHash)
				if err != nil {
					log.Printf("Warning: Failed to generate thumbnail for %s: %v", fileHeader.Filename, err)
					// Generate placeholder thumbnail instead
					placeholderData := generatePlaceholderImage(fileHeader.Filename)
					thumbnailData = placeholderData
				}

				// Save encrypted thumbnail (either real thumbnail or placeholder)
				thumbnailDir := filepath.Join(thumbnailsDir, cleanDir)
				err = os.MkdirAll(thumbnailDir, 0750)
				if err != nil {
					log.Printf("Warning: Failed to create thumbnail directory: %v", err)
				} else {
					thumbnailPath := filepath.Join(thumbnailDir, encFileName+encryptedExt)
					err = encryptAndSaveFile(thumbnailData, thumbnailPath, passwordHash)
					if err != nil {
						log.Printf("Warning: Failed to save thumbnail for %s: %v", fileHeader.Filename, err)
					}
				}
			}
		}
	}

	// Construct proper redirect path
	redirectPath := "/gallery/"
	if cleanDir != "/" {
		// Handle subdirectory path properly
		// Strip any leading slash from cleanDir to avoid double slashes
		redirectDir := strings.TrimPrefix(cleanDir, "/")
		redirectPath = "/gallery/" + redirectDir
		// Ensure the path ends with a slash for directories
		if !strings.HasSuffix(redirectPath, "/") {
			redirectPath += "/"
		}
	}

	http.Redirect(w, r, redirectPath, http.StatusSeeOther)
}

// createDirHandler creates a new directory
func createDirHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "gallery-session")
	if err != nil {
		log.Printf("Failed to get session in createDirHandler: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		log.Printf("Authentication failed in createDirHandler: ok=%v, auth=%v", ok, auth)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	passwordHash, ok := session.Values["password_hash"].(string)
	if !ok {
		log.Printf("Failed to retrieve password hash from session in createDirHandler")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Get form data
	currentDir := r.FormValue("currentDir")
	if currentDir == "" {
		currentDir = "/"
	}

	dirName := r.FormValue("dirName")
	if dirName == "" {
		http.Error(w, "Directory name is required", http.StatusBadRequest)
		return
	}

	// Sanitize the directory path to prevent directory traversal
	cleanDir := filepath.Clean(currentDir)
	cleanDir = strings.Replace(cleanDir, "\\", "/", -1) // Normalize backslashes
	if cleanDir != "/" && strings.HasPrefix(cleanDir, "/") {
		cleanDir = cleanDir[1:] // Remove leading slash for proper joining
	}

	// Check if the parent directory exists
	parentDir := filepath.Join(galleryDir, cleanDir)
	if !strings.HasPrefix(parentDir, galleryDir) {
		http.Error(w, "Invalid directory path", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(parentDir)
	if os.IsNotExist(err) {
		http.Error(w, "Parent directory does not exist", http.StatusNotFound)
		return
	}

	// Ensure it's a directory
	if !info.IsDir() {
		http.Error(w, "Parent path is not a directory", http.StatusBadRequest)
		return
	}

	// Sanitize directory name - prevent any path traversal attempts in the name itself
	dirName = filepath.Base(dirName)

	// Encrypt the directory name
	encDirName, err := encryptFileName(dirName, passwordHash)
	if err != nil {
		http.Error(w, "Error encrypting directory name", http.StatusInternalServerError)
		return
	}

	// Create the directory
	newDirPath := filepath.Join(galleryDir, cleanDir, encDirName+encryptedExt)
	err = os.MkdirAll(newDirPath, 0750)
	if err != nil {
		http.Error(w, "Error creating directory", http.StatusInternalServerError)
		return
	}

	// Construct proper redirect path
	redirectPath := "/gallery/"
	if cleanDir != "/" {
		// Handle subdirectory path properly
		// Strip any leading slash from cleanDir to avoid double slashes
		redirectDir := strings.TrimPrefix(cleanDir, "/")
		redirectPath = "/gallery/" + redirectDir
		// Ensure the path ends with a slash for directories
		if !strings.HasSuffix(redirectPath, "/") {
			redirectPath += "/"
		}
	}

	http.Redirect(w, r, redirectPath, http.StatusSeeOther)
}

// deleteHandler removes a file or directory
func deleteHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "gallery-session")
	if err != nil {
		log.Printf("Failed to get session in deleteHandler: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		log.Printf("Authentication failed in deleteHandler: ok=%v, auth=%v", ok, auth)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Get the path to delete
	itemPath := r.FormValue("path")
	if itemPath == "" {
		http.Error(w, "Path is required", http.StatusBadRequest)
		return
	}

	// Get the current directory (for redirection after deletion)
	currentDir := r.FormValue("currentDir")
	if currentDir == "" {
		currentDir = "/"
	}

	// Sanitize the item path to prevent directory traversal
	cleanItemPath := filepath.Clean(itemPath)
	cleanItemPath = strings.Replace(cleanItemPath, "\\", "/", -1) // Normalize backslashes
	if cleanItemPath != "/" && strings.HasPrefix(cleanItemPath, "/") {
		cleanItemPath = cleanItemPath[1:] // Remove leading slash for proper joining
	}

	// Sanitize the current directory path
	cleanDir := filepath.Clean(currentDir)
	cleanDir = strings.Replace(cleanDir, "\\", "/", -1) // Normalize backslashes
	if cleanDir != "/" && strings.HasPrefix(cleanDir, "/") {
		cleanDir = cleanDir[1:] // Remove leading slash for proper joining
	}

	// Validate and sanitize the path to prevent directory traversal
	fullPath := filepath.Join(galleryDir, cleanItemPath)
	if !strings.HasPrefix(fullPath, galleryDir) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Check if the item exists
	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		http.Error(w, "Item does not exist", http.StatusNotFound)
		return
	}

	// Remove the item (recursively if it's a directory)
	var removeErr error
	if info.IsDir() {
		removeErr = os.RemoveAll(fullPath)
	} else {
		removeErr = os.Remove(fullPath)
	}

	if removeErr != nil {
		http.Error(w, "Error removing item: "+removeErr.Error(), http.StatusInternalServerError)
		return
	}

	// Also remove the corresponding thumbnail file or directory
	thumbnailPath := filepath.Join(thumbnailsDir, cleanItemPath)
	if strings.HasPrefix(thumbnailPath, thumbnailsDir) {
		// Check if thumbnail exists before trying to remove it
		if _, err := os.Stat(thumbnailPath); err == nil {
			var thumbnailRemoveErr error
			if info.IsDir() {
				// Remove thumbnail directory recursively
				thumbnailRemoveErr = os.RemoveAll(thumbnailPath)
			} else {
				// Remove thumbnail file
				thumbnailRemoveErr = os.Remove(thumbnailPath)
			}

			if thumbnailRemoveErr != nil {
				// Log the error but don't fail the request since the main file was already deleted
				log.Printf("Warning: Failed to remove thumbnail for %s: %v", cleanItemPath, thumbnailRemoveErr)
			}
		}
	}

	// Construct proper redirect path
	redirectPath := "/gallery/"
	if cleanDir != "/" {
		// Handle subdirectory path properly
		// Strip any leading slash from cleanDir to avoid double slashes
		redirectDir := strings.TrimPrefix(cleanDir, "/")
		redirectPath = "/gallery/" + redirectDir
		// Ensure the path ends with a slash for directories
		if !strings.HasSuffix(redirectPath, "/") {
			redirectPath += "/"
		}
	}

	http.Redirect(w, r, redirectPath, http.StatusSeeOther)
}

// logoutHandler logs the user out
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "gallery-session")
	if err != nil {
		log.Printf("Failed to get session in logoutHandler: %v", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	session.Values["authenticated"] = false
	session.Values["password_hash"] = ""

	if err := session.Save(r, w); err != nil {
		log.Printf("Failed to save session in logoutHandler: %v", err)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// hashPassword creates a secure hash from a password
func hashPassword(password string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	hasher.Write(saltBytes)
	return hex.EncodeToString(hasher.Sum(nil))
}

// createAESCipher creates an AES cipher from the password hash
func createAESCipher(passwordHash string) (cipher.Block, error) {
	// Use first 32 bytes of the hash as the AES-256 key
	key, _ := hex.DecodeString(passwordHash)
	if len(key) > 32 {
		key = key[:32]
	} else if len(key) < 32 {
		newKey := make([]byte, 32)
		copy(newKey, key)
		key = newKey
	}
	return aes.NewCipher(key)
}

// encryptFileName encrypts a filename
func encryptFileName(filename string, passwordHash string) (string, error) {
	data := []byte(filename)
	block, err := createAESCipher(passwordHash)
	if err != nil {
		return "", err
	}

	// Create initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Encrypt
	stream := cipher.NewCFBEncrypter(block, iv)
	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	// Add a validation tag to verify correct password later
	// Add a small validity check (4 bytes is enough)
	validationTag := []byte("GOCR")
	tagEncrypted := make([]byte, len(validationTag))
	// Use the same IV for consistency (it's included in the output)
	stream = cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(tagEncrypted, validationTag)

	// Combine IV + encrypted data + encrypted validation tag
	combined := append(iv, encrypted...)
	combined = append(combined, tagEncrypted...)

	// Convert to hex string
	return hex.EncodeToString(combined), nil
}

// decryptFileName decrypts a filename
func decryptFileName(encryptedHex string, passwordHash string) (string, error) {
	// Convert from hex
	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", err
	}

	// Ensure we have enough data (at least IV size + validation tag)
	minSize := aes.BlockSize + 4
	if len(encrypted) < minSize {
		return "", errors.New("encrypted data is too short")
	}

	block, err := createAESCipher(passwordHash)
	if err != nil {
		return "", err
	}

	// Extract IV from the first 16 bytes
	iv := encrypted[:aes.BlockSize]
	// The rest is the encrypted data + validation tag
	encryptedData := encrypted[aes.BlockSize : len(encrypted)-4]
	encryptedTag := encrypted[len(encrypted)-4:]

	// Decrypt
	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, len(encryptedData))
	stream.XORKeyStream(decrypted, encryptedData)

	// Decrypt validation tag
	stream = cipher.NewCFBDecrypter(block, iv)
	decryptedTag := make([]byte, 4)
	stream.XORKeyStream(decryptedTag, encryptedTag)

	// Verify the validation tag
	if string(decryptedTag) != "GOCR" {
		return "", errors.New("decryption failed: incorrect password")
	}

	return string(decrypted), nil
}

// encryptAndSaveFile encrypts and saves a file
func encryptAndSaveFile(data []byte, path string, passwordHash string) error {
	block, err := createAESCipher(passwordHash)
	if err != nil {
		return err
	}

	// Create initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Create the file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write IV to the beginning of the file
	if _, err := f.Write(iv); err != nil {
		return err
	}

	// Encrypt the data
	stream := cipher.NewCFBEncrypter(block, iv)
	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	// Create HMAC for authenticated encryption
	h := hmac.New(sha256.New, []byte(passwordHash))
	h.Write(encrypted) // Add the encrypted data to HMAC
	mac := h.Sum(nil)

	// Write the HMAC size and value
	macSize := make([]byte, 8)
	// Store the MAC size (which is fixed anyway, but for completeness)
	macSize[0] = byte(len(mac))
	if _, err := f.Write(macSize); err != nil {
		return err
	}
	if _, err := f.Write(mac); err != nil {
		return err
	}

	// Write the encrypted data
	if _, err := f.Write(encrypted); err != nil {
		return err
	}

	return nil
}

// decryptFile decrypts a file
func decryptFile(path string, passwordHash string) ([]byte, error) {
	// Open the encrypted file
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read the IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(f, iv); err != nil {
		return nil, fmt.Errorf("file is corrupted or too small: %v", err)
	}

	// Read the HMAC size
	macSizeBuf := make([]byte, 8)
	if _, err := io.ReadFull(f, macSizeBuf); err != nil {
		return nil, fmt.Errorf("file is corrupted (missing HMAC size): %v", err)
	}
	macSize := int(macSizeBuf[0])
	if macSize <= 0 || macSize > 64 { // Sanity check
		return nil, fmt.Errorf("file has invalid MAC size: %d", macSize)
	}

	// Read the HMAC
	mac := make([]byte, macSize)
	if _, err := io.ReadFull(f, mac); err != nil {
		return nil, fmt.Errorf("file is corrupted (missing HMAC): %v", err)
	}

	// Read the rest of the file (encrypted data)
	fileInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	encryptedSize := fileInfo.Size() - int64(aes.BlockSize) - 8 - int64(macSize)
	if encryptedSize <= 0 {
		return nil, errors.New("file is corrupted (no encrypted data)")
	}

	encryptedData := make([]byte, encryptedSize)
	if _, err := io.ReadFull(f, encryptedData); err != nil {
		return nil, fmt.Errorf("file is corrupted (missing encrypted data): %v", err)
	}

	// Verify HMAC to detect wrong password
	h := hmac.New(sha256.New, []byte(passwordHash))
	h.Write(encryptedData)
	expectedMAC := h.Sum(nil)
	if !hmac.Equal(mac, expectedMAC) {
		return nil, errors.New("decryption failed: incorrect password or tampered file")
	}

	// Decrypt the data
	block, err := createAESCipher(passwordHash)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, len(encryptedData))
	stream.XORKeyStream(decrypted, encryptedData)

	return decrypted, nil
}
