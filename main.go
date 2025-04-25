package main

import (
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
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// Global variables
var (
	templates     = template.Must(template.ParseGlob("templates/*.html"))
	store         = sessions.NewCookieStore([]byte("gocrypto-gallery-session-key"))
	saltBytes     = []byte("gallery-salt") // Salt for password hashing
	galleryDir    = "gallery"
	encryptedExt  = ".enc" // Extension for encrypted files
)

// Initialize the cookie store with proper options
func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// GalleryItem represents a file or folder in the gallery
type GalleryItem struct {
	Name     string
	IsDir    bool
	Path     string
	EncPath  string // Encrypted path name (for display)
}

// PageData contains data for template rendering
type PageData struct {
	CurrentPath string
	Items       []GalleryItem
	Error       string
}

func main() {
	// Parse command-line flags
	port := flag.String("port", "8080", "Port to listen on")
	host := flag.String("host", "localhost", "Host IP address to bind to")
	enableSSL := flag.Bool("ssl", false, "Enable HTTPS with self-signed certificates")
	certFile := flag.String("cert", "cert.pem", "Path to SSL certificate file")
	keyFile := flag.String("key", "key.pem", "Path to SSL key file")
	flag.Parse()

	// Create gallery directory if it doesn't exist
	if _, err := os.Stat(galleryDir); os.IsNotExist(err) {
		err = os.MkdirAll(galleryDir, 0755)
		if err != nil {
			log.Fatalf("Failed to create gallery directory: %v", err)
		}
		log.Printf("Created gallery directory at: %s", galleryDir)
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
	r.HandleFunc("/logout", logoutHandler)

	// Set up static file server for CSS, JS
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

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
			Addr:      serverAddr,
			Handler:   r,
			TLSConfig: tlsConfig,
		}

		fmt.Printf("Server started with HTTPS at https://%s:%s\n", *host, *port)
		log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))
	} else {
		fmt.Printf("Server started at http://%s:%s\n", *host, *port)
		log.Fatal(http.ListenAndServe(serverAddr, r))
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

	templates.ExecuteTemplate(w, "login.html", PageData{Error: errorMsg})
}

// loginHandler processes the login form
func loginHandler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	if password == "" {
		templates.ExecuteTemplate(w, "login.html", PageData{Error: "Password required"})
		return
	}

	// Store password hash in session for later decryption
	// We don't store the actual password
	session, err := store.Get(r, "gallery-session")
	if err != nil {
		log.Printf("Failed to get session: %v", err)
		templates.ExecuteTemplate(w, "login.html", PageData{Error: "Session error, please try again"})
		return
	}

	session.Values["password_hash"] = hashPassword(password)
	session.Values["authenticated"] = true

	if err := session.Save(r, w); err != nil {
		log.Printf("Failed to save session: %v", err)
		templates.ExecuteTemplate(w, "login.html", PageData{Error: "Failed to save session"})
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

	// Construct the actual file system path
	fsPath := filepath.Join(galleryDir, requestPath)
	info, err := os.Stat(fsPath)
	if os.IsNotExist(err) {
		templates.ExecuteTemplate(w, "gallery.html", PageData{
			Error: "Path does not exist",
		})
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

			itemPath := filepath.Join(requestPath, name)
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
		session.Save(r, w)

		// Redirect to login page with error
		http.Redirect(w, r, "/?error=incorrect_password", http.StatusSeeOther)
		return
	}

	templates.ExecuteTemplate(w, "gallery.html", PageData{
		CurrentPath: requestPath,
		Items:       items,
	})
}

// viewHandler decrypts and serves a file for viewing
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

	// Construct the file path
	filePath := filepath.Join(galleryDir, requestPath)
	if !strings.HasSuffix(filePath, encryptedExt) {
		filePath += encryptedExt
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Decrypt and serve the file
	decryptedData, err := decryptFile(filePath, passwordHash)
	if err != nil {
		// Check if this is a password error
		if strings.Contains(err.Error(), "incorrect password") {
			// Invalidate the user's session
			session.Values["authenticated"] = false
			session.Values["password_hash"] = ""
			session.Save(r, w)

			// Redirect to login page with error
			http.Redirect(w, r, "/?error=incorrect_password", http.StatusSeeOther)
			return
		}

		http.Error(w, "Error decrypting file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Determine content type
	originalName := strings.TrimSuffix(filepath.Base(requestPath), encryptedExt)
	decryptedName, err := decryptFileName(originalName, passwordHash)
	if err != nil {
		// Check if this is a password error
		if strings.Contains(err.Error(), "incorrect password") {
			// Invalidate the user's session
			session.Values["authenticated"] = false
			session.Values["password_hash"] = ""
			session.Save(r, w)

			// Redirect to login page with error
			http.Redirect(w, r, "/?error=incorrect_password", http.StatusSeeOther)
			return
		}

		http.Error(w, "Error decrypting filename", http.StatusInternalServerError)
		return
	}

	contentType := "application/octet-stream"
	switch strings.ToLower(filepath.Ext(decryptedName)) {
	case ".jpg", ".jpeg":
		contentType = "image/jpeg"
	case ".png":
		contentType = "image/png"
	case ".gif":
		contentType = "image/gif"
	case ".pdf":
		contentType = "application/pdf"
	}

	w.Header().Set("Content-Type", contentType)
	w.Write(decryptedData)
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

	targetDir := filepath.Join(galleryDir, currentDir)

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
		}
	}

	// Construct proper redirect path
	redirectPath := "/gallery/"
	if currentDir != "/" {
		// Handle subdirectory path properly
		// Strip any leading slash from currentDir to avoid double slashes
		cleanDir := strings.TrimPrefix(currentDir, "/")
		redirectPath = "/gallery/" + cleanDir
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

	// Check if the parent directory exists
	parentDir := filepath.Join(galleryDir, currentDir)
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

	// Encrypt the directory name
	encDirName, err := encryptFileName(dirName, passwordHash)
	if err != nil {
		http.Error(w, "Error encrypting directory name", http.StatusInternalServerError)
		return
	}

	// Create the directory
	newDirPath := filepath.Join(galleryDir, currentDir, encDirName+encryptedExt)
	err = os.MkdirAll(newDirPath, 0755)
	if err != nil {
		http.Error(w, "Error creating directory", http.StatusInternalServerError)
		return
	}

	// Construct proper redirect path
	redirectPath := "/gallery/"
	if currentDir != "/" {
		// Handle subdirectory path properly
		// Strip any leading slash from currentDir to avoid double slashes
		cleanDir := strings.TrimPrefix(currentDir, "/")
		redirectPath = "/gallery/" + cleanDir
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

	// Validate and sanitize the path to prevent directory traversal
	fullPath := filepath.Join(galleryDir, itemPath)
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

	// Construct proper redirect path
	redirectPath := "/gallery/"
	if currentDir != "/" {
		// Handle subdirectory path properly
		// Strip any leading slash from currentDir to avoid double slashes
		cleanDir := strings.TrimPrefix(currentDir, "/")
		redirectPath = "/gallery/" + cleanDir
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
	for i := range iv {
		iv[i] = byte(i)
	}

	// Encrypt
	stream := cipher.NewCFBEncrypter(block, iv)
	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	// Add a validation tag to verify correct password later
	// Add a small validity check (4 bytes is enough)
	validationTag := []byte("GOCR")
	tagEncrypted := make([]byte, len(validationTag))
	stream = cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(tagEncrypted, validationTag)

	// Combine encrypted data with encrypted validation tag
	combined := append(encrypted, tagEncrypted...)

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

	// Ensure we have enough data (at least for validation tag)
	if len(encrypted) < 4 {
		return "", errors.New("encrypted data is too short")
	}

	block, err := createAESCipher(passwordHash)
	if err != nil {
		return "", err
	}

	// Create initialization vector
	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = byte(i)
	}

	// Split the data - last 4 bytes are the validation tag
	dataLength := len(encrypted) - 4
	encryptedData := encrypted[:dataLength]
	encryptedTag := encrypted[dataLength:]

	// Decrypt
	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, dataLength)
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