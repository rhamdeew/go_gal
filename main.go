package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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
	r.HandleFunc("/view/{path:.*}", viewHandler)
	r.HandleFunc("/logout", logoutHandler)

	// Set up static file server for CSS, JS
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Construct server address from flags
	serverAddr := fmt.Sprintf("%s:%s", *host, *port)

	// Start the server
	fmt.Printf("Server started at http://%s:%s\n", *host, *port)
	log.Fatal(http.ListenAndServe(serverAddr, r))
}

// indexHandler shows the login page or redirects to gallery if already logged in
func indexHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "gallery-session")
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		http.Redirect(w, r, "/gallery/", http.StatusSeeOther)
		return
	}
	templates.ExecuteTemplate(w, "login.html", nil)
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
	session, _ := store.Get(r, "gallery-session")
	session.Values["password_hash"] = hashPassword(password)
	session.Values["authenticated"] = true
	session.Save(r, w)

	http.Redirect(w, r, "/gallery/", http.StatusSeeOther)
}

// galleryHandler shows the contents of the gallery or a specific directory
func galleryHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "gallery-session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	passwordHash, ok := session.Values["password_hash"].(string)
	if !ok {
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
	for _, file := range files {
		name := file.Name()

		// For both directories and files, check if they have the encrypted extension
		if strings.HasSuffix(name, encryptedExt) {
			encName := strings.TrimSuffix(name, encryptedExt)
			decryptedName, err := decryptFileName(encName, passwordHash)

			if err != nil {
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

	templates.ExecuteTemplate(w, "gallery.html", PageData{
		CurrentPath: requestPath,
		Items:       items,
	})
}

// viewHandler decrypts and serves a file for viewing
func viewHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "gallery-session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	passwordHash, ok := session.Values["password_hash"].(string)
	if !ok {
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
		http.Error(w, "Error decrypting file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Determine content type
	originalName := strings.TrimSuffix(filepath.Base(requestPath), encryptedExt)
	decryptedName, err := decryptFileName(originalName, passwordHash)
	if err != nil {
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
	session, _ := store.Get(r, "gallery-session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	passwordHash, ok := session.Values["password_hash"].(string)
	if !ok {
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
	session, _ := store.Get(r, "gallery-session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	passwordHash, ok := session.Values["password_hash"].(string)
	if !ok {
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

// logoutHandler logs the user out
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "gallery-session")
	session.Values["authenticated"] = false
	session.Values["password_hash"] = ""
	session.Save(r, w)
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

	// Convert to hex string
	return hex.EncodeToString(encrypted), nil
}

// decryptFileName decrypts a filename
func decryptFileName(encryptedHex string, passwordHash string) (string, error) {
	// Convert from hex
	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", err
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

	// Decrypt
	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, len(encrypted))
	stream.XORKeyStream(decrypted, encrypted)

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

	// Encrypt and write the data
	stream := cipher.NewCFBEncrypter(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: f}
	if _, err := writer.Write(data); err != nil {
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
		return nil, err
	}

	block, err := createAESCipher(passwordHash)
	if err != nil {
		return nil, err
	}

	// Create a buffer to hold the decrypted data
	buf := make([]byte, 1024)
	var result []byte

	// Decrypt the file
	stream := cipher.NewCFBDecrypter(block, iv)
	reader := &cipher.StreamReader{S: stream, R: f}

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}