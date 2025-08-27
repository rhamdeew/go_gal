# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Essential Commands
```bash
# Build the application
make build
# or
go build -o go_gal main.go

# Run the application (builds first)
make run

# Run with SSL enabled
make run-ssl

# Clean build artifacts
make clean

# Download dependencies
make deps
# or
go mod download
```

### Testing
```bash
# Run all tests with verbose output
make test
# or
go test -v ./...

# Run tests with coverage report
make test-coverage
go tool cover -html=coverage.out  # View coverage in browser

# Run benchmark tests for performance analysis
go test -bench=. -benchmem

# Run specific test patterns
go test -run=TestCrypto
go test -run=TestHandler

# Run tests in parallel (faster execution)
go test -parallel=4
```

### Installation and Deployment
```bash
# Install as systemd service (requires sudo)
sudo ./install.sh

# Install with custom options
sudo ./install.sh --port=9000 --enable-ssl --session-key="custom-key"

# Uninstall service
sudo ./uninstall.sh
```

## Architecture Overview

### Core Application Structure
This is a single-file Go application (`main.go`) that implements a password-protected, encrypted photo and video gallery. The application uses **client-side encryption** where all file names, directory names, and file contents are encrypted with AES-256 using the user's password.

### Key Components

#### HTTP Handlers
- `indexHandler` - Root redirect to login/gallery
- `loginHandler` - Authentication and password verification
- `galleryHandler` - Main gallery listing with breadcrumbs
- `viewHandler` - Image/video viewing with range request support
- `thumbnailHandler` - Encrypted thumbnail serving
- `uploadHandler` - Multi-file upload with encryption
- `createDirHandler` - Directory creation with encrypted names
- `deleteHandler` - File/directory deletion
- `logoutHandler` - Session cleanup

#### Encryption System
- **AES-256-GCM** for file content encryption
- **HMAC-SHA256** for file integrity verification
- **Filename encryption** with validation tags to verify password correctness
- **Thumbnail encryption** stored separately from original files

#### Data Structures
- `GalleryItem` - Represents files/folders with metadata (encrypted names, types, sizes)
- `PageData` - Template data structure for gallery pages
- `Breadcrumb` - Navigation breadcrumb structure

### Directory Structure
- `gallery/` - Encrypted files and directories (created at runtime)
- `thumbnails/` - Encrypted thumbnail cache (created at runtime) 
- `templates/` - HTML templates (gallery.html, login.html)
- `static/` - CSS, images, favicon files
- `*_test.go` - Comprehensive test suite covering all functionality

### Thumbnail System
The application automatically generates 200x200 pixel thumbnails for performance:
- **Images**: Generated using Go's native image libraries
- **Videos**: Extracted using FFmpeg (with colored placeholder fallback)
- **Storage**: All thumbnails are encrypted and cached with 1-hour browser cache headers

### Security Features
- No server-side password storage
- Session-based authentication with secure cookies
- HMAC file integrity verification
- Protection against directory traversal attacks
- Optional HTTPS/TLS support with self-signed certificates

### Environment Variables
- `GO_GAL_SESSION_KEY` - Session encryption key (production use)
- `GO_GAL_SALT` - Password hashing salt (production use)
- `GO_GAL_SSL_ENABLED` - Enable SSL features ("true"/"false")

### Dependencies
- `github.com/gorilla/mux` - HTTP routing
- `github.com/gorilla/sessions` - Session management
- `github.com/nfnt/resize` - Image thumbnail generation
- `golang.org/x/image/webp` - WebP image format support

### Testing Approach
The codebase includes comprehensive tests in separate `*_test.go` files following Go best practices:

**Test Organization:**
- 76 test functions across 18 test files (~4,200 lines of test code)
- Tests use `t.Parallel()` for faster execution where safe
- Table-driven tests for comprehensive edge case coverage
- Helper functions marked with `t.Helper()` for clean error reporting
- Extensive use of `t.Run()` subtests for organized testing

**Coverage Areas:**
- Encryption/decryption functionality with benchmark tests
- HTTP handlers and routing
- File operations and integrity verification
- SSL certificate generation
- Error conditions and edge cases
- Performance benchmarks for crypto operations

**Benchmark Tests:**
- `BenchmarkHashPassword` - Password hashing performance
- `BenchmarkCreateAESCipher` - Cipher creation performance  
- `BenchmarkEncryptDecryptData` - File encryption/decryption performance
- `BenchmarkEncryptDecryptFileName` - Filename encryption performance

### FFmpeg Integration
FFmpeg is used for video thumbnail generation but is optional:
- Automatic detection with graceful fallback to colored placeholders
- Installation instructions provided for major platforms
- Not required for core gallery functionality