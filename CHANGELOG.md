# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.7] - 2025-05-10

### Fixed
- GitHub CI/CD workflow issues
- Build process for multi-platform releases

## [0.0.6] - 2025-05-02

### Added
- Systemd service support for easy daemon management
- Installation script for systemd service setup
- Service configuration templates

## [0.0.5] - 2025-04-25

### Added
- File and directory deletion functionality
- GitHub CI/CD Workflow for automated builds and releases
- Comprehensive test suite for file HMAC verification
- Additional tests for filename encryption
- SSL certificate testing

## [0.0.4] - 2024-07-21

### Added
- HMAC-SHA256 file integrity verification to detect tampered files
- Validation tags for filename encryption to verify password correctness
- Comprehensive test suite for encryption functionality
- Enhanced error handling for file corruption detection

### Changed
- Improved security with authenticated encryption for files
- Better password verification for both files and directories

## [0.0.3] - 2024-07-14

### Added
- HTTPS support via the `--ssl=true` command line flag
- Automatic generation of self-signed certificates
- Custom certificate path options with `--cert` and `--key` flags
- TLS 1.2+ enforcement for enhanced security

## [0.0.2] - 2023-10-15

### Added
- Multi-file upload support
- Drag-and-drop interface for file uploads
- Image preview functionality before uploading
- Improved upload UX with visual feedback

## [0.0.1] - 2023-09-22

### Added
- Initial release of the Go Gallery application
- Password-protected access to the gallery
- AES-256 encryption for folder and file names
- AES-256 encryption for file contents
- Create new folders with encrypted names
- Upload images to your gallery
- Modern and responsive UI
- Session-based authentication with secure cookies
- No server-side password storage for enhanced security