# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.29] - 2026-03-19

### Fixed
- Fixed update.sh script

## [0.0.28] - 2026-03-19

### Added
- Exponential backoff for login brute-force protection to enhance security

## [0.0.27] - 2026-03-18

### Added
- Update functionality for easier application updates
- Improved uninstall process

### Changed
- Updated README.md with update instructions

## [0.0.26] - 2026-03-18

### Changed
- Optimized memory consumption when uploading large files

## [0.0.25] - 2026-03-16

### Added
- Let's Encrypt support with automatic TLS via autocert
- `--acme`, `--acme-domain`, `--acme-email` flags for automatic certificate management
- HTTP-01 challenge server on port 80, HTTPS on port 443

### Changed
- Rewrote install.sh as interactive wizard with prompts for session key, salt, host, port, and SSL mode

## [0.0.24] - 2026-03-16

### Changed
- Updated GitHub Actions workflow
- Updated release builds

## [0.0.23] - 2026-03-14

### Added
- Rename functionality for files and directories
- Move functionality for files and directories

## [0.0.22] - 2026-03-14

### Added
- Argon2id key derivation function for hardened encryption
- Version 2 file format with improved security

### Changed
- UI improvements

### Fixed
- Build error

### Security
- Hardened encryption with Argon2id KDF
- Migration tool for upgrading to v2 file format

## [0.0.21] - 2026-01-26

### Added
- Streaming support for media files
- Support for uploading large files
- Support for trimming long filenames
- Per-file upload processing

## [0.0.20] - 2025-08-28

### Security
- Security improvements to encryption and authentication

### Changed
- Test files improvements

## [0.0.19] - 2025-08-28

### Fixed
- Corrected Go module definition

### Added
- CLAUDE.md for AI assistant guidance

## [0.0.18] - 2025-05-23

### Fixed
- Delete button style for videos

## [0.0.17] - 2025-05-23

### Changed
- Code formatting (go fmt)

### Added
- New tests

## [0.0.16] - 2025-05-23

### Added
- Functionality to regenerate thumbnails for images without them

### Fixed
- Bug with displaying video previews
- Video playback issue in mobile Safari

## [0.0.15] - 2025-05-23

### Fixed
- Bug with cleaning thumbnail images after removing images or videos
- Breadcrumb displaying issue

## [0.0.14] - 2025-05-23

### Added
- **Automatic thumbnail generation for images and videos** - Major performance improvement for gallery browsing
- **Fast thumbnail previews** - 200x200 pixel thumbnails with maintained aspect ratio for instant loading
- **Video thumbnail extraction** using FFmpeg - Extract preview frames from the first second of videos
- **Image thumbnail generation** for JPEG, PNG, GIF, and WebP formats using native Go libraries
- **Encrypted thumbnail storage** - All thumbnails are encrypted and stored separately from original files
- **Intelligent placeholder system** - Colored placeholder images when thumbnail generation fails
  - Blue placeholders for video files (when FFmpeg unavailable)
  - Gray placeholders for image files (when generation fails)
- **Browser caching** - 1-hour cache headers for improved performance
- **FFmpeg integration** with automatic detection and graceful fallback
- New dependencies: `github.com/nfnt/resize` and `golang.org/x/image` for image processing
- Support documentation for FFmpeg installation across platforms (macOS, Ubuntu/Debian, Windows)
- Comprehensive troubleshooting guide for thumbnail-related issues

### Changed
- **Dramatically improved gallery performance** - Thumbnails load instead of full-resolution files
- Enhanced installation script to automatically create `thumbnails/` directory
- Updated `.gitignore` to exclude `thumbnails/` directory from version control
- Updated README.md with detailed thumbnail system documentation
- Installation script now ensures proper permissions for thumbnails directory (770)
- Improved user experience with faster gallery browsing and reduced bandwidth usage

### Infrastructure
- Added `thumbnails/` directory creation to installation process
- Enhanced systemd service setup to handle thumbnail directory permissions
- Updated favicon handling in installation script with proper warnings

## [0.0.13] - 2025-05-23

### Added
- install.sh and uninstall.sh scripts included in release
- App update instructions in README

## [0.0.12] - 2025-05-23

### Added
- Complete video support with HTML5 video player
- Support for major video formats: MP4, MOV, AVI, MKV, WebM, 3GP, FLV, WMV, M4V
- Optimized support for iPhone (MOV, M4V) and Android (MP4, 3GP) video formats
- Built-in video player with standard controls (play, pause, seek, volume, fullscreen)
- Video file detection and preview during upload
- Unified media gallery interface for both images and videos
- Video thumbnails with distinctive video icons and play overlays
- Seamless navigation between images and videos in modal viewer
- Responsive video player that scales properly on all devices
- Video file preview functionality during drag-and-drop upload

### Changed
- Updated upload interface to accept both image and video files
- Enhanced modal viewer to support both images and videos with unified navigation
- Improved UI with better visual distinction between image and video files
- Updated documentation to reflect video support capabilities

### Fixed
- Proper MIME type handling for all supported video formats
- Consistent styling between image and video previews
- Mobile-responsive video playback experience

## [0.0.11] - 2025-04-25

### Fixed
- Fixes to get better score from goreportcard

## [0.0.10] - 2025-04-25

### Fixed
- Fixed install.sh and uninstall.sh, Use gogal:gogal user/group for systemd.service

## [0.0.9] - 2025-04-25

### Fixed
- SSL configuration for systemd.service

## [0.0.8] - 2025-04-25

### Fixed
- Fixed work as systemd service

## [0.0.7] - 2025-04-25

### Fixed
- GitHub CI/CD workflow issues
- Build process for multi-platform releases
- Login issue on remote server

## [0.0.6] - 2025-04-25

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

## [0.0.4] - 2025-04-25

### Added
- HMAC-SHA256 file integrity verification to detect tampered files
- Validation tags for filename encryption to verify password correctness
- Comprehensive test suite for encryption functionality
- Enhanced error handling for file corruption detection

### Changed
- Improved security with authenticated encryption for files
- Better password verification for both files and directories

## [0.0.3] - 2025-04-25

### Added
- HTTPS support via the `--ssl=true` command line flag
- Automatic generation of self-signed certificates
- Custom certificate path options with `--cert` and `--key` flags
- TLS 1.2+ enforcement for enhanced security

## [0.0.2] - 2025-04-25

### Added
- Support for specifying IP and port
- Modal gallery view

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