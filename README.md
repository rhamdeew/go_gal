# Go Gallery

![CI/CD Status](https://github.com/rhamdeew/go_gal/actions/workflows/release.yml/badge.svg)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/rhamdeew/go_gal)](https://github.com/rhamdeew/go_gal/releases/latest)
[![GitHub license](https://img.shields.io/github/license/rhamdeew/go_gal)](https://github.com/rhamdeew/go_gal/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/rhamdeew/go_gal)](https://goreportcard.com/report/github.com/rhamdeew/go_gal)
[![GitHub stars](https://img.shields.io/github/stars/rhamdeew/go_gal)](https://github.com/rhamdeew/go_gal/stargazers)

A password-protected web gallery application written in Go. All folders and files are encrypted, and only users with the correct password can access and view the content.

![go_gallery](https://github.com/user-attachments/assets/3df10213-0fd5-4824-b7f5-6d69b0273b75)

## Features

- Password-protected access to the gallery
- All folders and files are encrypted with your password
- Files are decrypted on-the-fly when viewed
- **Automatic thumbnail generation for images and videos**
- **Fast gallery browsing with thumbnail previews**
- Create new folders with encrypted names
- Upload images and videos to your gallery
- Support for common video formats (MP4, MOV, AVI, MKV, WebM, 3GP, FLV, WMV, M4V)
- Support for common image formats (JPEG, PNG, GIF, WebP)
- Built-in video player with controls for viewing videos
- Multi-file upload support with drag-and-drop interface
- Image and video preview before uploading
- Modern and responsive UI with unified media gallery
- No server-side password storage for enhanced security
- HTTPS support with self-signed certificates

## Thumbnail System

The gallery now includes automatic thumbnail generation for both images and videos, significantly improving browsing performance and user experience.

### Supported Formats for Thumbnails

**Images** (auto-thumbnailed):
- JPEG/JPG
- PNG
- GIF
- WebP

**Videos** (auto-thumbnailed with FFmpeg):
- MP4, MOV, AVI, MKV, WebM, 3GP, FLV, WMV, M4V

### How Thumbnails Work

1. **Automatic Generation**: When you upload images or videos, thumbnails are automatically created
2. **Encrypted Storage**: Thumbnails are encrypted and stored separately from original files
3. **Fast Loading**: Gallery displays thumbnails instead of loading full files
4. **Video Previews**: Video thumbnails are extracted from the first second of the video
5. **Optimized Size**: All thumbnails are 200x200 pixels maximum, maintaining aspect ratio
6. **Fallback Placeholders**: When thumbnail generation fails (e.g., FFmpeg not available), colored placeholder images are automatically generated

### FFmpeg Requirement

For video thumbnail generation, FFmpeg must be installed:

- **macOS**: `brew install ffmpeg`
- **Ubuntu/Debian**: `sudo apt install ffmpeg`
- **Windows**: Download from [ffmpeg.org](https://ffmpeg.org/download.html) and add to PATH

**Note**: Image thumbnails work without FFmpeg. Video files can still be uploaded and viewed without FFmpeg, but placeholder images will be shown instead of actual video thumbnails.

## Troubleshooting

### "FFmpeg not found" Error
- **Issue**: Video uploads work, but colorful placeholder images appear instead of actual video thumbnails
- **Solution**: Install FFmpeg and ensure it's in your system PATH
- **Alternative**: Placeholder images still provide a visual representation - the gallery remains fully functional

### Placeholder Images Instead of Thumbnails
- **Blue placeholders**: Indicate video files without generated thumbnails (likely missing FFmpeg)
- **Gray placeholders**: Indicate image files where thumbnail generation failed
- **Note**: Placeholder images are automatically generated and encrypted like real thumbnails

### Thumbnail Not Displaying
- Check browser console for errors
- Verify the file format is supported
- Ensure FFmpeg is installed for video files (or expect placeholder images)

### Performance Issues
- Thumbnails are cached with 1-hour browser cache
- Large video files may take time to generate thumbnails on first upload
- Placeholder generation is much faster than video thumbnail extraction

## Security Features

- Folder and file names are encrypted using AES-256
- File contents are encrypted with AES-256
- File integrity verification with HMAC-SHA256 to detect tampering
- Validation tags for filename encryption to verify password correctness
- No passwords are stored on the server, only used for encryption/decryption
- Session-based authentication with secure cookies
- Optional HTTPS with TLS 1.2+ for secure connections
- Protection against directory traversal attacks
- Environment variable configuration for sensitive values

## Environment Variables

The application can be configured using the following environment variables:

- `GO_GAL_SESSION_KEY`: Custom session key for cookie encryption (default: a hardcoded value)
- `GO_GAL_SALT`: Custom salt for password hashing (default: a hardcoded value)
- `GO_GAL_SSL_ENABLED`: Set to "true" to enable HTTPS features (automatically set when using --ssl flag)

For production use, it's highly recommended to set custom values for these variables:

```bash
export GO_GAL_SESSION_KEY="your-random-secure-key"
export GO_GAL_SALT="your-random-secure-salt"
./go_gal --ssl=true
```

## Requirements

- Go 1.18 or higher
- FFmpeg (optional, for video thumbnail generation)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/rhamdeew/go_gal.git
   cd go_gal
   ```

2. Download the necessary dependencies:
   ```
   go mod download
   ```

3. Build the application:
   ```
   go build -o go_gal
   ```

4. Run the installation script included in the release:
   ```
   sudo ./install.sh
   ```

   The script will automatically detect and use any binary matching the pattern `go_gal*` in the current directory and create the necessary directories (gallery and thumbnails).

## Usage

1. Run the application:
   ```
   ./go_gal
   ```

   You can also specify custom host and port:
   ```
   ./go_gal --host=0.0.0.0 --port=9000
   ```

   To enable HTTPS with self-signed certificates:
   ```
   ./go_gal --ssl=true
   ```

   Available command line arguments:
   ```
   --host=<ip>       : Specify the host IP address (default: 127.0.0.1)
   --port=<number>   : Specify the port number (default: 8080)
   --ssl=true/false  : Enable HTTPS with self-signed certificates (default: false)
   --cert=<path>     : Specify a custom path for the SSL certificate (default: cert.pem)
   --key=<path>      : Specify a custom path for the SSL private key (default: key.pem)
   ```

2. Open your web browser and go to:
   ```
   http://localhost:8080
   ```

   Or if SSL is enabled:
   ```
   https://localhost:8080
   ```

   Or if you used custom host/port:
   ```
   http://<host>:<port>
   ```

3. Enter your password to access the gallery. This password will be used to encrypt and decrypt your files.

4. You can now:
   - Browse your encrypted gallery
   - Create new directories
   - Upload images and videos by selecting files or using drag-and-drop
   - See image and video previews before uploading
   - View images and videos by clicking on them

## Important Notes

- **Remember your password!** If you forget it, there is no way to recover your encrypted files since the password is not stored anywhere.
- When creating a new gallery, the first password you enter will be the one used for encryption.
- For security purposes, encryption/decryption happens on the server side, but the password is not stored permanently.
- The application uses HMAC validation to detect file tampering, providing an additional layer of security.
- When using self-signed certificates, your browser may show a security warning. You can safely proceed for personal use.
- **Security Best Practices:**
  - For production or internet-facing deployments, always use HTTPS (--ssl=true)
  - Set custom values for `GO_GAL_SESSION_KEY` and `GO_GAL_SALT` environment variables
  - Consider running behind a reverse proxy for additional security
  - Use strong, unique passwords for your gallery

## GitHub Actions and Releases

This project uses GitHub Actions to automatically build and release binaries for multiple platforms when you create a new tag. The workflow will:

1. Build binaries for the following platforms:
   - Linux (amd64, arm64)
   - Windows (amd64)
   - macOS (amd64, arm64)

2. Run tests to ensure everything works

3. Create a release with all binaries bundled (including templates and static files)

To create a new release:

```bash
# Tag a new version
git tag v1.0.0

# Push the tag to GitHub
git push origin v1.0.0
```

The GitHub Actions workflow will automatically trigger, build the binaries, and create a release with all the necessary files.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

# Go Crypto Gallery - Systemd Service

## Installation as a systemd service

The application can be installed as a systemd service for automatic startup and management.

### Prerequisites

- A Linux system with systemd
- Root access for service installation

### Installation

1. Download the appropriate binary for your platform from the [Releases page](https://github.com/rhamdeew/go_gal/releases).

2. Run the installation script included in the release:
   ```
   sudo ./install.sh
   ```

   The script will automatically detect and use any binary matching the pattern `go_gal*` in the current directory and create the necessary directories (gallery and thumbnails).

3. Start and enable the service:
   ```
   sudo systemctl start go_gal
   sudo systemctl enable go_gal
   ```

### Configuration Options

You can pass the following options to the installation script:

| Option              | Description                   | Default          |
|---------------------|-------------------------------|------------------|
| `--dir=DIR`         | Installation directory        | `/opt/go_gal`    |
| `--port=PORT`       | Port to listen on             | `8080`           |
| `--host=HOST`       | Host IP to bind to            | `0.0.0.0`        |
| `--enable-ssl`      | Enable SSL/TLS                | Disabled         |
| `--cert=FILE`       | SSL certificate file          | `cert.pem`       |
| `--key=FILE`        | SSL key file                  | `key.pem`        |
| `--session-key=KEY` | Custom session encryption key | Random generated |
| `--salt=SALT`       | Custom password hashing salt  | Random generated |

Example:
```
sudo ./install.sh --port=9000 --enable-ssl --session-key="my-secure-key"
```

### Managing the Service

- Check status:
  ```
  sudo systemctl status go_gal
  ```

- Stop the service:
  ```
  sudo systemctl stop go_gal
  ```

- View logs:
  ```
  sudo journalctl -u go_gal
  ```

### Uninstallation

To uninstall the service:

```
sudo ./uninstall.sh
```

This will stop and disable the service, remove the service file, and remove the installation directory.

### Manual Configuration

If you need to manually configure the service after installation, edit the systemd service file:

```
sudo nano /etc/systemd/system/go_gal.service
```

After making changes, reload the systemd configuration:

```
sudo systemctl daemon-reload
sudo systemctl restart go_gal
```

### Updating the Application

To update an existing installation to a new version:

1. **Stop the service:**
   ```
   sudo systemctl stop go_gal
   ```

2. **Backup current encryption keys (important!):**

   Before updating, extract the current session key and salt from the service file to preserve access to your encrypted data:
   ```bash
   # View current keys
   sudo grep -E "GO_GAL_(SESSION_KEY|SALT)" /etc/systemd/system/go_gal.service
   ```

   Note down the values for `GO_GAL_SESSION_KEY` and `GO_GAL_SALT`.

3. **Download the new version** from the [Releases page](https://github.com/rhamdeew/go_gal/releases).

4. **Run the installer with your existing keys:**
   ```bash
   sudo ./install.sh \
     --session-key="your_existing_session_key" \
     --salt="your_existing_salt" \
     [other_options_as_needed]
   ```

5. **Start the service:**
   ```
   sudo systemctl start go_gal
   ```

**⚠️ Important Update Notes:**

- **Always preserve your session key and salt** - New random values will be generated if not specified, which could make your encrypted data inaccessible
- The installer will overwrite the binary, templates, and static files with the new version
- Your gallery data in `/opt/go_gal/gallery` (or custom directory) will be preserved
- SSL certificates will be preserved if they exist
- The systemd service configuration will be updated

**Quick Update Example:**
```bash
# Stop service
sudo systemctl stop go_gal

# Update with preserved keys (replace with your actual values)
sudo ./install.sh \
  --session-key="abc123xyz789" \
  --salt="def456uvw"

# Start service
sudo systemctl start go_gal
```
