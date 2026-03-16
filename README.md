# Go Gallery

![CI/CD Status](https://github.com/rhamdeew/go_gal/actions/workflows/release.yml/badge.svg)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/rhamdeew/go_gal)](https://github.com/rhamdeew/go_gal/releases/latest)
[![GitHub license](https://img.shields.io/github/license/rhamdeew/go_gal)](https://github.com/rhamdeew/go_gal/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/rhamdeew/go_gal)](https://goreportcard.com/report/github.com/rhamdeew/go_gal)
[![GitHub stars](https://img.shields.io/github/stars/rhamdeew/go_gal)](https://github.com/rhamdeew/go_gal/stargazers)

A password-protected web gallery application written in Go. All folders and files are encrypted, and only users with the correct password can access and view the content.

![app screenshot](https://github.com/user-attachments/assets/a77fee7a-77ac-49ef-a3a2-c51460968cb9)

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

- Folder and file names are encrypted using **AES-256-GCM** (authenticated encryption)
- File contents are encrypted with **AES-256-CFB** with **HMAC-SHA256** integrity protection (IV is authenticated)
- Password-based key derivation using **Argon2id** (GPU/ASIC-resistant, OWASP recommended)
- No passwords are stored on the server — only the derived key is held in the session
- Session-based authentication with secure cookies (HttpOnly, SameSite)
- Cookie is fully deleted on logout (MaxAge=-1)
- Login rate limiting: 10 attempts per 15-minute window per IP
- Optional HTTPS with TLS 1.2+ and TLS private key stored with restricted permissions (0600)
- Security response headers: `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Strict-Transport-Security` (when SSL enabled)
- Protection against directory traversal attacks
- Environment variable configuration for sensitive values

### File Format Versions

The application uses a versioned file format to allow safe upgrades:

| Version | KDF | File cipher | Filename cipher | Notes |
|---------|-----|------------|-----------------|-------|
| v1 (legacy) | SHA-256 | AES-256-CFB + HMAC | AES-256-CFB | Readable by new binary |
| **v2 (current)** | **Argon2id** | **AES-256-CFB + HMAC(IV+data)** | **AES-256-GCM** | Written by new binary |

New files are always written in v2. Old v1 files remain readable until you run the migration.

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

- FFmpeg (optional, for video thumbnail generation)
- Go 1.23+ (only if building from source)

## Installation

### Linux / macOS

1. Download the latest release archive for your platform from the [Releases page](https://github.com/rhamdeew/go_gal/releases):
   - `go_gal_linux_amd64.tar.gz` — Linux x86-64
   - `go_gal_linux_arm64.tar.gz` — Linux ARM64 (Raspberry Pi, etc.)
   - `go_gal_darwin_amd64.tar.gz` — macOS Intel
   - `go_gal_darwin_arm64.tar.gz` — macOS Apple Silicon

2. Extract the archive:
   ```bash
   mkdir go_gal && tar -xzvf go_gal_linux_amd64.tar.gz -C go_gal
   cd go_gal
   ```

3. Run the installation script:
   ```bash
   sudo ./install.sh --session-key="your-random-secure-key" --salt="your-random-secure-salt"
   ```

   The script creates a `gogal` system user, installs everything to `/opt/go_gal`, and registers a systemd service. If `--session-key` and `--salt` are omitted, random values are generated automatically and written into the systemd unit file — you can retrieve them later with:
   ```bash
   sudo grep -E "GO_GAL_(SESSION_KEY|SALT)" /etc/systemd/system/go_gal.service
   ```

4. Start and enable the service:
   ```bash
   sudo systemctl start go_gal
   sudo systemctl enable go_gal
   ```

5. Open `http://<your-server>:8080` in a browser and set your gallery password.

### Windows

1. Download `go_gal_windows_amd64.zip` from the [Releases page](https://github.com/rhamdeew/go_gal/releases).

2. Extract the archive to a folder, e.g. `C:\go_gal\`.

3. Open **PowerShell** and run the application:
   ```powershell
   cd C:\go_gal
   .\go_gal.exe --host=0.0.0.0 --port=8080
   ```

4. Open `http://localhost:8080` in a browser.

#### Running as a Windows Service (optional)

Use [NSSM](https://nssm.cc/download) to install go_gal as a background service:

```powershell
# Install NSSM, then:
nssm install go_gal "C:\go_gal\go_gal.exe"
# In the NSSM GUI set the working directory to C:\go_gal
nssm start go_gal
```

#### Environment variables on Windows

Set these before starting the application (recommended for production):

```powershell
$env:GO_GAL_SESSION_KEY = "your-random-secure-key"
$env:GO_GAL_SALT        = "your-random-secure-salt"
.\go_gal.exe --host=0.0.0.0 --port=8080
```

#### FFmpeg for video thumbnails (Windows)

Download FFmpeg from [ffmpeg.org](https://ffmpeg.org/download.html) and add `ffmpeg.exe` to your `PATH`.

### Building from Source

Requires Go 1.23+:

```bash
git clone https://github.com/rhamdeew/go_gal.git
cd go_gal
go mod download
go build -o go_gal .
sudo ./install.sh
```

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
   --migrate         : Migrate gallery files from v1 to v2 encryption format (see Migration section)
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

## Migrating from a Previous Version

If you have an existing gallery encrypted with an older version of go_gal, you need to run the one-time migration to upgrade all files to the new v2 format (Argon2id key derivation + improved HMAC). The new binary can **read** old files without migration, but migration is strongly recommended for security.

### What changes during migration

| | Before | After |
|---|---|---|
| Key derivation | SHA-256 (single pass) | Argon2id (GPU-resistant) |
| Filename encryption | AES-256-CFB | AES-256-GCM |
| File HMAC | Covers ciphertext only | Covers IV + ciphertext |
| File format | v1 | v2 |

The gallery password does **not** change. All your files remain accessible.

### Step 1 — Backup

```bash
cp -r gallery/ gallery_backup/
cp -r thumbnails/ thumbnails_backup/
```

### Step 2 — Set environment variables

Make sure you use the **same** `GO_GAL_SALT` value as your running instance — it is part of the key derivation:

```bash
export GO_GAL_SESSION_KEY="your-session-key"
export GO_GAL_SALT="your-salt"
```

If you were using the defaults (no env vars set), do not set them now either — leave them unset so the migration uses the same defaults.

### Step 3 — Stop the server and run migration

```bash
# Stop the gallery server first
sudo systemctl stop go_gal   # or kill the process

# Run migration (you will be prompted for the gallery password)
./go_gal --migrate
```

Example output:
```
Enter gallery password:
Starting migration...
Migrated: gallery/3a8f1c...enc
Migrated: gallery/7d2b04...enc
...

=== Migration Complete ===
Files processed:  47
Files migrated:   47
Files skipped:    0  (already v2)
File errors:      0
Dirs migrated:    3
Dir errors:       0
```

If there are any errors, the original files are untouched — restore from backup and report the issue.

### Step 4 — Restart the server

```bash
sudo systemctl start go_gal
```

On first login after migration you will notice a ~1 second delay at the login screen — this is Argon2id computing the key, which is intentional and prevents brute-force attacks.

### Step 5 — Clean up backup (after confirming everything works)

```bash
rm -rf gallery_backup/ thumbnails_backup/
```

### systemd update with migration

If running as a systemd service, the full update sequence is:

```bash
# 1. Stop service
sudo systemctl stop go_gal

# 2. Backup gallery data
cp -r /opt/go_gal/gallery /opt/go_gal/gallery_backup
cp -r /opt/go_gal/thumbnails /opt/go_gal/thumbnails_backup

# 3. Install new binary (preserve existing keys)
sudo ./install.sh \
  --session-key="your_existing_session_key" \
  --salt="your_existing_salt"

# 4. Run migration as the service user
cd /opt/go_gal
sudo -u go_gal GO_GAL_SALT="your_existing_salt" ./go_gal --migrate

# 5. Start service
sudo systemctl start go_gal
```

## Important Notes

- **Remember your password!** If you forget it, there is no way to recover your encrypted files since the password is never stored on the server.
- When creating a new gallery, the first password you enter will be the one used for all encryption.
- Encryption and decryption happen on the server side; the password is only used during login to derive the encryption key (via Argon2id), which is then held in a signed session cookie for the session duration.
- File integrity is verified with HMAC-SHA256 on every read, detecting tampering or corruption.
- When using self-signed certificates, your browser may show a security warning. You can safely proceed for personal use.
- **Security Best Practices:**
  - For production or internet-facing deployments, always use HTTPS (`--ssl=true`)
  - Always set `GO_GAL_SESSION_KEY` and `GO_GAL_SALT` to strong, random values in production
  - Run the `--migrate` command after upgrading from an older version to use the strongest available encryption
  - Consider running behind a reverse proxy (nginx, Caddy) for additional security and proper TLS certificates
  - Use a strong, unique password — Argon2id makes brute force expensive, but a strong password is still the primary defence

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

1. Download the release archive for your platform from the [Releases page](https://github.com/rhamdeew/go_gal/releases) and extract it:
   ```bash
   mkdir go_gal && tar -xzvf go_gal_linux_amd64.tar.gz -C go_gal
   cd go_gal
   ```

2. Run the installation script:
   ```bash
   sudo ./install.sh
   ```

   The script creates a `gogal` system user, copies the binary, templates, and static files to `/opt/go_gal`, and registers a systemd service.

3. Start and enable the service:
   ```bash
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

- **Always preserve your session key and salt** — new random values will be generated if not specified, which would make your encrypted data inaccessible
- The installer will overwrite the binary, templates, and static files with the new version
- Your gallery data in `/opt/go_gal/gallery` (or custom directory) will be preserved
- SSL certificates will be preserved if they exist
- The systemd service configuration will be updated
- **After upgrading, run `--migrate`** to re-encrypt your gallery with the improved v2 format (see the Migration section above)

**Quick Update Example:**
```bash
# Stop service
sudo systemctl stop go_gal

# Update with preserved keys (replace with your actual values)
sudo ./install.sh \
  --session-key="abc123xyz789" \
  --salt="def456uvw"

# Migrate gallery to v2 encryption format
cd /opt/go_gal
sudo -u go_gal GO_GAL_SALT="def456uvw" ./go_gal --migrate

# Start service
sudo systemctl start go_gal
```
