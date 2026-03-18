# Go Gallery

![CI/CD Status](https://github.com/rhamdeew/go_gal/actions/workflows/release.yml/badge.svg)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/rhamdeew/go_gal)](https://github.com/rhamdeew/go_gal/releases/latest)
[![GitHub license](https://img.shields.io/github/license/rhamdeew/go_gal)](https://github.com/rhamdeew/go_gal/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/rhamdeew/go_gal)](https://goreportcard.com/report/github.com/rhamdeew/go_gal)
[![GitHub stars](https://img.shields.io/github/stars/rhamdeew/go_gal)](https://github.com/rhamdeew/go_gal/stargazers)

Password-protected web gallery with client-side encryption. All folders and files are encrypted with AES-256 using your password — only users with the correct password can access and view the content.

![app screenshot](https://github.com/user-attachments/assets/a77fee7a-77ac-49ef-a3a2-c51460968cb9)

## Features

- Password-protected access to the gallery
- All folders and files are encrypted with your password
- Files are decrypted on-the-fly when viewed
- Automatic thumbnail generation for images and videos
- Fast gallery browsing with thumbnail previews
- Create new folders with encrypted names
- Upload images and videos (multi-file with drag-and-drop)
- Support for video formats: MP4, MOV, AVI, MKV, WebM, 3GP, FLV, WMV, M4V
- Support for image formats: JPEG, PNG, GIF, WebP
- Built-in video player
- HTTPS support: self-signed certificates or automatic TLS via Let's Encrypt (ACME)
- No server-side password storage

---

# User Guide

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
   sudo ./install.sh
   ```

   The script is interactive and will ask you:
   - **Session key** and **salt** for encryption (press Enter to generate random values)
   - **Host** and **port** to bind to
   - **SSL/TLS mode**: HTTP only, manual certificates, or automatic Let's Encrypt

   It creates a `gogal` system user, installs everything to `/opt/go_gal`, and registers a systemd service. You can retrieve the generated keys any time with:
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

### FFmpeg (optional)

For video thumbnail generation, install FFmpeg:

- **macOS**: `brew install ffmpeg`
- **Ubuntu/Debian**: `sudo apt install ffmpeg`
- **Windows**: Download from [ffmpeg.org](https://ffmpeg.org/download.html) and add to PATH

Image thumbnails work without FFmpeg. Video files can still be uploaded and viewed — placeholder images will be shown instead of actual video thumbnails.

## Updating

### Linux / macOS (automated)

The installation includes an `update.sh` script that handles updates automatically:

```bash
sudo /opt/go_gal/update.sh
```

The script will:
- Check for the latest version on GitHub
- Backup your current installation
- Preserve your encryption keys
- Download and install the update
- Restart the service

**Options:**
```bash
sudo /opt/go_gal/update.sh --version=v0.0.26  # Update to specific version
sudo /opt/go_gal/update.sh --dry-run           # Check for updates without installing
```

### Linux / macOS (manual)

1. **Backup your encryption keys:**
   ```bash
   sudo grep -E "GO_GAL_(SESSION_KEY|SALT)" /etc/systemd/system/go_gal.service
   ```
   Note down the values for `GO_GAL_SESSION_KEY` and `GO_GAL_SALT`.

2. **Stop the service:**
   ```bash
   sudo systemctl stop go_gal
   ```

3. **Download the new version** from the [Releases page](https://github.com/rhamdeew/go_gal/releases) and extract.

4. **Run the installer** and enter your existing session key and salt when prompted:
   ```bash
   sudo ./install.sh
   ```

5. **Start the service:**
   ```bash
   sudo systemctl start go_gal
   ```

**Important:** Always preserve your session key and salt — new random values will make your encrypted data inaccessible.

### Windows (automated)

The distribution includes an `update.ps1` script:

```powershell
.\update.ps1
```

The script will:
- Check for the latest version on GitHub
- Backup your current installation
- Preserve your encryption keys (from .env file or environment variables)
- Download and install the update

**Options:**
```powershell
.\update.ps1 -Version v0.0.26  # Update to specific version
.\update.ps1 -DryRun           # Check for updates without installing
```

**Note:** For the update script to work, create a `.env` file in the installation directory with your keys:
```powershell
GO_GAL_SESSION_KEY=your-key
GO_GAL_SALT=your-salt
```

### Windows (manual)

1. Stop the application (Ctrl+C or `nssm stop go_gal`)
2. Download the new version and extract
3. Start the application with the same environment variables

## Uninstallation

### Linux / macOS

```bash
sudo /opt/go_gal/uninstall.sh
```

This will stop and disable the service, remove the service file, and remove the installation directory.

### Windows

Delete the application folder and remove the NSSM service if configured:
```powershell
nssm remove go_gal confirm
```

## Migration from versions before 0.0.22

> **This section only applies if you are upgrading from a version older than 0.0.22.**
> If you are installing fresh or upgrading from 0.0.22 or later, you can skip this section.

Old versions used v1 encryption format (SHA-256 key derivation). New versions use v2 format (Argon2id). The new binary can **read** old v1 files without migration, but migration is strongly recommended for security.

### What changes during migration

| | Before (v1) | After (v2) |
|---|---|---|
| Key derivation | SHA-256 (single pass) | Argon2id (GPU-resistant) |
| Filename encryption | AES-256-CFB | AES-256-GCM |
| File HMAC | Covers ciphertext only | Covers IV + ciphertext |

The gallery password does **not** change. All your files remain accessible.

### Migration Steps

#### Step 1 — Backup

```bash
cp -r gallery/ gallery_backup/
cp -r thumbnails/ thumbnails_backup/
```

#### Step 2 — Stop the server

```bash
sudo systemctl stop go_gal   # or kill the process
```

#### Step 3 — Run migration

Make sure you use the **same** `GO_GAL_SALT` value as your running instance:

```bash
export GO_GAL_SALT="your-salt"
./go_gal --migrate
```

You will be prompted for the gallery password.

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

#### Step 4 — Restart the server

```bash
sudo systemctl start go_gal
```

On first login after migration you will notice a ~1 second delay at the login screen — this is Argon2id computing the key, which prevents brute-force attacks.

#### Step 5 — Clean up backup (after confirming everything works)

```bash
rm -rf gallery_backup/ thumbnails_backup/
```

---

# Developer Guide

## Building from Source

Requires Go 1.23+:

```bash
git clone https://github.com/rhamdeew/go_gal.git
cd go_gal
go mod download
go build -o go_gal .
```

## Running

```bash
./go_gal
```

Command line arguments:
```
--host=<ip>            Host IP address to bind to (default: localhost)
--port=<number>        Port number (default: 8080)
--ssl                  Enable HTTPS with self-signed certificates
--cert=<path>          Path to SSL certificate file (default: cert.pem)
--key=<path>           Path to SSL private key file (default: key.pem)
--acme                 Enable automatic HTTPS via Let's Encrypt
--acme-domain=<host>   Domain name for the Let's Encrypt certificate (required with --acme)
--acme-email=<email>   Email address for Let's Encrypt notifications
--acme-cache=<dir>     Directory to cache Let's Encrypt certificates (default: acme-cache)
--migrate              Migrate gallery files from v1 to v2 encryption format
--version              Show version information
```

## Testing

```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. -benchmem
```

## Environment Variables

- `GO_GAL_SESSION_KEY`: Custom session key for cookie encryption (default: hardcoded value)
- `GO_GAL_SALT`: Custom salt for password hashing (default: hardcoded value)
- `GO_GAL_SSL_ENABLED`: Set to "true" to enable HTTPS features

For production use, set custom values:
```bash
export GO_GAL_SESSION_KEY="your-random-secure-key"
export GO_GAL_SALT="your-random-secure-salt"
./go_gal --ssl=true
```

## Security Features

- Folder and file names are encrypted using **AES-256-GCM** (authenticated encryption)
- File contents are encrypted with **AES-256-CFB** with **HMAC-SHA256** integrity protection
- Password-based key derivation using **Argon2id** (GPU/ASIC-resistant, OWASP recommended)
- No passwords are stored on the server — only the derived key is held in the session
- Session-based authentication with secure cookies (HttpOnly, SameSite)
- Login rate limiting: 10 attempts per 15-minute window per IP
- Optional HTTPS with TLS 1.2+ — self-signed certificates or automatic Let's Encrypt via ACME
- Security response headers: `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Strict-Transport-Security`
- Protection against directory traversal attacks

## File Format Versions

| Version | KDF | File cipher | Filename cipher | Notes |
|---------|-----|------------|-----------------|-------|
| v1 (legacy) | SHA-256 | AES-256-CFB + HMAC | AES-256-CFB | Readable by new binary |
| **v2 (current)** | **Argon2id** | **AES-256-CFB + HMAC(IV+data)** | **AES-256-GCM** | Written by new binary |

New files are always written in v2. Old v1 files remain readable until you run the migration.

## GitHub Actions and Releases

This project uses GitHub Actions to automatically build and release binaries for multiple platforms when you create a new tag:

1. Build binaries for Linux (amd64, arm64), Windows (amd64), macOS (amd64, arm64)
2. Run tests
3. Create a release with all binaries bundled

To create a new release:
```bash
git tag v1.0.0
git push origin v1.0.0
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.