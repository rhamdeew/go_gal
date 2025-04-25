# Go Gallery

A password-protected web gallery application written in Go. All folders and files are encrypted, and only users with the correct password can access and view the content.

## Features

- Password-protected access to the gallery
- All folders and files are encrypted with your password
- Files are decrypted on-the-fly when viewed
- Create new folders with encrypted names
- Upload images to your gallery
- Multi-file upload support with drag-and-drop interface
- Image preview before uploading
- Modern and responsive UI
- No server-side password storage for enhanced security
- HTTPS support with self-signed certificates

## Security Features

- Folder and file names are encrypted using AES-256
- File contents are encrypted with AES-256
- File integrity verification with HMAC-SHA256 to detect tampering
- Validation tags for filename encryption to verify password correctness
- No passwords are stored on the server, only used for encryption/decryption
- Session-based authentication with secure cookies
- Optional HTTPS with TLS 1.2+ for secure connections

## Requirements

- Go 1.18 or higher

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
   - Upload images by selecting files or using drag-and-drop
   - See image previews before uploading
   - View images by clicking on them

## Important Notes

- **Remember your password!** If you forget it, there is no way to recover your encrypted files since the password is not stored anywhere.
- When creating a new gallery, the first password you enter will be the one used for encryption.
- For security purposes, encryption/decryption happens on the server side, but the password is not stored permanently.
- The application uses HMAC validation to detect file tampering, providing an additional layer of security.
- When using self-signed certificates, your browser may show a security warning. You can safely proceed for personal use.

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