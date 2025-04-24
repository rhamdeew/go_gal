# Go Gallery

A password-protected web gallery application written in Go. All folders and files are encrypted, and only users with the correct password can access and view the content.

## Features

- Password-protected access to the gallery
- All folders and files are encrypted with your password
- Files are decrypted on-the-fly when viewed
- Create new folders with encrypted names
- Upload images to your gallery
- Modern and responsive UI
- No server-side password storage for enhanced security

## Security Features

- Folder and file names are encrypted using AES-256
- File contents are encrypted with AES-256
- No passwords are stored on the server, only used for encryption/decryption
- Session-based authentication with secure cookies

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
   go build -o gallery
   ```

## Usage

1. Run the application:
   ```
   ./gallery
   ```

2. Open your web browser and go to:
   ```
   http://localhost:8080
   ```

3. Enter your password to access the gallery. This password will be used to encrypt and decrypt your files.

4. You can now:
   - Browse your encrypted gallery
   - Create new directories
   - Upload images
   - View images by clicking on them

## Important Notes

- **Remember your password!** If you forget it, there is no way to recover your encrypted files since the password is not stored anywhere.
- When creating a new gallery, the first password you enter will be the one used for encryption.
- For security purposes, encryption/decryption happens on the server side, but the password is not stored permanently.

## License

This project is licensed under the MIT License - see the LICENSE file for details.