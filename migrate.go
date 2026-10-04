package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// runMigration orchestrates the full migration from v1 to v2 encryption
func runMigration(password string) error {
	oldHash := hashPasswordLegacy(password)
	newHash := hashPassword(password)

	if oldHash == newHash {
		fmt.Println("Warning: old and new key hashes are identical (unexpected). Check implementation.")
	}

	fmt.Println("Step 1: Migrating file contents...")
	totalFiles, migratedFiles, skippedFiles, errorFiles := migrateFileContents(oldHash, newHash)

	fmt.Println("Step 2: Migrating file names...")
	migratedNames, nameErrors := migrateFileNames(password, oldHash, newHash)

	fmt.Println("Step 3: Migrating directory names...")
	migratedDirs, dirErrors := migrateDirectoryNames(password, oldHash, newHash)

	fmt.Printf("\n=== Migration Complete ===\n")
	fmt.Printf("Files processed:  %d\n", totalFiles)
	fmt.Printf("Files migrated:   %d\n", migratedFiles)
	fmt.Printf("Files skipped:    %d (already v2)\n", skippedFiles)
	fmt.Printf("File errors:      %d\n", errorFiles)
	fmt.Printf("Names migrated:   %d\n", migratedNames)
	fmt.Printf("Name errors:      %d\n", nameErrors)
	fmt.Printf("Dirs migrated:    %d\n", migratedDirs)
	fmt.Printf("Dir errors:       %d\n", dirErrors)

	if errorFiles > 0 || dirErrors > 0 || nameErrors > 0 {
		return fmt.Errorf("migration completed with %d file errors, %d name errors and %d directory errors", errorFiles, nameErrors, dirErrors)
	}
	return nil
}

// migrateFileContents re-encrypts all file contents from v1 to v2 format.
func migrateFileContents(oldHash, newHash string) (total, migrated, skipped, errors int) {
	dirs := []string{galleryDir, thumbnailsDir}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, encryptedExt) {
				return nil
			}

			total++

			// Detect current format
			f, err := os.Open(path)
			if err != nil {
				log.Printf("ERROR: cannot open %s: %v", path, err)
				errors++
				return nil
			}
			versionBuf := make([]byte, 1)
			_, readErr := f.Read(versionBuf)
			f.Close()
			if readErr != nil {
				log.Printf("ERROR: cannot read %s: %v", path, readErr)
				errors++
				return nil
			}

			if versionBuf[0] == fileFormatV2Magic {
				// Try to decrypt with new key to see if already migrated
				_, decErr := decryptFileV2(path, newHash)
				if decErr == nil {
					skipped++
					return nil // Already migrated
				}
				log.Printf("WARN: %s appears to be v2 but failed new-key decrypt, trying old key", path)
			}

			// Decrypt with old key (v1 or v2 with old key).
			// A v1 file starts with a random IV, so 1 in 256 v1 files begins with
			// the v2 magic byte: fall back to v1 when the v2 attempt fails.
			var data []byte
			if versionBuf[0] == fileFormatV2Magic {
				data, err = decryptFileV2(path, oldHash)
				if err != nil {
					data, err = decryptFileV1(path, oldHash)
				}
			} else {
				data, err = decryptFileV1(path, oldHash)
			}
			if err != nil {
				log.Printf("ERROR: cannot decrypt %s (old key): %v", path, err)
				errors++
				return nil
			}

			// Re-encrypt with new key in v2 format
			tmpPath := path + ".migrating"
			if err := encryptAndSaveFileV2(data, tmpPath, newHash); err != nil {
				log.Printf("ERROR: cannot re-encrypt %s: %v", path, err)
				os.Remove(tmpPath)
				errors++
				return nil
			}

			// Atomically replace old file
			if err := os.Rename(tmpPath, path); err != nil {
				log.Printf("ERROR: cannot replace %s: %v", path, err)
				os.Remove(tmpPath)
				errors++
				return nil
			}

			migrated++
			log.Printf("Migrated: %s", path)
			return nil
		})

		if err != nil {
			log.Printf("Error walking directory %s: %v", dir, err)
		}
	}
	return
}

// renameWithThumbnail renames a gallery entry and gives its thumbnail (same relative
// path under thumbnailsDir) the identical new name, so thumbnails stay linked
func renameWithThumbnail(galleryPath, newName string) error {
	newGalleryPath := filepath.Join(filepath.Dir(galleryPath), newName)

	rel, err := filepath.Rel(galleryDir, galleryPath)
	if err != nil {
		return err
	}
	thumbPath := filepath.Join(thumbnailsDir, rel)
	if _, err := os.Stat(thumbPath); err == nil {
		newThumbPath := filepath.Join(filepath.Dir(thumbPath), newName)
		if err := os.Rename(thumbPath, newThumbPath); err != nil {
			return fmt.Errorf("cannot rename thumbnail %s -> %s: %v", thumbPath, newThumbPath, err)
		}
	}

	if err := os.Rename(galleryPath, newGalleryPath); err != nil {
		return fmt.Errorf("cannot rename %s -> %s: %v", galleryPath, newGalleryPath, err)
	}
	return nil
}

// migrateDirectoryNames renames directories from old encrypted names to new encrypted names.
// Matching thumbnail directories are renamed to the same new names.
func migrateDirectoryNames(password, oldHash, newHash string) (migrated, errors int) {
	if _, err := os.Stat(galleryDir); os.IsNotExist(err) {
		return
	}

	// We need to process from deepest to shallowest to avoid path invalidation
	var dirPaths []string
	filepath.Walk(galleryDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && path != galleryDir && strings.HasSuffix(path, encryptedExt) {
			dirPaths = append(dirPaths, path)
		}
		return nil
	})

	// Process deepest paths first
	for i := len(dirPaths) - 1; i >= 0; i-- {
		dirPath := dirPaths[i]
		base := filepath.Base(dirPath)

		// Strip .enc extension to get the encrypted hex name
		encHex := strings.TrimSuffix(base, encryptedExt)

		// Try decrypting with new key first (already migrated)
		_, err := decryptFileNameV2(encHex, newHash)
		if err == nil {
			continue // Already migrated
		}

		// Decrypt with old key (v1 format)
		decrypted, err := decryptFileNameV1(encHex, oldHash)
		if err != nil {
			log.Printf("ERROR: cannot decrypt dir name %s: %v", dirPath, err)
			errors++
			continue
		}

		// Re-encrypt with new key, trimming names that would exceed the filesystem limit
		newEncHex, err := encryptFileName(decrypted, newHash)
		if err != nil {
			log.Printf("ERROR: cannot re-encrypt dir name %s: %v", decrypted, err)
			errors++
			continue
		}

		if err := renameWithThumbnail(dirPath, newEncHex+encryptedExt); err != nil {
			log.Printf("ERROR: %v", err)
			errors++
			continue
		}
		log.Printf("Migrated dir: %s -> %s", base, newEncHex+encryptedExt)
		migrated++
	}
	return
}

// migrateFileNames re-encrypts all file .enc names (filesystem names, not contents).
// Matching thumbnails are renamed to the same new names.
func migrateFileNames(password, oldHash, newHash string) (migrated, errors int) {
	if _, err := os.Stat(galleryDir); os.IsNotExist(err) {
		return
	}

	// Collect all file entries (not directories)
	type fileEntry struct {
		path    string
		encName string
	}
	var files []fileEntry

	filepath.Walk(galleryDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, encryptedExt) {
			base := filepath.Base(path)
			encName := strings.TrimSuffix(base, encryptedExt)
			files = append(files, fileEntry{path: path, encName: encName})
		}
		return nil
	})

	for _, fe := range files {
		// Try to decrypt name with new key first (already migrated)
		_, err2 := decryptFileNameV2(fe.encName, newHash)
		if err2 == nil {
			continue // Already migrated
		}

		// Try to decrypt name with old key
		decrypted, err := decryptFileNameV1(fe.encName, oldHash)
		if err != nil {
			log.Printf("ERROR: cannot decrypt filename %s: %v", fe.encName, err)
			errors++
			continue
		}

		// Re-encrypt with new key, trimming names that would exceed the filesystem limit
		newEncName, err := encryptFileName(decrypted, newHash)
		if err != nil {
			log.Printf("ERROR: cannot re-encrypt filename %s: %v", decrypted, err)
			errors++
			continue
		}

		if err := renameWithThumbnail(fe.path, newEncName+encryptedExt); err != nil {
			log.Printf("ERROR: %v", err)
			errors++
			continue
		}
		log.Printf("Migrated filename: %s -> %s", fe.encName, newEncName)
		migrated++
	}
	return
}
