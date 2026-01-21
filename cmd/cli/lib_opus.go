package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// checkLibOpus checks for library existence
func checkLibOpus() bool {
	switch runtime.GOOS {
	case "windows":
		// On Windows, we look for the DLL in the current directory
		_, err := os.Stat("libopus.dll")
		return err == nil
	default: // linux, darwin (macOS)
		cmd := exec.Command("pkg-config", "--exists", "opus")
		return cmd.Run() == nil
	}
}

// installLibOpus attempts to download/install the library
func installLibOpus() error {
	switch runtime.GOOS {
	case "darwin": // macOS
		return runCommand("brew", "install", "opus")

	case "linux":
		if isCommandAvailable("apt-get") {
			// Debian/Ubuntu
			return runCommand("sudo", "apt-get", "install", "-y", "libopus-dev")
		} else if isCommandAvailable("dnf") {
			// Fedora/RHEL
			return runCommand("sudo", "dnf", "install", "-y", "opus-devel")
		} else if isCommandAvailable("pacman") {
			// Arch Linux
			return runCommand("sudo", "pacman", "-S", "--noconfirm", "opus")
		} else if isCommandAvailable("apk") {
			// Alpine
			return runCommand("sudo", "apk", "add", "libopus-dev")
		}
		return fmt.Errorf("unsupported Linux package manager")

	case "windows":
		fmt.Println("Attempting to download libopus for Windows...")
		const downloadURL = "https://github.com/DSharpPlus/DSharpPlus/raw/master/docs/natives/vnext_natives_win32_x64.zip"

		// Download the zip file
		resp, err := http.Get(downloadURL)
		if err != nil {
			return fmt.Errorf("failed to download libopus zip: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("bad status: %s", resp.Status)
		}

		// Read the entire body into memory to pass to zip.NewReader
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		// Open the zip archive
		zipReader, err := zip.NewReader(bytes.NewReader(bodyBytes), int64(len(bodyBytes)))
		if err != nil {
			return fmt.Errorf("failed to open zip reader: %w", err)
		}

		// Find and extract libopus.dll
		found := false
		for _, file := range zipReader.File {
			// Check if the file is the dll we need (ignoring case and path)
			if strings.EqualFold(filepath.Base(file.Name), "libopus.dll") {
				fmt.Printf("Found %s, extracting...\n", file.Name)

				rc, err := file.Open()
				if err != nil {
					return fmt.Errorf("failed to open file in zip: %w", err)
				}

				// Create the file in the current directory
				dst, err := os.Create("libopus.dll")
				if err != nil {
					rc.Close()
					return fmt.Errorf("failed to create libopus.dll: %w", err)
				}

				_, err = io.Copy(dst, rc)
				dst.Close()
				rc.Close()

				if err != nil {
					return fmt.Errorf("failed to write libopus.dll: %w", err)
				}
				
				found = true
				break // Found it, stop looking
			}
		}

		if !found {
			return fmt.Errorf("libopus.dll not found in the downloaded archive")
		}

		fmt.Println("Successfully installed libopus.dll")
		return nil

	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// Helper to run commands and stream output
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("Running: %s %s\n", name, strings.Join(args, " "))
	return cmd.Run()
}

// Helper to check if a command exists in PATH
func isCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}