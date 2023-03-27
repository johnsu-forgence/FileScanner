package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/shirou/gopsutil/host"
)

type FileData struct {
	FilePath    string      `json:"file_path"`
	FileName    string      `json:"file_name"`
	Extension   string      `json:"extension"`
	Size        int64       `json:"size"`
	ModTime     time.Time   `json:"mod_time"`
	IsDir       bool        `json:"is_dir"`
	Permissions os.FileMode `json:"permissions"`
	MD5         string      `json:"md5"`
	SHA1        string      `json:"sha1"`
	SHA256      string      `json:"sha256"`
}

type FlagData struct {
	Debug       bool   `json:"debug"`
	StartDir    string `json:"start_dir"`
	ScanSubDirs bool   `json:"scan_sub_dirs"`
	OutputFile  string `json:"output_file"`
	Concurrency int    `json:"concurrency"`
}

type OutputData struct {
	HostData host.InfoStat `json:"host_data"`
	FlagData *FlagData     `json:"flag_data"`
	FileData []FileData    `json:"file_data"`
}

func main() {
	debug := flag.Bool("debug", false, "enable debug output")
	startDir := flag.String("start-dir", ".", "starting directory for file scanning")
	scanSubDirs := flag.Bool("sub-dirs", true, "scan subdirectories")
	outputFile := flag.String("output", "file_data.json", "output file path")
	concurrency := flag.Int("concurrency", 10, "number of concurrent workers")
	help := flag.Bool("help", false, "show help message")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Traverse the various folders on a system, gather information on each file to include file location, filename, file extension, size, mod time, is_dir, permissions, md5, sha1, sha256, and ssdeep, run in parallel, and store all the data in a JSON file.\n")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	flagData := &FlagData{
		Debug:       *debug,
		StartDir:    *startDir,
		ScanSubDirs: *scanSubDirs,
		OutputFile:  *outputFile,
		Concurrency: *concurrency,
	}

	hostData, _ := host.Info()

	outputData := OutputData{
		HostData: *hostData,
		FlagData: flagData,
		FileData: make([]FileData, 0),
	}

	var wg sync.WaitGroup
	files := make(chan FileData, 100)

	wg.Add(1)
	go func() {
		defer wg.Done()
		traverseFiles(*startDir, files, *scanSubDirs)
		close(files)
	}()

	for file := range files {
		wg.Add(1)
		go func(file FileData) {
			defer wg.Done()

			if *debug {
				fmt.Println("Processing file:", file.FilePath)
			}

			file.MD5, _ = getHash(file.FilePath, "md5")
			file.SHA1, _ = getHash(file.FilePath, "sha1")
			file.SHA256, _ = getHash(file.FilePath, "sha256")

			outputData.FileData = append(outputData.FileData, file)
		}(file)
	}

	wg.Wait()

	// Write output file
	jsonBytes, _ := json.MarshalIndent(outputData, "", "  ")
	err := ioutil.WriteFile(*outputFile, jsonBytes, 0644)
	if err != nil {
		fmt.Println("Error writing to output file:", err)
	}

	fmt.Println("Done!")
}

func traverseFiles(dirPath string, files chan<- FileData, scanSubDirs bool) {
	filepath.Walk(dirPath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("Error walking file path:", err)
			return nil
		}

		if !info.IsDir() {
			absPath, err := filepath.Abs(filePath)
			if err != nil {
				fmt.Println("Error getting absolute path:", err)
				return nil
			}

			fileData := FileData{
				FilePath:    absPath,
				FileName:    filepath.Base(filePath),
				Extension:   filepath.Ext(filePath),
				Size:        info.Size(),
				ModTime:     info.ModTime(),
				IsDir:       false,
				Permissions: info.Mode(),
			}

			fileData.MD5, _ = getHash(fileData.FilePath, "md5")
			fileData.SHA1, _ = getHash(fileData.FilePath, "sha1")
			fileData.SHA256, _ = getHash(fileData.FilePath, "sha256")

			files <- fileData
		} else if scanSubDirs {
			if filePath != dirPath {
				return filepath.SkipDir
			}
		}

		return nil
	})
}

func getHash(filePath string, hashType string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var hash []byte
	switch hashType {
	case "md5":
		h := md5.New()
		if _, err := io.Copy(h, file); err != nil {
			return "", err
		}
		hash = h.Sum(nil)
	case "sha1":
		h := sha1.New()
		if _, err := io.Copy(h, file); err != nil {
			return "", err
		}
		hash = h.Sum(nil)
	case "sha256":
		h := sha256.New()
		if _, err := io.Copy(h, file); err != nil {
			return "", err
		}
		hash = h.Sum(nil)
	default:
		return "", fmt.Errorf("unsupported hash type: %s", hashType)
	}

	return fmt.Sprintf("%x", hash), nil
}
