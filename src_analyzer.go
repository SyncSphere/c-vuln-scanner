package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Vulnerability represents a pattern to detect and its description
type Vulnerability struct {
	Pattern     *regexp.Regexp
	Description string
}

// ScanResult holds information about detected vulnerabilities
type ScanResult struct {
	File        string `json:"file"`
	LineNumber  int    `json:"line_number"`
	Description string `json:"description"`
}

// Define vulnerability patterns
var vulnerabilities = []Vulnerability{
	{regexp.MustCompile(`\bgets\s*\(`), "Potential buffer overflow: 'gets()' is unsafe"},
	{regexp.MustCompile(`\bstrcpy\s*\(`), "Potential buffer overflow: 'strcpy()' is unsafe"},
	{regexp.MustCompile(`\bsprintf\s*\(`), "Potential buffer overflow: 'sprintf()' is unsafe"},
	{regexp.MustCompile(`\bstrcat\s*\(`), "Potential buffer overflow: 'strcat()' is unsafe"},
	{regexp.MustCompile(`\bfork\s*\(\s*\)\s*;`), "Possible race condition: 'fork()' without proper handling"},
	{regexp.MustCompile(`\bpthread_create\s*\(`), "Possible concurrency issue: 'pthread_create()'"},
	{regexp.MustCompile(`\bMD5\s*\(`), "Weak cryptography: MD5 is insecure"},
	{regexp.MustCompile(`\bDES_set_key\s*\(`), "Weak cryptography: DES is insecure"},
	{regexp.MustCompile(`\bchroot\s*\(\s*`), "Potential chroot jail misconfiguration: check usage"},
}

// Unused variable detection regex
var varDeclarationRegex = regexp.MustCompile(`\b(int|char|float|double|long)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;`)
var identifierRegex = regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]*\b`)

// scanFile scans a given C/C++ file for vulnerabilities and unused variables
func scanFile(filePath string, results *[]ScanResult) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Could not open file: %s\n", filePath)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	variableUsage := make(map[string]bool) // Track usage of variables

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Detect vulnerabilities
		for _, vuln := range vulnerabilities {
			if vuln.Pattern.MatchString(line) {
				fmt.Printf("[!] %s: %s (Line %d)\n", filePath, vuln.Description, lineNumber)
				*results = append(*results, ScanResult{
					File:        filePath,
					LineNumber:  lineNumber,
					Description: vuln.Description,
				})
			}
		}

		// Detect variable declarations
		matches := varDeclarationRegex.FindStringSubmatch(line)
		if len(matches) > 2 {
			varName := matches[2]
			variableUsage[varName] = false // Mark as declared but not yet used
		}

		// Detect variable usage
		identifiers := identifierRegex.FindAllString(line, -1)
		for _, id := range identifiers {
			if _, exists := variableUsage[id]; exists {
				variableUsage[id] = true // Mark as used
			}
		}
	}

	// Report unused variables
	for varName, used := range variableUsage {
		if !used {
			fmt.Printf("[!] %s: Unused variable '%s'\n", filePath, varName)
			*results = append(*results, ScanResult{
				File:        filePath,
				LineNumber:  0,
				Description: fmt.Sprintf("Unused variable: '%s'", varName),
			})
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %s\n", filePath)
	}
}

// runStaticAnalysis runs Clang Static Analyzer on the given file
func runStaticAnalysis(filePath string, results *[]ScanResult) {
	cmd := exec.Command("clang-tidy", filePath, "--")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running static analysis on %s: %v\n", filePath, err)
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "warning:") || strings.Contains(line, "error:") {
			fmt.Printf("[!] Static Analysis %s: %s\n", filePath, line)
			*results = append(*results, ScanResult{
				File:        filePath,
				LineNumber:  0,
				Description: line,
			})
		}
	}
}

// scanDirectory recursively scans a directory for C/C++ files
func scanDirectory(root string) []ScanResult {
	var results []ScanResult

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %v\n", path, err)
			return nil
		}
		if !info.IsDir() && (filepath.Ext(path) == ".c" || filepath.Ext(path) == ".cpp") {
			scanFile(path, &results)
			runStaticAnalysis(path, &results)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error scanning directory: %v\n", err)
	}

	return results
}

// saveResultsToCSV saves results to a CSV file
func saveResultsToCSV(results []ScanResult, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating CSV file: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"File", "Line Number", "Description"})
	for _, result := range results {
		writer.Write([]string{result.File, fmt.Sprintf("%d", result.LineNumber), result.Description})
	}

	fmt.Printf("Results saved to %s\n", filename)
}

// saveResultsToJSON saves results to a JSON file
func saveResultsToJSON(results []ScanResult, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating JSON file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(results)
	if err != nil {
		fmt.Printf("Error encoding JSON: %v\n", err)
	}

	fmt.Printf("Results saved to %s\n", filename)
}

func main() {
	dir := flag.String("dir", "", "Directory to scan (Required)")
	csvOutput := flag.String("csv", "", "Output results to a CSV file (e.g., results.csv)")
	jsonOutput := flag.String("json", "", "Output results to a JSON file (e.g., results.json)")
	flag.Parse()

	if *dir == "" {
		fmt.Println("Usage: go run main.go -dir <directory> [--csv <file>] [--json <file>]")
		os.Exit(1)
	}

	fmt.Printf("Scanning directory: %s\n", *dir)
	results := scanDirectory(*dir)

	if *csvOutput != "" {
		saveResultsToCSV(results, *csvOutput)
	}
	if *jsonOutput != "" {
		saveResultsToJSON(results, *jsonOutput)
	}

	if len(results) == 0 {
		fmt.Println("No issues found! 🎉")
	}
}
