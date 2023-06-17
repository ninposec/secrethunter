package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	apiKeyPattern   = regexp.MustCompile(`apiKey:\s*['"](.+?)['"]`)
	api_keyPattern  = regexp.MustCompile(`api_key:\s*['"](.+?)['"]`)
	api_Pattern     = regexp.MustCompile(`api:\s*['"](.+?)['"]`)
	token_Pattern   = regexp.MustCompile(`token:\s*['"](.+?)['"]`)
	apiKey2_Pattern = regexp.MustCompile(`API_KEY:\s*['"](.+?)['"]`)
	secret_Pattern  = regexp.MustCompile(`SECRET:\s*['"](.+?)['"]`)
	access_Pattern  = regexp.MustCompile(`access_token:\s*['"](.+?)['"]`)
)

func main() {
	log.SetFlags(0) // Disable default timestamp

	flag.Usage = func() {
		fmt.Println(`
		
███████╗███████╗ ██████╗██████╗ ███████╗████████╗   
██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝   
███████╗█████╗  ██║     ██████╔╝█████╗     ██║      
╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║      
███████║███████╗╚██████╗██║  ██║███████╗   ██║      
╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝      
													
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
																																								 
			
		`)
		fmt.Printf("Secrethunter v.0.1\n")
		fmt.Printf("Author: ninposec\n")
		fmt.Println("")
		fmt.Println("Scans URLs or files for exposed API keys and secrets.")
		fmt.Println("Provide URLs as a list in a file or through stdin.")
		fmt.Println("")
		flag.PrintDefaults()
	}

	helpPtr := flag.Bool("h", false, "show help message")
	filenamePtr := flag.String("urls", "", "Filename containing the list of URLs")
	fileDirPtr := flag.String("dir", "", "the directory path containing files to scan")
	concurrencyPtr := flag.Int("c", 10, "number of concurrent goroutines")

	flag.Parse()

	if *helpPtr {
		flag.Usage()
		os.Exit(0)
	}

	if *fileDirPtr != "" {
		err := filepath.Walk(*fileDirPtr, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Printf("Error accessing a path %q: %v\n", path, err)
				return err
			}

			if !info.IsDir() {
				scanFile(path)
			}
			return nil
		})
		if err != nil {
			log.Fatalf("Error walking the path %v: %v", *fileDirPtr, err)
		}
		return
	}

	var urls []string
	if *filenamePtr == "" {
		urls = readUrlsFromStdin()
	} else {
		var err error
		urls, err = extractUrls(*filenamePtr)
		if err != nil {
			log.Fatalf("Error reading URLs from file %s: %v", *filenamePtr, err)
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	red := color.New(color.FgRed).SprintFunc()

	var wg sync.WaitGroup
	results := make(chan string)
	concurrency := *concurrencyPtr
	semaphore := make(chan struct{}, concurrency)

	wg.Add(len(urls))

	go func() {
		wg.Wait()
		close(results)
	}()

	for _, url := range urls {
		semaphore <- struct{}{}
		go func(url string) {
			defer func() { <-semaphore }()
			defer wg.Done()

			req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
			if err != nil {
				results <- fmt.Sprintf("Error creating request for %s: %v", url, err)
				return
			}

			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
			req.Header.Set("Connection", "close")

			resp, err := client.Do(req)
			if err != nil {
				results <- fmt.Sprintf("Error making request to %s: %v", url, err)
				return
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return
			}

			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				results <- fmt.Sprintf("Error reading response body from %s: %v", url, err)
				return
			}

			var matches []string
			if apiKey := extractPattern(apiKeyPattern, body); apiKey != "" {
				matches = append(matches, fmt.Sprintf("apiKey=%s", apiKey))
			}

			if api_key := extractPattern(api_keyPattern, body); api_key != "" {
				matches = append(matches, fmt.Sprintf("api_key=%s", api_key))
			}

			if api := extractPattern(api_Pattern, body); api != "" {
				matches = append(matches, fmt.Sprintf("api=%s", api))
			}

			if token := extractPattern(token_Pattern, body); token != "" {
				matches = append(matches, fmt.Sprintf("token=%s", token))
			}

			if API_KEY := extractPattern(apiKey2_Pattern, body); API_KEY != "" {
				matches = append(matches, fmt.Sprintf("API_KEY=%s", API_KEY))
			}

			if SECRET := extractPattern(secret_Pattern, body); SECRET != "" {
				matches = append(matches, fmt.Sprintf("SECRET=%s", SECRET))
			}

			if access_token := extractPattern(access_Pattern, body); access_token != "" {
				matches = append(matches, fmt.Sprintf("access_token=%s", access_token))
			}

			if len(matches) > 0 {
				results <- fmt.Sprintf("%s: %s", url, red(strings.Join(matches, ", ")))
			}
		}(url)
	}

	for result := range results {
		log.Println(result)
	}
}

func extractUrls(filename string) ([]string, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", filename, err)
	}

	urls := []string{}
	for _, line := range strings.Split(string(content), "\n") {
		url := strings.TrimSpace(line)
		if url != "" {
			urls = append(urls, url)
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs found in file %s", filename)
	}

	return urls, nil
}

func extractPattern(pattern *regexp.Regexp, body []byte) string {
	match := pattern.FindSubmatch(body)
	if len(match) > 1 {
		return string(match[1])
	}
	return ""
}

func readUrlsFromStdin() []string {
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading URLs from stdin: %v", err)
	}
	if len(urls) == 0 {
		log.Fatalf("No URLs found in stdin")
	}
	return urls
}

func scanFile(filename string) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("Error reading file %s: %v", filename, err)
		return
	}

	body := content
	red := color.New(color.FgRed).SprintFunc()

	var matches []string

	if apiKey := extractPattern(apiKeyPattern, body); apiKey != "" {
		matches = append(matches, fmt.Sprintf("apiKey=%s", apiKey))
	}

	if api_key := extractPattern(api_keyPattern, body); api_key != "" {
		matches = append(matches, fmt.Sprintf("api_key=%s", api_key))
	}

	if api := extractPattern(api_Pattern, body); api != "" {
		matches = append(matches, fmt.Sprintf("api=%s", api))
	}

	if token := extractPattern(token_Pattern, body); token != "" {
		matches = append(matches, fmt.Sprintf("token=%s", token))
	}

	if API_KEY := extractPattern(apiKey2_Pattern, body); API_KEY != "" {
		matches = append(matches, fmt.Sprintf("API_KEY=%s", API_KEY))
	}

	if SECRET := extractPattern(secret_Pattern, body); SECRET != "" {
		matches = append(matches, fmt.Sprintf("SECRET=%s", SECRET))
	}

	if access_token := extractPattern(access_Pattern, body); access_token != "" {
		matches = append(matches, fmt.Sprintf("access_token=%s", access_token))
	}

	if len(matches) > 0 {
		log.Printf("%s: %s", filename, red(strings.Join(matches, ", ")))
	}
}
