package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
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

	// Custom usage message
	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", "secrethunter")
		fmt.Println("secrethunter scans URLs for exposed API keys and secrets.")
		fmt.Println("Provide URLs as a list in a text file or through stdin.")
		fmt.Println("Example:")
		fmt.Println("\tsecrethunter --file urls.txt")
		flag.PrintDefaults()
	}

	helpPtr := flag.Bool("h", false, "show help message")
	filenamePtr := flag.String("file", "", "the filename containing the list of URLs")
	flag.Parse()

	if *helpPtr {
		flag.Usage()
		os.Exit(0)
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

	for _, url := range urls {
		req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
		if err != nil {
			log.Printf("Error creating request for %s: %v", url, err)
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
		req.Header.Set("Connection", "close")

		resp, err := client.Do(req)
		if err != nil {
			//log.Printf("Error making request to %s: %v", url, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			//log.Printf("Error reading response body from %s: %v", url, err)
			continue
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
			log.Printf("%s: %s", url, red(strings.Join(matches, ", ")))
		}
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
