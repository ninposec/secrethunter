package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var (
	apiKeyPattern  = regexp.MustCompile(`apiKey:\s*"(.+?)"`)
	secretPattern  = regexp.MustCompile(`secret:\s*"(.+?)"`)
	api_keyPattern = regexp.MustCompile(`api_key:\s*"(.+?)"`)
)

func main() {
	filenamePtr := flag.String("file", "", "the filename containing the list of URLs")
	flag.Parse()

	if *filenamePtr == "" {
		fmt.Println("Error: Please provide a filename using the -file flag")
		os.Exit(1)
	}

	urls, err := extractUrls(*filenamePtr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	for _, url := range urls {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Printf("Error creating request for %s: %s\n", url, err)
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
		req.Header.Set("Connection", "close")

		resp, err := client.Do(req)
		if err != nil {
			// Suppress HTTP and connection error messages
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("Error reading response body from %s: %s\n", url, err)
			continue
		}

		var matches []string
		if apiKey := extractPattern(apiKeyPattern, body); apiKey != "" {
			matches = append(matches, fmt.Sprintf("apiKey=%s", apiKey))
		}

		if secret := extractPattern(secretPattern, body); secret != "" {
			matches = append(matches, fmt.Sprintf("secret=%s", secret))
		}

		if api_key := extractPattern(api_keyPattern, body); api_key != "" {
			matches = append(matches, fmt.Sprintf("api_key=%s", api_key))
		}

		if len(matches) > 0 {
			fmt.Printf("%s: %s\n", url, strings.Join(matches, ", "))
		}
	}
}

func extractUrls(filename string) ([]string, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %s", filename, err)
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
