# Secrethunter

Hunt for secrets inside JS and HTML responses.

Scans urls or files for exposed api keys and secrets.


### Installation

```bash
go install github.com/ninposec/secrethunter@latest
```

This will download and install the tool in your system's $GOPATH/bin directory.



### Usage

Secrethunter reads URLs from STDIN or from urls input flag, looks in the reponse for patterns and matches API keys and Secrets.


```bash
secrethunter -h

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
																			
			
		
Secrethunter v.0.1
Author: ninposec

Scans URLs or files for exposed API keys and secrets.
Provide URLs as a list in a file or through stdin.

  -c int
    	number of concurrent goroutines (default 10)
  -dir string
    	the directory path containing files to scan
  -h	show help message
  -urls string
    	Filename containing the list of URLs
```


### Examples

Look for secrets inside HTTP Responses.

```bash
cat urls.txt | secrethunter
```

Look for secrets inside directory of files.

```bash
secrethunter -dir jsfiles/
```

### ToDo

* Add more key checks
* Optimize regex filters
* Better handling of large files