# Apple VRE Take Home Assignment: sbscanner
This is a private repo dedicated to Apple's take home coding exercise for the Vulnerability Response Engineer position.

## Assignment 
Write a scanner in either Python, Go, or Bash which will test web servers basic auth for credentials of root:root.

## Requirements
**sbscanner** is developed to the following requirements:

### Language - Python, Go, or Bash

The scanner is written in Python.

### Scaleability - You may need to run this on tens of thousands of hosts.
**Performance:** To help ensure high network I/O performance, the scanner makes asynchronous HTTP requests using the [aiohttp framework](https://docs.aiohttp.org/en/stable/).

**Bulk targeting:** To enable the scanner to be run against tens of thousands of hosts, the scanner supports bulk targets input via file.

### Ports - The service may be running on an alternative port.
**Alternative port selection:** Users are able to define URL:Port pairs in .csv and .txt files. Alternatively, users may provide a list of ports to scan as a command line argument via the `--list` flag and `--list-ports [ports]` option.

### Output - Is the output of the tool easy to decipher and could you easily use the input for other tools?
**Easy to decipher:** The scanner clearly reports cases of successful HTTP Basic Auth to STDOUT by default. Failures and errors are also easily presented through the use of the `--verbose` flag. Each result is captured in its own line, and therefore easily parsed by grep and other stream editors.

**Output interpoerability:** The scanner's output achieves interoperability by allowing the user to export the output to STDOUT as either a JSON or XML, in addition to the default text report option.

### Accuracy - How can you confirm the result is a true positive?
**Authentication validation:** The scanner confirms accuracy by not only checking to see if the web server supports basic auth, but also authenticates with the webserver using the provided provided credentials (default: root:root) and confirms success. Logic to handle edge cases (e.g. HTTP Authentication required, but Basic not supported) is also used to ensure accuracy.

## Installation
```
git clone https://github.com/sbenson09/sbscanner.git
cd sbscanner
pip3 install -r requirements.txt
```

## Instructions for use
```
Usage: sbscanner.py [OPTIONS]

  An HTTP Basic Authentication scanner written in Python by Sean Benson.

  Features:

  * Supports multiple forms of input (csv file, txt file, list of args).

  * Supports multiple forms of output via STDOUT (Text report, XML, CSV).

  * Performant through the use of Python's aiohttp framework.

Options:
  --csv PATH                Path to a CSV file, containing a list of urls &
                            ports.
  --text PATH               Path to a text file, containing url:port notated
                            targets.
  --list                    Flag to indicate that input is supplied via CLI
                            arguments.
  --list-urls TEXT          Comma separated list of URL values.
  --list-ports TEXT         Comma separated list of port values.
  --url-col TEXT            Name of the URL column in the CSV.
  --port-col TEXT           Name of the port column in the CSV.
  --username TEXT           Username for HTTP Basic Auth.
  --password TEXT           Password for HTTP Basic Auth.
  --verbose                 Enables verbose mode for text output.
  --no-verify-ssl           Disables ssl verification when scanning.
  --output [text|json|xml]  Output format: text, json or xml
  --help                    Show this message and exit.
```

## Example usage

### Scanning URLs/Ports defined in a .csv.
```
~/sbscanner/ main ⇣ ≡
$ python3 sbscanner.py --csv inputs/csv_input.csv  --url-col URL --port-col Port  --no-verify-ssl          
http://127.0.0.1:8080 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
http://localhost:8080 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
http://127.0.0.1:8081 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
https://127.0.0.1:8443 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
```

### Scanning URLs/Ports defined in a .csv, with verbose output.
```
~/sbscanner/ main ⇣ ≡
$ python3 sbscanner.py --csv inputs/csv_input.csv  --url-col URL --port-col Port  --no-verify-ssl --verbose     
Using csv input.
http://127.0.0.1:8080 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
http://localhost:8080 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
http://127.0.0.1:8081 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
http://127.0.0.1:8082 - FAILED - HTTP Basic auth failed with the username: 'root' and password: 'root'
http://127.0.0.1:8083 - FAILED - HTTP Basic auth failed with the username: 'root' and password: 'root'
http://127.0.0.1:8084 - FAILED - HTTP Basic auth not required
http://127.0.0.1:8085 - FAILED - HTTP Basic auth not required
http://127.0.0.1:8086 - FAILED - Connection failed: Cannot connect to host 127.0.0.1:8086 ssl:False [Connect call failed ('127.0.0.1', 8086)]
http://127.0.0.1:8087 - FAILED - Connection failed: Cannot connect to host 127.0.0.1:8087 ssl:False [Connect call failed ('127.0.0.1', 8087)]
https://127.0.0.1:8443 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
https://127.0.0.1:8444 - FAILED - Connection failed: Cannot connect to host 127.0.0.1:8444 ssl:False [Connect call failed ('127.0.0.1', 8444)]
```

### Scanning URLs/Ports defined in a .txt.
```
~/sbscanner/ main ⇣ ≡
$ python3 sbscanner.py --text inputs/text_input.txt --no-verify-ssl
http://127.0.0.1:8080 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
http://127.0.0.1:8081 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
https://127.0.0.1:8443 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
```

### Scanning a list of URLs/Ports provided as commandline arguments.
```
~/sbscanner main ⇣ ≡
$ python3 sbscanner.py --list --list-ports 80,8080,8081,8443 --list-urls http://127.0.0.1,https://localhost --no-verify-ssl
http://127.0.0.1:8080 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
http://127.0.0.1:8081 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
https://localhost:8443 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
```

### Scanning a list of URL/Ports provided as commandline arguments, and using grep to filter results to auth failure due to invalid credentials.
```
~/sbscanner main ⇣ ≡
$ python3 sbscanner.py --list --list-ports 8083,8084,8085,8086,80,8080,8081,8443 --list-urls http://127.0.0.1,https://localhost --no-verify-ssl --verbose | grep "Basic auth failed"
http://127.0.0.1:8083 - FAILED - HTTP Basic auth failed with the username: 'root' and password: 'root'
```

## Docker

A Dockerfile to build the scanner has also been included for use. Build the docker image, and then run with the following:
```
docker run [image name] [options]
```

### Docker example usage
```
# In the directory of the cloned repo
~/sbscanner main ⇣ ≡
$ docker build . -t sbscanner

~/sbscanner main ⇣ ≡
$ docker run sbscanner --text inputs/text_input_remote.txt --verbose --no-verify-ssl             
https://www.google.com:443 - FAILED - HTTP Basic auth not required.
https://www.youtube.com:443 - FAILED - HTTP Basic auth not required.
https://www.facebook.com:443 - FAILED - HTTP Basic auth not required.
https://www.amazon.com:443 - FAILED - HTTP Basic auth not required.
https://www.wikipedia.org:443 - FAILED - HTTP Basic auth not required.
https://www.twitter.com:443 - FAILED - HTTP Basic auth not required.
https://www.instagram.com:443 - FAILED - HTTP Basic auth not required.
https://www.linkedin.com:443 - FAILED - HTTP Basic auth not required.
https://www.netflix.com:443 - FAILED - HTTP Basic auth not required.
https://www.reddit.com:443 - FAILED - HTTP Basic auth not required.
```

## Sample input data
Sample input and testing data has been provided and available for use in the [/inputs](https://github.com/sbenson09/sbscanner/tree/main/inputs) folder.

## Test server environment via docker compose.
To test across several cases (http, https, nginx server, httpd server, successful basic auth, failed basic auth invalid credentials, etc.) a series of Dockerfiles, orchestrated by a docker-compose manifest were included in the [/test_servers](https://github.com/sbenson09/sbscanner/tree/main/test_servers) folder.

Refer to Docker's [docker compose documentation](https://docs.docker.com/compose/) for instructions on installation and use.

## Assumptions & Considerations
* Building on top of existing tools like Nmap were assumed out of the spirit of the assignment, and thus not considered.
* The scanner must support both HTTP and HTTPS.
* While credentials of the assignment are defined upfront (i.e. `root`:`root`), the scanner will allow these to be input as commandline arguments (`--username [username]`, `--password [password]`) to allow for additional flexibility.
* For ad-hoc use cases where inputs are assumed to be minimal (<= 10K URL/Ports), the script is sufficiently performant  
  * (`time` output on 10k URL/Ports: `1.14s user 0.27s system 73% cpu 1.925 total`).
* In larger scans that would likely run on a daily schedule, the script is simulated to be sufficiently performant, but certainly could be optimized. Note that the simulation was performed against localhost.
  * (`time` output on 258k URL/Ports: `43.21s user 15.13s system 3% cpu 24:28.23 total`).
* CSV file input assumes the use of a header row.

## Limitations
* The scanner assumes TCP, and does not support the scanning of UDP ports.
* The scanner requires URL values, and thus, all scan targets must be prefixed with http(s)://.
* Testing against tens of thousands of remote hosts believed to be unfeasible, and thus, testing bulk targets has been simulated via webservers running on localhost via docker(258K targets). Additional testing with remote targets at scale would be highly desirable.
* Requests that are silently dropped by either the server or WAFs may result in significant slowdowns, as the request must timeout. Default timeout is set to 2 seconds.
* The scanner has no options to control concurrency or rate limiting.

## Dependencies
sbscanner was developed using Python 3.11, and contains the following depencies.
* `aiohttp` for asynchronous http requests
* `click` for handling command line arguments
* `dicttoxml` for converting Python dictionaries to XML.


