# sbscanner
sbscanner was a small project I worked on as a part of a take-home interview assignment in early 2024. The primary objective for the assignment was to build a port scanner that could identify and gather information on services that supported HTTP Basic Authentication. It doesn't do anything novel.

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
  Identifies HTTP servers that support HTTP Basic Authentication with a given
  set of credentials.

  Features:

  * Supports multiple forms of input (CSV file, text file, list of args).

  * Supports multiple forms of output via STDOUT (Text report, XML, JSON,
  CSV).

  * Performant through the use of Python's asyncio & aiohttp frameworks.

  * Customizable behavior defined through command line arguments.

Options:
  --csv PATH                    Path to a CSV file, containing a list of urls
                                & ports.
  --text PATH                   Path to a text file, containing url:port
                                notated targets.
  --list                        Flag to indicate that input is supplied via
                                CLI arguments.
  --list-urls TEXT              Comma separated list of URL values.
  --list-ports TEXT             Comma separated list of port values.
  --url-col TEXT                Name of the URL column in the CSV.
  --port-col TEXT               Name of the port column in the CSV.
  --username TEXT               Username for HTTP Basic Auth. Default of
                                'root'
  --password TEXT               Password for HTTP Basic Auth. Default of
                                'root'
  --concurrency INTEGER RANGE   Number of concurrent scan jobs to run at a
                                time. Default of '100'  [x>=1]
  --timeout INTEGER RANGE       Request timeout in seconds. Default of '2'
                                [x>=0]
  --verbose                     Enables verbose mode for text output.
  --no-verify-ssl               Disables ssl verification when scanning.
  --output [text|json|xml|csv]  Output format: text, json, csv, or xml.
                                Default of text'
  --help                        Show this message and exit.
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

### Scanning a list of URLs/Ports provided as command line arguments.
```
~/sbscanner main ⇣ ≡
$ python3 sbscanner.py --list --list-ports 80,8080,8081,8443 --list-urls http://127.0.0.1,https://localhost --no-verify-ssl
http://127.0.0.1:8080 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
http://127.0.0.1:8081 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
https://localhost:8443 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
```

### Scanning a list of URL/Ports provided as command line arguments, and using grep to filter results to auth failure due to invalid credentials.
```
~/sbscanner main ⇣ ≡
$ python3 sbscanner.py --list --list-ports 8083,8084,8085,8086,80,8080,8081,8443 --list-urls http://127.0.0.1,https://localhost --no-verify-ssl --verbose | grep "Basic auth failed"
http://127.0.0.1:8083 - FAILED - HTTP Basic auth failed with the username: 'root' and password: 'root'
```

### Scanning a list of URL/Ports provided as command line arguments and outputting as JSON.
```
~/sbscanner main ⇣ ≡
$ python3 sbscanner.py --list --list-urls http://127.0.0.1,https://127.0.0.1 --list-ports 8080 --no-verify-ssl --verbose --output json               
{
    "http://127.0.0.1:8080": {
        "url": "http://127.0.0.1",
        "port": "8080",
        "connected": true,
        "basic_auth_required": true,
        "authentication_success": true
    },
    "https://127.0.0.1:8080": {
        "url": "https://127.0.0.1",
        "port": "8080",
        "connected": false,
        "basic_auth_required": false,
        "authentication_success": false,
        "error": "Cannot connect to host 127.0.0.1:8080 ssl:False [[SSL] record layer failure (_ssl.c:1006)]"
    }
}
```

### Scanning a list of URL/Ports provided as command line arguments and outputting as XML.
```
~/sbscanner main ⇣ ≡
$ python3 sbscanner.py --list --list-urls http://127.0.0.1,https://127.0.0.1 --list-ports 8080 --no-verify-ssl --verbose --output xml
<?xml version="1.0" ?>
<scan_results>
    <key name="http://127.0.0.1:8080">
        <url>http://127.0.0.1</url>
        <port>8080</port>
        <connected>true</connected>
        <basic_auth_required>true</basic_auth_required>
        <authentication_success>true</authentication_success>
    </key>
    <key name="https://127.0.0.1:8080">
        <url>https://127.0.0.1</url>
        <port>8080</port>
        <connected>false</connected>
        <basic_auth_required>false</basic_auth_required>
        <authentication_success>false</authentication_success>
        <error>Cannot connect to host 127.0.0.1:8080 ssl:False [[SSL] record layer failure (_ssl.c:1006)]</error>
    </key>
</scan_results>
```

### Scanning a list of URL/Ports provided as command line arguments and outputting as CSV.
```
~/sbscanner main ⇣ ≡
$ python3 sbscanner.py --list --list-urls http://127.0.0.1,https://127.0.0.1 --list-ports 8080 --no-verify-ssl --verbose --output csv
target,connected,basic_auth_required,authentication_success,error
http://127.0.0.1:8080,True,True,True,
https://127.0.0.1:8080,False,False,False,Cannot connect to host 127.0.0.1:8080 ssl:False [[SSL] record layer failure (_ssl.c:1006)]
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

Any input files must be within the scanner's directory when the image is built, otherwise they will not be included in the image.

## Sample input data
Sample input and testing data has been provided and available for use in the [/inputs](https://github.com/sbenson09/sbscanner/tree/main/inputs) folder.

## Test server environment via docker compose.
To test across several cases (http, https, nginx server, httpd server, successful basic auth, failed basic auth due to invalid credentials, etc.) a series of Dockerfiles, orchestrated by a docker-compose manifest were included in the [/test_servers](https://github.com/sbenson09/sbscanner/tree/main/test_servers) folder.

Refer to Docker's [docker compose documentation](https://docs.docker.com/compose/) for instructions on installation and use.

## Assumptions & Considerations
* Building on top of existing tools like Nmap were assumed out of the spirit of the assignment, and thus not considered.
* The scanner must support both HTTP and HTTPS.
*  The scanner must be performant in both minimal use cases (<= 10K URL/Ports) and large use cases (>=250K URL/Ports). To validate this, I measured runtime with `time` on my M2 Macbook Air.
  * `time` output on 10k URL/Ports: `0.91s user 0.19s system 96% cpu 1.139 total`.
  * `time` output on 258k URL/Ports: ` 47.44s user 15.35s system 105% cpu 59.473 total`.
* CSV file input assumes the use of a header row.
* While credentials of the assignment are defined upfront (i.e. `root`:`root`), the scanner should allow these to be input as command line arguments (`--username [username]`, `--password [password]`) to allow for additional flexibility.

## Limitations
* The scanner is designed for TCP and does not support scanning of UDP ports.
* The scanner requires URL values for input, and thus, all scan targets must be prefixed with http(s)://.
* Testing against tens of thousands of remote hosts was considered impractical, and thus, testing bulk targets has been simulated via web servers running on localhost via docker(258K targets). Additional testing with remote targets at scale would be highly desirable to better understand performance and potential bottlenecks.
* Requests that are silently dropped by a server or WAF may result in significant slowdowns, as the request must timeout. Default timeout is set to 2 seconds, and can be configured by the user.
* CSV file input assumes the use of a header row.

## Dependencies
sbscanner was developed using Python 3.11, and contains the following dependencies.
* `aiohttp` for asynchronous HTTP requests
* `click` for handling command line arguments
* `dicttoxml` for converting Python dictionaries to XML


