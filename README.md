# Apple VRE Take Home Assignment: sbscanner
This is a private repo dedicated to Apple's take home coding exercise for the Vulnerability Response Engineer position.

## Assignment 
Write a scanner in either Python, Go, or Bash which will test web servers basic auth for credentials of root:root.

## Requirements
The scanner is developed to the following requirements:

### Language - Python, Go, or Bash

The scanner is written in Python.

### Scaleability - You may need to run this on tens of thousands of hosts.
**Performance:** To help ensure high network I/O performance, the scanner makes HTTP requests using the [aiohttp framework](https://docs.aiohttp.org/en/stable/).

**Bulk targeting:** To enable the scanner to be run against tens of thousands of hosts, the scanner supports bulk targets input via file.

### Ports - The service may be running on an alternative port.
**Alternative port selection:** Scanning of alternative ports is supported by allowing the user to define each port to be scanned in conjunction with the URL provided. Alternatively, a list of ports can be supplied as command line argument using the `--list` flag and `--list-ports [ports]` option.

### Output - Is the output of the tool easy to decipher and could you easily use the input for other tools?
**Easy to decipher:** The scanner addresses this concern by providing cases of successful HTTP Basic Auth to STDOUT by default. Failures and errors are also easily presented through the use of the `--verbose` flag. Each result is captured in its own line, and therefore easily parsed by grep and other stream editors.

**Output interpoerability:** The scanner addresses output interoperability by allowing the user to export the output to STDOUT as either a JSON or XML, in addition to the default text report option.

### Accuracy - How can you confirm the result is a true positive?
**Authentication validation:** The scanner confirms accuracy by not only checking to see if the web server supports basic auth, but also authenticates with the webserver using the provided provided credentials (default: root:root) and confirms success 

## Instructions for use
```
Usage: sbscanner.py [OPTIONS]

  An HTTP Basic Authentication scanner written in Python.

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
  --list-urls TEXT          Comma separate list of URL values.
  --list-ports TEXT         Comma separate list of port values.
  --url-col TEXT            Name of the URL column in the CSV.
  --port-col TEXT           Name of the port column in the CSV.
  --username TEXT           Username for HTTP Basic Auth.
  --password TEXT           Password for HTTP Basic Auth.
  --verbose                 Enables verbose mode.
  --no-verify-ssl           Enables ssl verification when scanning.
  --output [text|json|xml]  Output format: text, json or xml
  --help                    Show this message and exit.
```

## Example usage

##### Scanning a list of URLs/Ports in a .csv.
```
~/sbscanner/ main ≡
$ python3 sbscanner.py --csv inputs/csv_input.csv  --url-col URL --port-col Port  --no-verify-ssl          
http://127.0.0.1:8080 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
http://localhost:8080 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
http://127.0.0.1:8081 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
https://127.0.0.1:8443 - SUCCESS -  HTTP Basic auth succeeded using username: 'root' and password: 'root'
```

##### Scanning a list of URLs/Ports in a .csv, with verbose output.
```
~/sbscanner/ main ≡
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


### Assumptions & Considerations
* While Nmap could be easily leveraged for the assignment and may allow for easily meeting the requirements, this is assumed to be out of ther spirit of the assignment, and therefore not considered.
* The scanner must support both HTTP and HTTPS.
* While credentials of the assignment are defined upfront (i.e. `root`:`root`), the scanner will allow these to be input as commandline arguments (`--username [username]`, `--password [password]`) to allow for additional flexibility.
* For ad-hoc use cases where inputs are assumed to be minimal (<= 10K URL/Ports), the script is sufficiently performant  
  * (`time` output on 10k URL/Ports: `1.14s user 0.27s system 73% cpu 1.925 total`).
* In larger scans that would likely run on a daily schedule, the script is also sufficiently performant, but could certainly be optimized
  * (`time` output on 258k URL/Ports: `43.21s user 15.13s system 3% cpu 24:28.23 total`).

## Limitations
* The scanner assumed TCP, and does not support the scanning of UDP ports.
* The scanner requires URL values, and thus, all scan targets must be prefixed with http(s)://.
* Testing has been limited to webservers running on localhost via docker. Additional testing with remote targets at scale.

## Dependencies
* aiosync
* click
* dicttoxml

## Tests
To run the tests associated with this scanner, run `python tests.py`

* Accepts list input
* Accepts csv input
* Accepts flat file input

## To do
* Comments
* Summary function
* Dockerfile
