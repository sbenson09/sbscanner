# Apple VRE Take Home Assignment: sbscanner
This is a private repo dedicated to Apple's take home coding exercise for the Vulnerability Response Engineer position.

## Assignment 
Write a scanner in either Python, Go, or Bash which will test web servers basic auth for credentials of root:root.

## Requirements
The scanner is developed to the following requirements:

### Language - Python, Go, or Bash

The scanner is written in Python.

### Scaleability - You may need to run this on tens of thousands of hosts.
**Performance:** To ensure high performance, the scanner makes HTTP requests using the [aiohttp framework](https://docs.aiohttp.org/en/stable/).

**Bulk targeting:** To ensure the scanner can be ran against tens of thousands of hosts, the scanner supports declaring bulk targets via a file.

### Ports - The service may be running on an alternative port.
**Alternative port selection:** The scanner addresses the concern of alternative ports by allowing the port to be specified, either together, as a piece of data paired with a host entry, or separately, as list provided by the user.

### Output - Is the output of the tool easy to decipher and could you easily use the input for other tools?
**Easy to decipher:** The scanner addresses this concern by providing relevant results to STDOUT by default. The output is easily parsed by grep and other stream editors.

**Output interpoerability:** The scanner addresses output interoperability by allowing the user to export the output as either a JSON or XML, in addition to the default STDOUT report option.

### Accuracy - How can you confirm the result is a true positive?
**Authentication validation:** The scanner confirms accuracy by not only checking to see if the web server supports basic auth, but also authenticates with the webserver using the provided provided credentials (default: root:root) and confirms success 

## Instructions for use

### Assumptions & Considerations
* While Nmap could be easily leveraged for the assignment and may allow for easily meeting the requirements, writing a wrapper that provides nmap with input would likely not be within the spirit of the exercise and thus a scanning engine should be built from scratch.
* The scanner should support both HTTP and HTTPS.
* While certain requirements of the assignment are hardcoded (e.g. use of root:root), where possible, the scanner will expect these to be input into the scanner as an argument to allow for future flexibility.

## Dependencies
* aiohttp
* aiosync
* click

## Limitations
* The scanner does not support the scanning of UDP ports.
* The scanner requires URL values, and thus, all scan targets must be prefixed with http(s)://.

## Tests
To run the tests associated with this scanner, run `python tests.py`

* Accepts list input
* Accepts csv input
* Accepts flat file input


## To do
* Comments
* Summary function
* Dockerfile
