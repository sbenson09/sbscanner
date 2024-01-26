#!/usr/bin/env python3
import click
import csv
import aiohttp
import asyncio
import json
import dicttoxml
from xml.dom.minidom import parseString
from base64 import b64encode

@click.command(context_settings=dict(
    # To change Click's argument handling behavior:
    #ignore_unknown_options=True,
    #allow_extra_args=True,
))
@click.option('--csv', 'csv_filepath', type=click.Path(exists=True), help='Path to a CSV file, containing a list of urls & ports.')
@click.option('--text', 'text_filepath', type=click.Path(exists=True), help='Path to a text file, containing url:port notated targets.')
@click.option('--list', 'list_flag', required=False, is_flag=True, help='Flag to indicate that input is supplied via CLI arguments.')
@click.option('--list-urls', 'list_urls', required=False, help='Comma separated list of URL values.')
@click.option('--list-ports', 'list_ports', required=False, help='Comma separated list of port values.')
@click.option('--url-col', required=False, help='Name of the URL column in the CSV.')
@click.option('--port-col', required=False, help='Name of the port column in the CSV.')
@click.option('--username', 'username', default='root', help='Username for HTTP Basic Auth. Default of \'root\'')
@click.option('--password', 'password', default='root', help='Password for HTTP Basic Auth. Default of \'root\'')
@click.option('--concurrency', 'concurrency', default=100, type=click.IntRange(min=1), help='Number of concurrent scan jobs to run at a time. Default of \'100\'')
@click.option('--timeout', 'timeout', default=2, type=click.IntRange(min=0), help='Request timeout in seconds. Default of \'2\'')
@click.option('--verbose', is_flag=True, required=False, help='Enables verbose mode for text output.')
@click.option('--no-verify-ssl', is_flag=True, required=False, help='Disables ssl verification when scanning.')
@click.option('--output', type=click.Choice(['text', 'json', 'xml', 'csv'], case_sensitive=False), default='text', help='Output format: text, json, csv, or xml. Default of text\'')
@click.pass_context
def scan_workflow(ctx, csv_filepath, text_filepath, list_flag, list_urls, list_ports, url_col, port_col, username, password, concurrency, timeout, verbose, no_verify_ssl, output):
    """An HTTP Basic Authentication scanner written in Python by Sean Benson. 
    Identifies HTTP servers that support HTTP Basic Authentication with a
    given set of credentials.

    Features:\n
    * Supports multiple forms of input (CSV file, text file, list of args).\n
    * Supports multiple forms of output via STDOUT (Text report, XML, JSON).\n
    * Performant through the use of Python's asyncio & aiohttp framework.\n
    * Customizable behavior defined through command line arguments."""
    

    # Take input provided by user, and process into a dictionary of targets to use for scanning
    targets = process_input(ctx, csv_filepath, text_filepath, list_flag, list_urls, list_ports, url_col, port_col, verbose)
    
    # Scan each provided target, asynchronously
    scan_result = asyncio.run(scan_targets(targets, verbose, username, password, concurrency, timeout, not no_verify_ssl))
    
    # Create report in the user-supplied format
    if output == 'json':
        click.echo(json.dumps(scan_result, indent=4))
    elif output == 'xml':
        # Convert dictionary to unformatted XML, then pretty print
        unformatted_xml = dicttoxml.dicttoxml(scan_result, custom_root='scan_results', attr_type=False)
        dom = parseString(unformatted_xml)
        pretty_xml = dom.toprettyxml(indent="    ") 
        click.echo(pretty_xml)
    elif output == 'csv':
        generate_csv_report(scan_result, verbose)
    elif output == 'text':  # Default option
        generate_text_report(scan_result, username, password, verbose)

def process_input(ctx, csv_filepath, text_filepath, list_flag, list_urls, list_ports, url_col, port_col, verbose):
    """
    Takes input provided by user, performs some input validation, and  calls appropriate
    function to process input data and returns a dictionary with processed scanning targets.
    """
    target_dict = {}

    # For handling csv input
    if csv_filepath and not any([text_filepath, list_flag]):
        if not url_col or not port_col:
            raise click.UsageError('When using --csv option, you must also provide --url-col and --port-col options.')
        target_dict = process_csv(csv_filepath, url_col, port_col, verbose)
             
    # For handling text input
    elif text_filepath and not any([csv_filepath, list_flag]):
        target_dict = process_text_file(text_filepath, verbose)

    # For handling list inputs. Loop through lists, perform validation,
    # and then return a target dictionary.
    elif list_flag and not any([text_filepath, csv_filepath]):
        if not list_urls or not list_ports:
            raise click.UsageError('--list-urls and --list-ports options are required when using --list.')
        url_list = list_urls.split(',')
        port_list = list_ports.split(',')
        if not all(url_list) or not all(port_list):
            raise click.UsageError('List arguments must contain valid URL and port entries separated by commas.')
        target_dict = process_list(list_urls, list_ports)

    else:
        # In the event a user has not provided a single input option
        raise click.UsageError('You must provide an input using only one of: --csv, --text, or --list options.')

    return target_dict
    
async def scan_targets(targets, verbose, username, password, concurrency, timeout, verify_ssl=True):
    # Prepare authentication header to use for HTTP Basic Authorization
    # Reference: https://stackoverflow.com/questions/53622829/python-encode-base64-to-basic-connect-to-an-api
    creds = f'{username}:{password}'.encode('utf-8')  
    auth_header = 'Basic ' + b64encode(creds).decode('utf-8')

    # None for SSL verification, False for no verification
    ssl_context = None if verify_ssl else False

    #Control client timeout & concurrency options
    timeout_duration = aiohttp.ClientTimeout(total=timeout)
    semaphore = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(timeout=timeout_duration) as session:
        # Create a list of coroutines for scanning each target
        tasks = [scan_target(session, semaphore, target, details, auth_header, ssl_context) for target, details in targets.items()]
        # Gather the results from all the coroutines
        results = await asyncio.gather(*tasks)
        
        # Update the targets dictionary with the results
        for result in results:
            target_key = result.pop('target_key')
            targets[target_key].update(result)

    return targets

async def scan_target(session, semaphore, target_key, details, auth_header, ssl_context):
    async with semaphore:
        connected = False
        try:
            # Attempt the initial request
            async with session.get(target_key, ssl=ssl_context) as initial_response:
                connected = True
                # Check for HTTP authentication requirements
                if initial_response.status == 401 and 'WWW-Authenticate' in initial_response.headers:
                    supports_basic_auth = 'Basic' in initial_response.headers.get('WWW-Authenticate', '')
                    if supports_basic_auth:
                        # Attempt authentication
                        async with session.get(target_key, headers={'Authorization': auth_header}, ssl=ssl_context) as auth_response:
                            auth_success = 200 <= auth_response.status < 300
                            return {
                                'target_key': target_key,
                                'connected': connected,
                                'basic_auth_required': supports_basic_auth,
                                'authentication_success': auth_success,
                            }
                    else:
                        return {  
                            'target_key': target_key,
                            'connected': connected,
                            'basic_auth_required': False,
                            'authentication_success': False,
                            'error': 'HTTP Authentication required, but Basic Auth is not supported.'
                        }
                else:
                    return {  # HTTP Basic Auth not required
                        'target_key': target_key,
                        'connected': connected,
                        'basic_auth_required': False,
                    }
        except aiohttp.ClientError as e:
            return {  # Client error
                'target_key': target_key,
                'connected': connected,
                'basic_auth_required': False,  #Assume false
                'authentication_success': False,
                'error': str(e),
            }
        except Exception as e:
            return {  #Generic exception
                'target_key': target_key,
                'connected': connected,
                'basic_auth_required': False,  #Assume false
                'authentication_success': False,
                'error': 'An unexpected error occurred.'
            }

def generate_text_report(targets, username, password, verbose):
    """
    Handles text report output. Takes a dictionary of scan results and config options. Outputs to STDOUT.
    """
    for target, details in targets.items():
        if details.get('connected'):
            if details.get('basic_auth_required') and details.get('authentication_success'):
                click.echo(f"{target} - SUCCESS -  HTTP Basic auth succeeded with username: '{username}' and password: '{password}'") 
            # Handle the verbose output for various cases
            elif verbose:
                if details.get('basic_auth_required') is False and 'error' in details and 'HTTP Authentication required' in details.get('error'):
                    click.echo(f"{target} - FAILED - HTTP Auth required, but Basic not supported")
                elif details.get('basic_auth_required'): 
                    click.echo(f"{target} - FAILED - HTTP Basic auth failed with username: '{username}' and password: '{password}'")
                else:
                    click.echo(f"{target} - FAILED - HTTP Basic auth not required.")
        elif verbose and 'error' in details:
            click.echo(f"{target} - FAILED - Connection failed: {details['error']}")

def generate_csv_report(scan_results, verbose):
    """
    Takes a dictionary of scan results, outputs a report in CSV format.
    """
    fieldnames = ['target', 'connected', 'basic_auth_required', 'authentication_success', 'error']
    writer = csv.DictWriter(click.get_text_stream('stdout'), fieldnames=fieldnames)
    writer.writeheader()
    for target_key, details in scan_results.items():
        row = {
            'target': target_key,
            'connected': details.get('connected', 'False'),
            'basic_auth_required': details.get('basic_auth_required', 'False'),
            'authentication_success': details.get('authentication_success', 'False'),
            'error': details.get('error', '')
        }
        writer.writerow(row)


def process_csv(filepath, url_column, port_column, verbose):
    """
    Takes a csv filepath and header names, validates and processes the input,
    and returns a dictionary of targets to scan. Validates that the CSV file
    contains the necessary columns before processing the contents.
    """
    targets = {}
    with open(filepath, newline='') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        if url_column not in csv_reader.fieldnames or port_column not in csv_reader.fieldnames:
            raise click.UsageError(f'CSV file must contain "{url_column}" and "{port_col}" columns.')

        for line_number, row in enumerate(csv_reader, start=2):  # Line numbers start at 2 considering the header
            url = normalize_url(row[url_column].strip())
            port = row[port_column].strip()
            # Validate ports are digits within the TCP port range
            if is_valid_port(port):
                key = f"{url}:{port}"
                targets[key] = {'url': url, 'port': port}
            else:
                raise click.UsageError(f"Invalid port found in CSV: {port} (Line {line_number})")
    return targets

def process_text_file(filepath, verbose):
    """
    Takes a txt filepath, validates and processes the input, and returns a dictionary of targets to scan.
    """
    targets = {}
    try:
        with open(filepath, 'r') as text_file:
            for line_number, line in enumerate(text_file, start=1):
                line = line.strip()
                # Perform validation and processing
                if ':' in line and line.count(':') == 2:  # Expect 2, 1 from http(s)://, 1 from url:port
                    parts = line.rsplit(':', 1)
                    url = normalize_url(parts[0].strip())
                    port = parts[1].strip()
                    # Validate ports are digits within TCP port range
                    if is_valid_port(port):
                        key = f"{url}:{port}"
                        targets[key] = {'url': url, 'port': port}
                    else:
                        raise click.UsageError(f"Invalid port found in text file: {port} (Line {line_number})")
                else:
                    raise click.UsageError(f"Line {line_number} in text file is not correctly formatted as 'url:port'.")
    except Exception as e:
        raise click.ClickException(f"Error processing the text file: {e}")

    return targets


def process_list(urls, ports):
    """
    Takes a list of urls and ports, validates and processes the input, and returns a dictionary of targets to scan.
    """
    targets = {}
    #Parse commandline input
    url_list = urls.split(',')
    port_list = ports.split(',')
    
    for url in url_list:
        url = normalize_url(url.strip())  # Normalize and strip whitespace from the URL
        for port in port_list:
            port = port.strip()  
            # Validate ports are digits within TCP port range
            if is_valid_port(port):
                key = f"{url}:{port}"
                targets[key] = {'url': url, 'port': port}
            else:
                raise click.UsageError(f"Invalid port found in list: {port}")
    return targets

# Normalize URLs, anticipating URLs with trailing forwardslashes
def normalize_url(url):
    return url.rstrip('/')

# Checks if valid TCP port
def is_valid_port(port):
    try:
        port_num = int(port)
        return 0 < port_num <= 65535
    except ValueError:
        # The provided port is not a number
        return False

if __name__ == '__main__':
    scan_workflow()
