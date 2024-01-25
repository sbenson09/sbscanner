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
@click.option('--username', 'username', default='root', help='Username for HTTP Basic Auth.')
@click.option('--password', 'password', default='root', help='Password for HTTP Basic Auth.')
@click.option('--verbose', is_flag=True, required=False, help='Enables verbose mode for text output.')
@click.option('--no-verify-ssl', is_flag=True, required=False, help='Disables ssl verification when scanning.')
@click.option('--output', type=click.Choice(['text', 'json', 'xml'], case_sensitive=False), default='text', help='Output format: text, json or xml')
@click.pass_context
def scan_workflow(ctx, csv_filepath, text_filepath, list_flag, list_urls, list_ports, url_col, port_col, username, password, verbose, no_verify_ssl, output):
    """An HTTP Basic Authentication scanner written in Python by Sean Benson.

    Features:\n
    * Supports multiple forms of input (csv file, txt file, list of args).\n
    * Supports multiple forms of output via STDOUT (Text report, XML, CSV).\n
    * Performant through the use of Python's aiohttp framework.\n"""

    # Take input provided by user, and process into a dictionary of targets to use for scanning
    targets = process_input(ctx, csv_filepath, text_filepath, list_flag, list_urls, list_ports, url_col, port_col, verbose)
    
    # Run the scan against each provided target. 
    event_loop = asyncio.get_event_loop()
    scan_result = event_loop.run_until_complete(scan_targets(targets, verbose, username, password, not no_verify_ssl))
    event_loop.close()
    
    # Provide output report based on user input
    if output == 'json':
        click.echo(json.dumps(scan_result, indent=4))
    elif output == 'xml':
        unformatted_xml = dicttoxml.dicttoxml(scan_result, custom_root='scan_results', attr_type=False)
        # Parse the unformatted XML string, then pretty print to stdout
        dom = parseString(unformatted_xml)
        pretty_xml = dom.toprettyxml(indent="    ") 
        click.echo(pretty_xml)
    elif output == 'text':  # Click defaults to text output
        generate_text_report(scan_result, username, password, verbose)

def process_input(ctx, csv_filepath, text_filepath, list_flag, list_urls, list_ports, url_col, port_col, verbose):
    """
    Takes input provided by user, validates the input, and returns a dictionary with processed scanning targets.
    """
    target_dict = {}

    # For CSV input, loop through .csv file, validate that url and port header values
    # are valid, and then return a target dictionary
    if csv_filepath and not any([text_filepath, list_flag]):
        if verbose:
            click.echo("Using csv input.")
        if not url_col or not port_col:
            raise click.UsageError('When using --csv option, you must also provide --url-col and --port-col options.')    
        try:
            with open(csv_filepath, newline='') as csv_file:
                csv_reader = csv.reader(csv_file)
                headers = next(csv_reader, None)
                if url_col not in headers or port_col not in headers:
                    raise click.UsageError(f'CSV file must contain "{url_col}" and "{port_col}" columns.')
                target_dict = process_csv(csv_filepath, url_col, port_col)
        except Exception as e:
            raise click.ClickException(f"Error processing the CSV file: {e}")    
    # For text input, loop through .txt file, validate that lines follow expected format,
    # and then return a target dictionary
    elif text_filepath and not any([csv_filepath, list_flag]):
        with open(text_filepath, 'r') as text_file:
            for line_number, line in enumerate(text_file, 1):
                if ':' not in line or line.count(':') != 2:  # Anticipate 2 ':' (1 in http://, 1 between url + port)
                    raise click.UsageError(f"Line {line_number} in text file is not correctly formatted.")
            target_dict = process_text_file(text_filepath)

    # For list input, loop through lists, validating that lines are not empty,
    # and are valid, and then return a target dictionary.
    elif list_flag and not any([text_filepath, csv_filepath]):
        if verbose:    
            click.echo("Using list of URLs & Ports as input.")
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
    
async def scan_targets(targets, verbose, username, password, verify_ssl=True):
    creds = f'{username}:{password}'.encode('utf-8')  
    auth_header = 'Basic ' + b64encode(creds).decode('utf-8')
    ssl_context = None if verify_ssl else False
    timeout_duration = aiohttp.ClientTimeout(total=2)

    semaphore = asyncio.Semaphore(100)

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
            async with session.get(f"{target_key}", ssl=ssl_context) as initial_response:
                connected = True
                # Check for HTTP authentication requirements
                if initial_response.status == 401 and 'WWW-Authenticate' in initial_response.headers:
                    supports_basic_auth = 'Basic' in initial_response.headers.get('WWW-Authenticate', '')
                    if supports_basic_auth:
                        # Attempt authentication
                        async with session.get(f"{target_key}", headers={'Authorization': auth_header}, ssl=ssl_context) as auth_response:
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
                    return {
                        'target_key': target_key,
                        'connected': connected,
                        'basic_auth_required': False,
                    }
        except aiohttp.ClientError as e:
            return {
                'target_key': target_key,
                'connected': connected,
                'basic_auth_required': False,
                'authentication_success': False,
                'error': str(e),
            }
        except Exception as e:
            return {
                'target_key': target_key,
                'connected': connected,
                'basic_auth_required': False,
                'authentication_success': False,
                'error': 'An unexpected error occurred.'
            }

def generate_text_report(targets, username, password, verbose):
    """
    Takes a dictionary of scan results and config options. Outputs to STDOUT in text format.
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

# Normalize URLs, anticipating URLs with trailing forwardslashes
def normalize_url(url):
    return url.rstrip('/')

def process_csv(filepath, url_column, port_column):
    """
    Takes a csv filepath and header names, validates and processes the input, and returns a dictionary of targets to scan.
    """
    targets = {}
    with open(filepath, newline='') as csv_file:
        reader = csv.DictReader(csv_file)
        for line_number, row in enumerate(reader, start=2):  # Start at 2 to account for the header row
            url = normalize_url(row[url_column].strip())
            port = row[port_column].strip()
            # Validate ports are digits within TCP port range
            if not port.isdigit() or not 0 < int(port) <= 65535:
                raise click.UsageError(f"Invalid port found in CSV: {port} (Line {line_number})")
            key = f"{url}:{port}"
            targets[key] = {'url': url, 'port': port}
    return targets

def process_text_file(filepath):
    """
    Takes a txt filepath, validates and processes the input, and returns a dictionary of targets to scan.
    """
    targets = {}
    with open(filepath, 'r') as text_file:
        for line_number, line in enumerate(text_file, start=1):
            line = line.strip()
            parts = line.rsplit(':', 1)
            # Validate ports are digits within TCP port range
            if len(parts) == 2 and parts[1].isdigit() and 0 < int(parts[1]) <= 65535:
                url = normalize_url(parts[0])
                port = parts[1]
                targets[f"{url}:{port}"] = {'url': url, 'port': port}
            else:
                raise click.UsageError(f"Line {line_number} in text file is not correctly formatted as 'url:port'.")
    return targets

def process_list(urls, ports):
    """
    Takes a list of urls and ports, validates and processes the input, and returns a dictionary of targets to scan.
    """
    targets = {}
    url_list = urls.split(',')
    port_list = ports.split(',')
    
    for url in url_list:
        url = normalize_url(url.strip())  # Normalize and strip whitespace from the URL
        for port in port_list:
            port = port.strip()  # Strip whitespace from the port
            # Validate ports are digits within TCP port range
            if not port.isdigit() or not 0 < int(port) <= 65535:
                raise click.UsageError(f"Invalid port found in list: {port}")
            key = f"{url}:{port}"
            targets[key] = {'url': url, 'port': port}
    return targets

if __name__ == '__main__':
    asyncio.run(scan_workflow())
