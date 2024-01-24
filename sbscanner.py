import click
import csv
import aiohttp
import asyncio
import json
import dicttoxml
from xml.dom.minidom import parseString
from base64 import b64encode

@click.command(context_settings=dict(
    #ignore_unknown_options=True,
    #allow_extra_args=True,
))
@click.option('--csv', 'csv_filepath', type=click.Path(exists=True), help='Path to a CSV file, containing a list of urls & ports.')
@click.option('--text', 'text_filepath', type=click.Path(exists=True), help='Path to a text file, containing url:port notated targets.')
@click.option('--list', 'list_flag', required=False, is_flag=True, help='Flag to indicate that input is supplied via CLI arguments.')
@click.option('--list-urls', 'list_urls', required=False, help='Comma separate list of URL values.')
@click.option('--list-ports', 'list_ports', required=False, help='Comma separate list of port values.')
@click.option('--url-col', required=False, help='Name of the URL column in the CSV.')
@click.option('--port-col', required=False, help='Name of the port column in the CSV.')
@click.option('--username', 'username', default='root', help='Username for HTTP Basic Auth.')
@click.option('--password', 'password', default='root', help='Password for HTTP Basic Auth.')
@click.option('--verbose', is_flag=True, required=False, help='Enables verbose mode.')
@click.option('--no-verify-ssl', is_flag=True, required=False, help='Enables ssl verification when scanning.')
@click.option('--output', type=click.Choice(['text', 'json', 'xml'], case_sensitive=False), default='text', help='Output format: text, json or xml')
@click.pass_context
def scan_workflow(ctx, csv_filepath, text_filepath, list_flag, list_urls, list_ports, url_col, port_col, username, password, verbose, no_verify_ssl, output):
    """An HTTP Basic Authentication scanner written in Python by Sean Benson.

    Features:\n
    * Supports multiple forms of input (csv file, txt file, list of args).\n
    * Supports multiple forms of output via STDOUT (Text report, XML, CSV).\n
    * Performant through the use of Python's aiohttp framework.\n"""

    targets = process_input(ctx, csv_filepath, text_filepath, list_flag, list_urls, list_ports, url_col, port_col, verbose)
    event_loop = asyncio.get_event_loop()
    scan_result = event_loop.run_until_complete(scan_targets(targets, verbose, username, password, not no_verify_ssl))
    event_loop.close()
    if output == 'json':
        click.echo(json.dumps(scan_result, indent=4))
    elif output == 'xml':
        # Convert scan_result to an unformatted XML string using dicttoxml
        unformatted_xml = dicttoxml.dicttoxml(scan_result, custom_root='scan_results', attr_type=False)
        # Parse the unformatted XML string, then pretty print
        dom = parseString(unformatted_xml)
        pretty_xml = dom.toprettyxml(indent="    ")  # Adjust indent size as needed
        click.echo(pretty_xml)
    elif output == 'text':  # default to text output
        generate_report(scan_result, username, password, verbose)

# Processing input
def process_input(ctx, csv_filepath, text_filepath, list_flag, list_urls, list_ports, url_col, port_col, verbose):
    target_dict = {}

    if csv_filepath:
        if verbose:
            click.echo("Using csv input.")
        # Validate that the CSV has the required headers (columns)
        with open(csv_filepath, newline='') as csv_file:
            csv_reader = csv.reader(csv_file)
            headers = next(csv_reader, None)
            if url_col not in headers or port_col not in headers:
                raise click.UsageError(f'CSV file must contain "{url_col}" and "{port_col}" columns.')
            target_dict = process_csv(csv_filepath, url_col, port_col)
    
    if text_filepath:
        # Validate that each line in the text file follows the expected "url:port" format
        with open(text_filepath, 'r') as text_file:
            for line_number, line in enumerate(text_file, 1):
                if ':' not in line or line.count(':') != 2:
                    raise click.UsageError(f"Line {line_number} in text file is not correctly formatted.")
            target_dict = process_text_file(text_filepath)

    if list_flag:
        if verbose:    
            click.echo("Using list of URLs & Ports as input.")
        # Validate that the list arguments are not empty and have the correct format
        if not list_urls or not list_ports:
            raise click.UsageError('--list-urls and --list-ports options are required when using --list.')
        url_list = list_urls.split(',')
        port_list = list_ports.split(',')
        if not all(url_list) or not all(port_list):
            raise click.UsageError('List arguments must contain valid URL and port entries separated by commas.')

        # Additional format checking can be added here (e.g., check that each URL is valid)
        target_dict = process_list(list_urls, list_ports)

    if not any([csv_filepath, text_filepath, list_flag]):
        raise click.UsageError('You must provide an input using --csv, --text, or --list options.')

    return target_dict
    
# Scanning
async def scan_targets(targets, verbose, username, password, verify_ssl=True):
    creds = f'{username}:{password}'.encode('utf-8')  # Encode the credentials to bytes
    auth_header = 'Basic ' + b64encode(creds).decode('utf-8')  # Base64 encode the credentials and decode to string
    ssl_context = None if verify_ssl else False

    async with aiohttp.ClientSession() as session:
        for target, details in targets.items():
            connected = False
            try:
                # Attempt the first request without the Authorization header
                async with session.get(target, ssl=ssl_context) as initial_response:
                    connected = True
                    if initial_response.status == 401 and 'WWW-Authenticate' in initial_response.headers:
                        # The server expects Basic Auth, let's try with the credentials
                        supports_basic_auth = 'Basic' in initial_response.headers.get('WWW-Authenticate', '')
                        async with session.get(target, headers={'Authorization': auth_header}, ssl=ssl_context) as auth_response:
                            auth_success = 200 <= auth_response.status < 300
                            details.update({
                                'connected': connected,
                                'basic_auth_required': supports_basic_auth,
                                'authentication_success': auth_success,
                            })
                    else:
                        auth_success = 200 <= initial_response.status < 300
                        details.update({
                            'connected': connected,
                            'basic_auth_required': False,
                            'authentication_success': auth_success,
                        })
            except aiohttp.ClientError as e:
                details.update({
                    'connected': connected,
                    'basic_auth_required': False,
                    'authentication_success': False,
                    'error': str(e),
                })
            except Exception as e:
                details.update({
                    'connected': connected,
                    'basic_auth_required': False,
                    'authentication_success': False,
                    'error': 'An unexpected error occurred.',
                })
    return targets
# Report Generation
def generate_report(targets, username, password, verbose):
    for target, details in targets.items():
        if details.get('connected'):
            if details.get('basic_auth_required') and details.get('authentication_success'):
                click.echo(f"{target} - SUCCESS -  HTTP Basic auth succeeded using username: '{username}' and password: '{password}'")
            elif verbose:
                if details.get('basic_auth_required'):
                    auth_msg = f'HTTP Basic auth failed with the username: \'{username}\' and password: \'{password}\''
                else:
                    auth_msg = "HTTP Basic auth not required"
                click.echo(f"{target} - FAILED - {auth_msg}")
        elif verbose and 'error' in details:
            click.echo(f"{target} - FAILED - Connection failed: {details['error']}")

# Normalize URLs, anticipating URLs with trailing forwardslashes
def normalize_url(url):
    return url.rstrip('/')

# Processing of input
def process_csv(filepath, url_column, port_column):
    targets = {}
    with open(filepath, newline='') as csv_file:
        reader = csv.DictReader(csv_file)
        for line_number, row in enumerate(reader, start=2):  # Start at 2 to account for the header row
            url = normalize_url(row[url_column].strip())
            port = row[port_column].strip()
            if not port.isdigit() or not 0 < int(port) <= 65535:
                raise click.UsageError(f"Invalid port found in CSV: {port} (Line {line_number})")
            key = f"{url}:{port}"
            targets[key] = {'url': url, 'port': port}
    return targets

def process_text_file(filepath):
    targets = {}
    with open(filepath, 'r') as text_file:
        for line_number, line in enumerate(text_file, start=1):
            line = line.strip()
            parts = line.rsplit(':', 1)
            if len(parts) == 2 and parts[1].isdigit() and 0 < int(parts[1]) <= 65535:
                url = normalize_url(parts[0])
                port = parts[1]
                targets[f"{url}:{port}"] = {'url': url, 'port': port}
            else:
                raise click.UsageError(f"Line {line_number} in text file is not correctly formatted as 'url:port'.")
    return targets

def process_list(urls, ports):
    targets = {}
    url_list = urls.split(',')
    port_list = ports.split(',')
    
    for url in url_list:
        url = normalize_url(url.strip())  # Normalize and strip whitespace from the URL
        for port in port_list:
            port = port.strip()  # Strip whitespace from the port
            if not port.isdigit() or not 0 < int(port) <= 65535:
                raise click.UsageError(f"Invalid port found in list: {port}")
            key = f"{url}:{port}"
            targets[key] = {'url': url, 'port': port}
    return targets

if __name__ == '__main__':
    scan_workflow()