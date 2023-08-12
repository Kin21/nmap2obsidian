import argparse
import os
from libnmap.parser import NmapParser
import datetime
import json
import shutil
import re


# Argument parsing section
parser = argparse.ArgumentParser(
                    prog='nmap2obsidian',
                    description='''This program allows you to create folder structure for notes that 
                                    are written in Markdown by using nmap scan results as input.''',
                    epilog='^_^')

parser.add_argument('-f', action='extend', nargs='+',
                    help='Nmap scan result saved as xml files to parse',
                    metavar='files',
                    required=False)

parser.add_argument('--vault_name',
                    help='Name of the root folder for notes',
                    required=False)

parser.add_argument('--delete_vault', action='store_true',
                    help='Delete vault folder',
                    required=False)

parser.add_argument('--init_vault', action='store_true',
                    help='Init vault',
                    required=False)

args = parser.parse_args()
###

# Init values
if args.vault_name:
    vault_name = args.vault_name
elif args.init_vault:
    vault_name = f'Notes_{datetime.datetime.now().strftime("%Y_%m_%d_%H_%M")}'
    print(f'Name for vault automatically generated {vault_name}')
else:
    print('Provide name of the vault')
    exit(-1)

working_dir = os.getcwd()

vault_path = str(os.path.join(working_dir, vault_name))
if not os.path.isdir(vault_path) and not args.init_vault:
    print(f'Incorrect name of vault provided, directory do not exist {vault_path}')
    exit(-1)

config_dir = str(os.path.join(vault_path, 'config'))
config_file_path = str(os.path.join(config_dir, 'config.json'))
raw_files_dir = str(os.path.join(vault_path, 'Raw files'))
nmap_scan_results_dir = str(os.path.join(raw_files_dir, 'Nmap Scan Results'))

# Files to create in each host directory
raw_file_name = 'Raw.md'
host_dir_init_files = [raw_file_name]

# Folders to create in each host directory
open_ports_dir_name = 'Open ports'
screenshots_dir_name = 'Screenshots'
raw_files_dir_name = 'Raw files'
host_dir_init_dirs = [open_ports_dir_name, screenshots_dir_name, raw_files_dir_name]

# Formats
# Service name f'{s.port}-{s.service} {s.protocol}.md'

###


# Vault operations

def create_new_file(file_name):
    f = open(file_name, 'w')
    f.close()


def init_config():
    data = {
        "vault_name": vault_name,
        "vault_path": vault_path,
        "hosts": {}
            }
    os.mkdir(config_dir)
    with open(config_file_path, 'w') as f:
        json.dump(data, f)


def init_vault():
    try:
        os.mkdir(vault_path)
    except FileExistsError:
        print(f'Directory with this name is arleady exist {vault_path}')
        exit(-1)
    init_config()
    os.mkdir(raw_files_dir)
    os.mkdir(nmap_scan_results_dir)
    create_new_file(str(os.path.join(vault_path, 'Raw.md')))
    create_new_file(str(os.path.join(vault_path, 'Notes.md')))
    create_new_file(str(os.path.join(vault_path, 'Report.md')))
    exit()


def create_host_dir(dir_name):
    host_dir_path = str(os.path.join(vault_path, dir_name))
    os.mkdir(host_dir_path)
    create_new_file(str(os.path.join(host_dir_path, dir_name)) + '.md')
    for d in host_dir_init_dirs:
        d = str(os.path.join(host_dir_path, d))
        os.mkdir(d)
    for f in host_dir_init_files:
        f = str(os.path.join(host_dir_path, f))
        create_new_file(f)
    return host_dir_path


def read_config():
    with open(config_file_path, 'r') as f:
        config = json.load(f)
    return config


def delete_data():
    # This overhead ensures that correct folder will be deleted
    # If no config will be found just error occurs
    config = read_config()
    vault_path = config['vault_path']
    shutil.rmtree(vault_path)
    exit()
###


# Write info in Markdown
def create_link_text(link_to, show_as):
    return f'[[{link_to}|{show_as}]]'


def write_host_info(host, file_name):
    data = '# Nmap scan summary\n\n'
    data += f'IP: {host.address}\n'
    data += f'MAC address: {host.mac}\n'
    if host.hostnames:
        hostnames = ' '.join(host.hostnames)
        data += f'Hostnames: {hostnames}\n'
    data += '## Services \n\n'
    for s in host.services:
        service_name = open_ports_dir_name + f'/{s.port}-{s.service} {s.protocol}'
        link_to_service = create_link_text(service_name, f'{s.port}-{s.service} {s.protocol}')
        data += f'### {link_to_service} \n\n'
        data += f'Port: {s.port} Service: {s.service}\n'
        data += f'Banner: {s.banner}\n'
        data += f'Reason: {s.reason}\n'
        if s.scripts_results:
            data += f'#### Scripts\n\n'
            script_res = json.dumps(s.scripts_results, indent=4)
            result_string = re.sub(r'[\[\]\{\}]', ' ', script_res)
            data += f'{result_string}\n\n'

    data += '## Other results\n\n'
    if host.os_fingerprinted:
        data += f'OS: {host.os_fingerprint}'
    if host.scripts_results:
        script_res = json.dumps(host.scripts_results, indent=4)
        result_string = re.sub(r'[\[\]\{\}]', ' ', script_res)
        data += f'{result_string}\n\n'

    with open(file_name, 'w') as f:
        f.write(data)





# Nmap scans parsing
'''
    For Nmap report parsing following library is used: https://libnmap.readthedocs.io/en/latest/parser.html
    Files that are provided expected to be "a complete nmap XML scan report"
    
    Differences will be discovered on host "libnmap.objects.NmapHost" basis, using libnmap.diff module
    Only new services (added() function will be used) will be added to host report,
    hosts are distinguished by IP
'''


def host_is_present(host_ip):
    """
    Checks if host is already added to Notes
    Returns Bool
    """
    config = read_config()
    return host_ip in config['hosts'].keys()


def add_host_services(host):
    host_path = str(os.path.join(vault_path, host.address))
    for s in host.services:
        file_name = f'{s.port}-{s.service} {s.protocol}.md'
        file_path = str(os.path.join(host_path, open_ports_dir_name, file_name))
        create_new_file(file_path)


def add_new_host(host):
    if not host.is_up():
        return
    host_dir_path = create_host_dir(host.address)
    add_host_services(host)
    host_file_path = str(os.path.join(host_dir_path, host.address))
    write_host_info(host, host_file_path + '.md')


def parse_nmap_scans():
    try:
        nmap_reports = [NmapParser.parse_fromfile(f) for f in args.f]
    except FileNotFoundError as e:
        print(f'File "{e.filename}" was not found, not changes done, aborting...')
        exit(-1)
    hosts = []
    for r in nmap_reports:
        hosts += r.hosts
    for h in hosts:
        if not host_is_present(h.address):
            add_new_host(h)


# Execution
if args.delete_vault:
    if input('Delete vault and all data inside ? N/y') in ('y', 'Y'):
        delete_data()
elif args.init_vault:
    init_vault()
parse_nmap_scans()