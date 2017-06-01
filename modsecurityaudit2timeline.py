#!/usr/bin/env python
from __future__ import print_function
import argparse
import csv
import re
import sys
from urlparse import urlparse
from urllib import unquote_plus

parser = argparse.ArgumentParser(description='Convert modsecurity audit files to CSV')
parser.add_argument('-f', '--file', type=argparse.FileType('r'), help='Input file to process')
parser.add_argument('-o', '--output', type=argparse.FileType('w'), help='Output file to write to')
parser.add_argument('-i', '--input-files', type=argparse.FileType('r'), help='Input list of files to process')
args = parser.parse_args()

banner = '''
             _                     _ _                 _ _ _   ___ _   _           _ _
 _____ ___ _| |___ ___ ___ _ _ ___|_| |_ _ _ ___ _ _ _| |_| |_|_  | |_|_|_____ ___| |_|___ ___
|     | . | . |_ -| -_|  _| | |  _| |  _| | | .'| | | . | |  _|  _|  _| |     | -_| | |   | -_|
|_|_|_|___|___|___|___|___|___|_| |_|_| |_  |__,|___|___|_|_| |___|_| |_|_|_|_|___|_|_|_|_|___|
                                        |___|
'''

def parser_a(sectiondata):
    return re.search(r'\[(?P<timestamp>[^\[]+)\] (?P<transaction_id>\S+) (?P<src_ip>\S+) (?P<src_port>\S+) (?P<dst_ip>\S+) (?P<dst_port>\S+)', sectiondata).groupdict()

def parser_b(sectiondata):
    parsers = [r'(?P<request_http_method>\S+) (?P<request_http_request>\S+) (?P<request_http_protocol>\S+)',
               r'User-Agent: (?P<request_user_agent>.*)',
               r'Referer: (?P<request_referer>.*)',
               r'Cookie: (?P<request_cookie>.*)',
               r'Host: (?P<request_host>.*)',
               r'Origin: (?P<request_origin>.*)'
               r'Content-Type: (?P<request_content_type>.*)',
               r'Accept: (?P<request_accept>.*)',                   #Cant' think of an immediate security need for the following but might be useful(Detecting bots vs browsers?)
               r'Accept-Language: (?P<request_accept_language>.*)',
               r'Accept-Encoding: (?P<request_accept_encoding>.*)',
               r'DNT: (?P<request_do_not_track>.*)',
               r'Connection: (?P<request_connection>.*)']
    parsed = {}
    for parser in parsers:
        try:
            parsed.update(re.search(parser, sectiondata).groupdict())
        except:
            pass
    if 'request_cookie' in parsed:
        cookies = parsed['request_cookie'].split('; ')
        for cookie in cookies:
            parsed.update(dict([['cookie_' + cookie.split('=')[0], cookie.split('=')[1]]])) #Ugly but works
    request_http_request_parsed = urlparse(parsed['request_http_request'])
    parsed['request_http_request'] = request_http_request_parsed.path
    parsed.update({'request_http_request_query': unquote_plus(request_http_request_parsed.query)})
    return parsed

def parser_c(sectiondata):
    request_body = sectiondata.strip()
    parsed = {'request_body': request_body}
    for request_body_param in request_body.split('&'):
        request_body_param_key, request_body_param_value = request_body_param.split('=')
        request_body_param_key = 'request_body_param_' + unquote_plus(request_body_param_key)
        request_body_param_value = unquote_plus(request_body_param_value)
        parsed.update({'request_body': request_body})
    return parsed

def parser_f(sectiondata):
    parsers = [r'(?P<response_http_protocol>\S+) (?P<response_http_status_code>\S+) (?P<response_http_status_message>\S+)',
               r'Content-Length: (?P<response_content_length>\d+)']
    parsed = {}
    for parser in parsers:
        try:
            parsed.update(re.search(parser, sectiondata).groupdict())
        except:
            pass
    return parsed

def parser_h(sectiondata):
    parsers = [r'Engine-Mode: "(?P<enginer_mode>[^\"]+)"']
    parsed = {}
    for parser in parsers:
        try:
            parsed.update(re.search(parser, sectiondata).groupdict())
        except:
            pass
    for severity, message in re.findall(r'Message: (?P<modsecurity_severity>\S+)\. (?P<modsecurity_message>.*)', sectiondata):
        if 'modsecurity_severity_' + severity.lower() not in parsed:
            parsed.update({'modsecurity_severity_' + severity.lower(): message})
        else:
            parsed['modsecurity_severity_' + severity.lower()] = parsed['modsecurity_severity_' + severity.lower()] + '\n' + message
    return parsed

def parser_k(sectiondata):
    matched_rules = ''
    for line in sectiondata.splitlines():
        if not line.startswith('#'):
            matched_rules += line + '\n'
    return {'matched_rules': matched_rules.strip()}

def run_parser(section, sectiondata):
    #print("run_parser")
    if section in ['', 'Z']:
        return {}
    elif section is 'A':
        return parser_a(sectiondata)
    elif section is 'B':
        return parser_b(sectiondata)
    elif section is 'C':
        return parser_c(sectiondata)
    elif section is 'E':
        #Parser for "Intended Response Body" not implemented - not sure what to extract
        return {}
    elif section is 'F':
        return parser_f(sectiondata)
    elif section is 'H':
        return parser_h(sectiondata)
    elif section is 'K':
        return parser_k(sectiondata)
    else:
        print('Unknown section: %s' % section)

def process_mod_security_audit_file(file):
    section = ''
    sectiondata = ''
    auditentry = {}
    for line in file.splitlines():
        if line.startswith('--'):
            try:
                auditentry.update(run_parser(section, sectiondata))
            except:
                print("Error in process_mod_security_audit_file")
            section = line.split('-')[3]
            sectiondata = ''
        elif line :
            sectiondata += ('%s\n' % line)
    auditentry.update(run_parser(section, sectiondata))
    return auditentry


if __name__ == "__main__":
    print(banner)
    if (args.file is None or args.input_files is None) and args.output is None:
        parser.print_help()
        sys.exit(1)
    elif args.file is not None and args.input_files is not None:
        parser.print_help()
        sys.exit(1)
    elif args.file is not None and args.output is not None:
        #TODO: Log the actual input file into the generated dict
        auditfile = args.file.read()
        auditentries = []
        auditentries.append(process_mod_security_audit_file(auditfile))
        csvheaders = set().union(*(d.keys() for d in auditentries))
        csvwriter = csv.DictWriter(args.output, fieldnames=csvheaders)
        csvwriter.writeheader()
        csvwriter.writerows(auditentries)
        sys.exit(0)
    elif args.input_files is not None and args.output is not None:
        input_files = args.input_files.read()
        auditentries = []
        for index, input_file in enumerate(input_files.splitlines()):
            print("\r[+] Processing file %d - %s" % (index, input_file), end="")
            auditfile = open(input_file).read()
            auditentries.append(process_mod_security_audit_file(auditfile))
        print()
        csvheaders = set().union(*(d.keys() for d in auditentries))
        csvwriter = csv.DictWriter(args.output, fieldnames=csvheaders)
        csvwriter.writeheader()
        csvwriter.writerows(auditentries)
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(1)
