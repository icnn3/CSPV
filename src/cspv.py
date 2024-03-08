from datetime import datetime
import requests
import sys
import time
import threading
from urllib.parse import urlparse
import re
import logging
import pwinput
import os
from requests_ntlm import HttpNtlmAuth
import warnings
from art import *

warnings.simplefilter('ignore', category=UserWarning)
os.system('color')
requests.packages.urllib3.disable_warnings()

# host_regex = '^(?:(ftp|http|https):\/\/)?(?:[\w|\*]+\.)+[a-z]{2,6}(\/.*)?'
host_regex = '^(?:(ftp|http|https):\/\/)?(?:[a-zA-z,-|\*]+\.)+[a-z]{2,6}(\/.*)?'
ip_regex = "^(?:(ftp|http|https):\/\/)?((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"


class Spinner:
    busy = False
    delay = 0.1
    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in '|/-\\': yield cursor

    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(next(self.spinner_generator))
            sys.stdout.flush()
            time.sleep(self.delay)
            sys.stdout.write('\b')
            sys.stdout.flush()

    def __enter__(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def __exit__(self, exception, value, tb):
        self.busy = False
        time.sleep(self.delay)
        if exception is not None:
            return False


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def get_input():
    # 1) they paste the CSP string from the console
    # 2) they paste URL string
    # if it starts with http or https: call processURL to get the string
    #print('in getInput')
    response = input("Enter the URL (include http/https) or CSP String to evaluate\n")
    return response


def get_proxy_creds():
    global username
    global pw
    username = str(os.environ['USERNAME']).lower()
    pw = pwinput.pwinput(prompt="Enter AD-ENT Password for %s: " % username, mask='*')
    # return username, pw


def process_url(csphost: str):

    try:
        with Spinner():
            print("\nConnecting to " + csphost + " .....", end='')
            resp2 = requests.get(csphost, verify=False)
            print("done")
    except requests.ConnectionError as err:
        print("done")
        print("******************************************")
        print("\tConnection Error to " + csphost)
        print("\tMake sure site is available")
        print("\t" + str(err))
        print("******************************************")
        exit(-1)

    if resp2.status_code == 401:
        print("AD-ENT credentials required")
        # username, pw = get_proxy_creds()
        get_proxy_creds()

        response = requests.get(csphost, auth=HttpNtlmAuth('AD-ENT\\' + username.strip(), pw.strip()), verify=False,
                                allow_redirects=True)

        if response.status_code != 200:
            print("\n---Unable to authenticate----")
            print("Status Code: " + str(response.status_code))
            exit(-1)

        resp2 = response

    elif resp2.status_code != 200:
        print("Unable to Connect to " + csphost + "\nStatus Code: " + str(resp2.status_code))
        exit(-1)

    if 'Content-Security-Policy' not in resp2.headers:
        print("\n----------------------------------------------------------------")
        print("No CSP Header found for " + csphost + " current headers are...\n")
        print(resp2.headers)
        print("----------------------------------------------------------------")

        exit(-1)
    else:
        # print("headers from url...")
        # print(resp2.headers['Content-Security-Policy'] + "\n")
        return resp2.headers['Content-Security-Policy']

    # if you get 403, then ask for credentials
    # google python requests get csp header


def allow_list_check(allowlist_url, status):

    # If using an allowlist, then each resource must:
    # Specify the host of the origin
    # Such as https://this.example.com or at a minimum, example.com
    # The scheme and port are optional
    # The host must be a hostname containing only ASCII characters, and not an IP address
    # Not use the wildcard "*" for first-level / parent domains
    # Such as *.com
    # Not specify the scheme alone
    # Such as https:

    # Make a regular expression
    # for validating an Ip-address
    passed = True

    # scheme is specified alone check
    if allowlist_url == "http:" or allowlist_url == "https:":
        print(bcolors.FAIL + "[FAIL]" + bcolors.ENDC + ": Do not specify the scheme alone")
        return False

    # if no prefix, force one to allow urlparse to work correctly

    if '://' not in allowlist_url:
    # if not allowlist_url.startswith('http'):
        url2 = 'http://' + allowlist_url
    else:
        url2 = allowlist_url

    url = urlparse(url2)
    tld, domain, *sub_domains = url.hostname.split(".")[::-1]
    # print("domain value {}".format(domain))
    # print("hostname: " + url.hostname)

    # Check for IP address - not allowed
    if re.search(ip_regex, url.hostname):
        print(bcolors.FAIL + "[FAIL]" + bcolors.ENDC + ": IP address not allowed")
        return False

    # Check for no host
    # No requirement to check for host
    # if len(sub_domains) < 1:
    #     passed = False
    #     print(bcolors.FAIL + "[FAIL]" + bcolors.ENDC + ": host or level1 domain required??")

    # Check for wildcards as host or sub-domain
    elif '*' in domain:
        passed = False
        print(bcolors.FAIL + "[FAIL]" + bcolors.ENDC + ": wildcard not allowed in domain")

    # print(sub_domains)
    # print('found http/https process as "allow list"')

    if passed:
        if status == 'PASS':
            print(bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)
        elif status == 'WARN':
            print(bcolors.WARNING + "[WARN]:" + bcolors.ENDC + " alternative detected, ensure config is required")
        else:
            print("Program Error: unknown 'status' " + status)

    return passed


def format_csp_str(cspstr):
    csp_dict = {}
    cspstr = cspstr.lower().strip()
    cspstr = cspstr.replace("content-security-policy:", "")
    cspstr = cspstr.replace("content-security-policy", "")
    cspstr = cspstr.lower().strip()

    # for malformed CSP strings, removed the surrounding quotes
    if cspstr[0] == '"':
        cspstr = cspstr[1:]

    if cspstr[len(cspstr) - 1] == '"':
        cspstr = cspstr[:-1]

    if cspstr[len(cspstr) - 2] == '"':
        cspstr = cspstr[:-2]
    
    # ---------------------------------------

    dirs = [
        "report-to",
        "object-src",
        "report-uri",
        "child-src",
        "frame-ancestors",
        "script-src-elem",
        "script-src",
        "connect-src",
        "font-src",
        "img-src",
        "manifest-src",
        "media-src",
        "object-src",
        "base-uri",
        "prefetch-src",
        "form-action",
        "style-src",
        "worker-src",
        "default-src"
    ]

    # remove end semicolon if present
    if cspstr[len(cspstr) -1] == ';':
        cspstr = cspstr[0:(len(cspstr) - 1)]

    # split into array and dictionary
    csp_elements = cspstr.split(';')

    for x in csp_elements:
        parts = x.strip().split(' ')

        # remove any empty values
        if '' in parts:
            parts.remove('')

        # check for dupes
        # IF(same directive exists more than once in CSP header): FAIL w/ error 'CSP cannot contain duplicate directives'
        if parts[0] not in csp_dict:
            csp_dict[parts[0]] = parts[1:len(parts)]
        else:
            print("** FAIL: CSP cannot contain duplicate directives for '" + parts[0] + "'")
            print(parts[0] + ": " + " ".join(csp_dict[parts[0]]))
            print(parts[0] + ": " + " ".join(parts[1:len(parts)]))

    # validate string
    dir_found = False
    for dirval in dirs:
        if dirval in csp_dict:
            dir_found = True

    if not dir_found:
        print("\nInvalid CSP string, no directives found")
        exit(-1)

    return csp_dict


def validation(checklist: list, rules: dict, directive: str):
    # rules - dictionary with keys of directive vals and values of 'PASS' or 'ALLOW' or 'WARN' or "FAIL" or 'CHECK'
    # i.e. checklist['none', 'self', 'nonce'], rules{'none':'PASS'}
    # PASS - only 1 value in the array and it's equal the rule key

    not_allowed_found = False

    # validate the list
    for val in checklist:
        val = val.strip().strip("'").strip(":")

        # print("checking '" + val + "'....................", end='')
        print(val, end='')
        dots = '............................................'
        spacelen = 45 - (len(val))
        print(dots[0:spacelen], end='')

        # nonce format is nonce-rszyhwmwdr, set to 'nonce' to check if valid/allowed
        val2 = None
        if val.startswith("nonce-"):
            val2 = val
            val = "nonce"

        # similar to nonce for 'hash' values
        val3 = None
        hash_allows = ['sha256-','sha384-','sha512-']
        if val.startswith(tuple(hash_allows)):
            val3 = val
            val = 'hash'
        

        # lookup in rules
        if 'ALLOW-ALL' in rules.keys():
            print(bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)

        elif val in rules:
            rule = rules[val]
            if rule == 'PASS':  # check that the entire value is equal
                if len(checklist) == 1 and checklist[0].strip().strip("'") == val:
                    print(bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)
            elif rule == 'WARN':
                print(bcolors.WARNING + "[WARN]:" + bcolors.ENDC + " alternative detected, ensure config is required")
                # find the PASS items to print
                pass_vals = ["'" + val + "'" for val, rulex in rules.items() if rulex == "PASS"]
                # print(pass_vals)
                # print(", PASS values are ({})".format(" or ".join(pass_vals)))

                if val == 'nonce' and url_passed:
                    nonce_check(val2, directive)
            elif rule == "ALLOW":
                print(bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)
                if val == 'nonce' and url_passed:
                    nonce_check(val2, directive)
            elif rule == "FAIL":
                print(bcolors.FAIL + "[FAIL]" + bcolors.ENDC + ": not allowed")
                not_allowed_found = True
            elif rule == 'CHECK:WARN' or rule == 'CHECK:PASS':
                allow_list_check(val, rule.split(':')[1])
        else:
            print(bcolors.FAIL + "[FAIL]" + bcolors.ENDC + ": not allowed")
            not_allowed_found = True

    return not_allowed_found


def check_other(other_dir: str, other_str: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + other_dir + bcolors.ENDC + " directive")
    print("==============================================================================")

    # print(other_dir)
    # print(other_str)
    passed = True

    rules = {
        'nonce': 'ALLOW:',
        'hash': 'ALLOW:'
    }

    allow_rules = prep_allowlist_for_check(other_str, 'CHECK:PASS')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(other_str) + ")\n")
    # print("Rules: " + str(rules) + "\n")

    validation(other_str, rules, other_dir)


    # for x in other_str:
    #     v1 = x.strip().strip("'")
    #
    #     # if it starts with http or https, then process as allow list
    #     if v1.startswith('http:') or v1.startswith('https:'):
    #         # parse URL and check for host not wildcard
    #         allow_passed = allow_list_check(v1)

        # hash checks, lowest allowed according to W3.org is sha256 going back to 2016 when it introduced
        # https://www.w3.org/TR/CSP2/#source-list-valid-hashes
        # ex. sha256-RFWPLDbv2BY+rCkDzsE+0fr8ylGr2R2faWMhq4lfEQc=
        # https://content-security-policy.com/hash/

        # nonce checks
        # ex. 'nonce-VVJJcG9ydHMuY29tIGlzIHRoZSBiZXN0'


    # /*BROAD PASS CHECKS*/
    # IF(allow list exists for a directive) ->
    #   IF(host of the origin specified): PASS
    #   ELSE: FAIL w/ error 'host of origin not specified'
    #   IF(wildcard '*' used for first-level / parent domain): FAIL w/ error 'Do not use wildcard for first-level / parent domain'
    #   IF(scheme is specified alone): FAIL w/ error 'Do not specify the scheme alone'
    # IF(hash exists for a directive) ->
    #   IF(hash specifies SHA-256, SHA-384, or SHA-512): PASS
    #   ELSE: FAIL w/ error 'incorrect hash algorithms specified, must use SHA-256, SHA-384, or SHA-512'
    # IF(nonce exists for a directive) ->
    #   IF(nonce is at least 128 bits long before encoding): PASS
    #   ELSE: FAIL w/ error 'nonce must be at least 128 bits'
    # IF(same directive exists more than once in CSP header): FAIL w/ error 'CSP cannot contain duplicate directives'


def prep_allowlist_for_check(dirl: list, check_type):
    local_rules = {}
    # if allow list was permitted, add it check rule
    for val in dirl:
        # check for allow list
        val = val.strip().strip("'")
        if re.search(host_regex, val) is not None:
            local_rules[val] = check_type
        elif re.search(ip_regex, val) is not None:
            local_rules[val] = 'FAIL'
        # else:
        #     print("-- not a host: " + val)

    return local_rules


def check_default_src(default_src: list):
    print("\n\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "default-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    val1 = default_src[0].strip().strip("'")

    rules = {
       'none': 'PASS',
       'data': 'ALLOW',
       'blob': 'ALLOW'
    }

    print("(Values: " + ", ".join(default_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(default_src, rules, 'default_src')

    if show_allowed:
        print("\nAllowed values for default-src are: 'none', 'data', 'blob'")

    # //default-src
    # IF (default-src exists) ->
    #   IF (default-src value set to 'none'): PASS
    #   ELSE (any other value except 'none'): FAIL w/ error `default-src improperly set`
    # ELSE: FAIL w/ error `default-src does not exist`


def check_base_uri(base_uri: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "base-uri" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'data': 'ALLOW',
        'hash': 'WARN',
        'blob': 'ALLOW'
    }

    allow_rules = prep_allowlist_for_check(base_uri, "CHECK:WARN")
    rules.update(allow_rules)

    print("(Values: " + ", ".join(base_uri) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(base_uri, rules, 'base-uri')

    if show_allowed:
        print("\nAllowed values for base-uri are: 'none', 'self', 'nonce', 'hash', 'data', 'blob'")


    # #   IF (base-uri value set to 'none'): PASS
    # if len(base_uri) == 1 and base_uri[0].strip().strip("'") == "none":
    #     print("** PASS: base-uri is 'none'")
    #     return
    #
    # # //base-uri
    # for base_val in base_uri:
    #     base_val = base_val.strip().strip("'")
    #
    #     if base_val == 'self' or base_val == 'nonce' or base_val == 'hash':
    #         print("** WARN: alternative 'base-uri' detected, ensure [" + base_val + "] is required by application")
    #
    #     elif base_val.startswith('http:') or base_val.startswith('https:'):
    #         allow_list_check(base_val)
    #
    #     else:
    #         print("** FAIL: [" + base_val + "] not allowed, only 'self', 'none', 'nonce' & allow list are permitted")

    # IF (base-uri exists) ->
    #   IF (base-uri value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `base-uri is improperly set`
    # ELSE: FAIL w/ error `base-uri does not exist`


def check_form_action(form_action: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "form-action" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'data': 'ALLOW',
        'hash': 'WARN',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(form_action, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(form_action) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(form_action, rules, 'form-action')

    if show_allowed:
        print("\nAllowed values for form-action are: 'none', 'self','data', 'blob', (nonce), (hash)")


    # //form-action
    # IF (form-action exists) ->
    #   IF (form-action value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `form-action is improperly set`
    # ELSE: FAIL w/ error `form-action does not exist`


def check_frame_ancestors(frame_ancestors: list):
    print("\n\n===========================================================")
    print("\t\t Checking " + bcolors.OKBLUE + "frame-ancestors" + bcolors.ENDC + " directive")
    print("===========================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(frame_ancestors, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(frame_ancestors) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(frame_ancestors, rules, 'frame-ancestors')

    if show_allowed:
        print("\nAllowed values for frame-ancestors are: 'none', 'self', 'data', 'blob'")

    # //frame-ancestors
    # IF (frame-ancestors exists) ->
    #   IF (frame-ancestors value set to 'none'): PASS
    #   ELSE IF ('self', allow list): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list): FAIL w/ error `frame-ancestors is improperly set`
    # ELSE: FAIL w/ error `frame-ancestors does not exist`


def check_plugin_types(plugin_types):
    print("")
    # *** no longer allowed ***

    # //plugin-types
    # IF (plugin-types exists) ->
    #   IF (plugin-types value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `plugin-types is improperly set`
    # ELSE: FAIL w/ error `plugin-types does not exist`


def check_navigate_to(navigate_to):
    print("")
    # //navigate-to MUST NOT EXIST
    # IF (navigate-to exists): FAIL w/ error `navigate-to directive cannot be used`
    # ELSE: PASS


def check_child_src(child_src):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "child-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'hash': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'

    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(child_src, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(child_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(child_src, rules, 'child-src')

    if show_allowed:
        print("\nAllowed values for child-src are: 'none', 'self', 'data', 'blob', (nonce), (hash)")


    # //child-src
    # IF (child-src exists) ->
    #   IF (child-src value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `child-src is improperly set`)
    # ELSE: PASS


def check_connect_src(connect_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "connect-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    # //connect-src

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'hash': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(connect_src, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(connect_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(connect_src, rules, 'connect-src')

    if show_allowed:
        print("\nAllowed values for connect-src are: 'none', 'self', 'data', 'blob', (nonce), (hash)")

    # IF (connect-src exists) ->
    #   IF (connect-src value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `connect-src is improperly set`)
    # ELSE: PASS


def check_report_to(report_to: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "report-to" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'ALLOW-ALL': 'ALLOW',
    }

    print("(Values: " + ", ".join(report_to) + ")\n")

    validation(report_to, rules, 'report-to')



def check_font_src(font_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "font-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'hash': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(font_src, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(font_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(font_src, rules, 'font-src')

    if show_allowed:
        print("\nAllowed values for font-src are: 'none', 'self', 'data', 'blob', (nonce), (hash)")

    # //font-src
    # IF (font-src exists) ->
    #   IF (font-src value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `font-src is improperly set`)
    # ELSE: PASS


def check_frame_src(frame_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "frame-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'hash': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(frame_src, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(frame_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(frame_src, rules, 'frame-src')

    if show_allowed:
        print("\nAllowed values for frame-src are: 'none', 'self', 'data', 'blob', (nonce), (hash)")

    # //frame-src
    # IF (frame-src exists) ->
    #   IF (frame-src value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `frame-src is improperly set`)
    # ELSE: PASS


def check_img_src(img_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "img-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'hash': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(img_src, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(img_src) + ")\n")

    #  print("Rules: " + str(rules) + "\n")

    show_allowed = validation(img_src, rules, 'img-src')

    if show_allowed:
        print("\nAllowed values for img-src are: 'none', 'self', 'data', 'blob', (nonce), (hash)")

    # //img-src
    # IF (img-src exists) ->
    #   IF (img-src value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `img-src is improperly set`)
    # ELSE: PASS


def check_manifest_src(manifest_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "manifest-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'hash': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(manifest_src, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(manifest_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(manifest_src, rules, 'manifest-src')

    if show_allowed:
        print("\nAllowed values for manifest-src are: 'none', 'self', 'data', 'blob', (nonce), (hash)")

    # //manifest-src
    # IF (manifest-src exists) ->
    #   IF (manifest-src value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `manifest-src is improperly set`)
    # ELSE: PASS


def check_media_src(media_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "media-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'hash': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(media_src, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(media_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(media_src, rules, 'media-src')

    if show_allowed:
        print("\nAllowed values for media-src are: 'none', 'self', 'data', 'blob', (nonce), (hash)")

    # //media-src
    # IF (media-src exists) ->
    #   IF (media-src value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `media-src is improperly set`)
    # ELSE: PASS


def check_object_src(object_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "object-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'hash': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(object_src, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(object_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(object_src, rules, 'object-src')

    if show_allowed:
        print("\nAllowed values for object-src are: 'none', 'self', 'data', 'blob', (nonce), (hash)")

    # //object-src
    # IF (object-src exists) ->
    #   IF (object-src value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `object-src is improperly set`)
    # ELSE: PASS


def check_prefetch_src(prefetch_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "prefetch-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'hash': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(prefetch_src, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(prefetch_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(prefetch_src, rules, 'prefetch-src')

    if show_allowed:
        print("\nAllowed values for prefetch-src are: 'none', 'self', 'data', 'blob', (nonce), (hash)")

    # //prefetch-src
    # IF (prefetch-src exists) ->
    #   IF (prefetch-src value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `prefetch-src is improperly set`)
    # ELSE: PASS

def check_script_src_elem(script_src_elem: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "script-src-elem" + bcolors.ENDC + " directive")
    print("==============================================================================")
    print('********* here ************')

    # TODO: FOR NOW THIS IS BEING TREATED LIKE script-src while Chance Warren and team reviews what's allowed

    rules = {
        'data': 'FAIL',
        'unsafe-eval': 'FAIL',
        'unsafe-inline': 'FAIL',
        'unsafe-hashes': 'FAIL',
        'self': 'ALLOW',
        'nonce': 'ALLOW',
        'hash': 'ALLOW',
        'blob': 'ALLOW',
        'strict-dynamic': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(script_src_elem, 'CHECK:PASS')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(script_src_elem) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(script_src_elem, rules, 'script-src-elem')

    if show_allowed:
        print("\nAllowed values for script-src-elem are: 'self', 'blob', (nonce), (hash), 'strict-dynamic'")

    # //script-src*
    # IF (script-src* exists) ->




def check_script_src(script_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "script-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'data': 'FAIL',
        'unsafe-eval': 'FAIL',
        'unsafe-inline': 'FAIL',
        'unsafe-hashes': 'FAIL',
        'self': 'ALLOW',
        'nonce': 'ALLOW',
        'hash': 'ALLOW',
        'blob': 'ALLOW',
        'strict-dynamic': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(script_src, 'CHECK:PASS')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(script_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(script_src, rules, 'script-src')

    if show_allowed:
        print("\nAllowed values for script-src are: 'self', 'blob', (nonce), (hash), 'strict-dynamic'")

    # //script-src*
    # IF (script-src* exists) ->
    #   IF ("data" used as URL scheme): FAIL w/ error 'data URL scheme not allowed in script-src* directive'
    #   IF ('unsafe-eval' keyword used): FAIL w/ error 'unsafe-eval keyword not allowed in script-src* directive'
    #   IF ('unsafe-inline' keyword used): FAIL w/ error 'unsafe-inline keyword not allowed in script-src* directive'
    #   IF ('unsafe-hashes' keyword used): FAIL w/ error 'unsafe-hashes keyword not allowed in script-src* directive'
    #   IF (any other than keywords besides 'self', allow list, nonce, hash, 'strict-dynamic'): FAIL w/ error 'Only use Permitted Keywords for script-src* directive'
    # ELSE: PASS


def check_style_src(style_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "style-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'self': 'ALLOW',
        'nonce': 'ALLOW',
        'hash': 'ALLOW',
        'unsafe-inline': 'ALLOW',
        'unsafe-hashes': 'ALLOW',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(style_src, 'CHECK:PASS')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(style_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(style_src, rules, 'style-src')

    if show_allowed:
        print("\nAllowed values for script-src are: 'self', 'data', 'blob', (nonce), (hash), 'unsafe-inline', 'unsafe-hashes'")


    # //style-src*
    # IF (style-src exists) ->
    #   IF (any other than keywords besides 'self', allow list, nonce, hash, 'unsafe-inline', 'unsafe-hashes): FAIL w/ error 'Only use Permitted Keywords for style-src directive'
    # ELSE: PASS


def check_worker_src(worker_src: list):
    print("\n==============================================================================")
    print("\t\t\t Checking " + bcolors.OKBLUE + "worker-src" + bcolors.ENDC + " directive")
    print("==============================================================================")

    rules = {
        'none': 'PASS',
        'self': 'WARN',
        'nonce': 'WARN',
        'hash': 'WARN',
        'data': 'ALLOW',
        'blob': 'ALLOW'
    }

    # allowlist permitted
    allow_rules = prep_allowlist_for_check(worker_src, 'CHECK:WARN')
    rules.update(allow_rules)

    print("(Values: " + ", ".join(worker_src) + ")\n")

    # print("Rules: " + str(rules) + "\n")

    show_allowed = validation(worker_src, rules, 'worker-src')

    if show_allowed:
        print("\nAllowed values for worker-src are: 'none', 'self', 'data', 'blob', (nonce), (hash)")

    # //worker-src
    # IF (worker-src exists) ->
    #   IF (worker-src value set to 'none'): PASS
    #   ELSE IF ('self', allow list, nonce, hash): PASS w/ warning `alternative config detected, ensure config is required by application`
    #   ELSE (any other value than 'none', 'self', allow list, nonce, hash): FAIL w/ error `worker-src is improperly set`)
    # ELSE: PASS


def nonce_check(first_nonce: str, directive: str):
    # print("\nin check nonce")
    # print(first_nonce)
    passed = True

    print(first_nonce, end='')
    dots = '............................................'
    spacelen = 45 - (len(first_nonce))
    print(dots[0:spacelen], end='')

    if 'pw' not in globals():  # no proxy authen used
        resp2 = requests.get(url_host, verify=False)
    else:
        resp2 = requests.get(url_host, auth=HttpNtlmAuth('AD-ENT\\' + username.strip(), pw.strip()), verify=False,
                                allow_redirects=True)

    cspval = resp2.headers['Content-Security-Policy']
    cspdict = format_csp_str(cspval)
    # print("\n" + str(cspdict[directive]))

    for val in cspdict[directive]:
        if val.strip("'").startswith('nonce-'):
            # print(val.strip("'"))
            if val.strip("'") == first_nonce:
                passed = False
                print("[FAIL]: nonce value must change on each request")
                print("first: " + first_nonce + "\nsecond: " + val)
                return

    print(bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)

    # 1. url request with try/catch
    # 2. parse response looking for 'directive' param
    # 3. get nonce value - startwith 'nonce'
    # 4. compare nonce values
    # 5. print PASS/FAIL


def check_required_dirs(csp_dirs):
    # default-src, base-ui, form-action, frame-ancestors are required

    print("\n==============================================================================")
    print("\t \t \tChecking for required directives")
    print("==============================================================================")

    if "default-src" not in csp_dirs:
        print("default-src.................................." + bcolors.FAIL + "[FAIL]:" + bcolors.ENDC + " not found")
    else:
        print("default-src.................................." + bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)

    if "base-uri" not in csp_dirs:
        print("base-uri....................................." + bcolors.FAIL + "[FAIL]:" + bcolors.ENDC + " not found")
    else:
        print("base-uri....................................." + bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)

    if "form-action" not in csp_dirs:
        print("form-action.................................." + bcolors.FAIL + "[FAIL]:" + bcolors.ENDC + " not found")
    else:
        print("form-action.................................." + bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)

    if "frame-ancestors" not in csp_dirs:
        print("frame-ancestors.............................." + bcolors.FAIL + "[FAIL]:" + bcolors.ENDC + " not found")
    else:
        print("frame-ancestors.............................." + bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)

    # if required_present:
    #     print("\n \t-----> STATUS: " + bcolors.OKBLUE + "[PASS]" + bcolors.ENDC + " <-----\n")


def check_prohibited_dirs(csp_dirs):

    # check for dirs that must exist
    # plugin_types not allowed

    print("\n\n===============================================================================")
    print("\t \t \t Checking for prohibited directives")
    print("===============================================================================")

    if "plugin-types" in csp_dirs:
        print("plugin-types................................." + bcolors.FAIL + "[FAIL]:" + bcolors.ENDC + " not allowed")
    else:
        print("plugin-types................................." + bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)

    if "navigate-to" in csp_dirs:
        print("navigate-to.................................." + bcolors.FAIL + "[FAIL]:" + bcolors.ENDC + " not allowed")
    else:
        print("navigate-to.................................." + bcolors.OKGREEN + "[PASS]" + bcolors.ENDC)



def rollcall(csp_dict):
    # go through each and validate

    for csp_dir, csp_val in csp_dict.items():
        # func_str = "check_" + csp_dir.replace('-', '_') + '(csp_val)'
        func_str = "check_" + csp_dir.replace('-', '_')

        # print(func_str)
        if func_str in globals():
            function = globals()[func_str]
            function(csp_val)
            print('')
        else:  # the directive was not found
            # print("**** function not found for [" + func_str + "] ********")
            check_other(csp_dir, csp_val)
            print('')

        # print(csp_dir)
        # print("\t".join(csp_val))

def samples(which_sample: int):
    sample_list = [
        "Content-Security-Policy: default-src https: data: 'self' 'unsafe-inline' 'unsafe-eval' https://wellsofficeuat.ceo.wellsfargo.com https://wellsdocxuat.ceo.wellsfargo.com https://ceosvuat.ceo.wellsfargo.com https://wifpt-uat.wellsfargo.com https://wifpuat.wellsfargo.com https://ceomediauat.wf.com; report-uri https://wellsofficeuat.ceo.wellsfargo.com/ceopub/ceoa/csp.html; frame-ancestors https://ceomediauat.wf.com https://*.ceo.wellsfargo.com;",
        "Content-Security-Policy: default-src 'self' https://securedeliveryuat.wellsfargo.com https://lendingmanagement-uat.sec.wellsfargo.com https://commercialconnect-uat.sec.wellsfargo.com https://wcauat.sec.wellsfargo.com https://wcauat.wellsfargo.net https://uat.accesswca.com https://wcauat.wellsfargofunds.com https://wcauat.lcmatrix.com https://wcasit.sec.wellsfargo.com https://wellsofficeuat.ceo.wellsfargo.com https://ceosvuat.ceo.wellsfargo.com https://ceomobileuat.ceo.wellsfargo.com https://gpowuat.ceo.wellsfargo.com https://achgpuat.ceo.wellsfargo.com https://wellsofficeuat.wellsfargo.com https://ceosvuat.wellsfargo.com https://ceomobileuat.wellsfargo.com https://gpowuat.wellsfargo.com https://achgpuat.wellsfargo.com https://ceopyuat.ceo.wellsfargo.com; style-src 'self' https://securedeliveryuat.wellsfargo.com https://lendingmanagement-uat.sec.wellsfargo.com https://commercialconnect-uat.sec.wellsfargo.com https://wcauat.sec.wellsfargo.com https://wcauat.wellsfargo.net https://uat.accesswca.com https://wcauat.wellsfargofunds.com https://www.lcmatrixuat.com https://wcasit.sec.wellsfargo.com https://wellsofficeuat.ceo.wellsfargo.com https://ceosvuat.ceo.wellsfargo.com https://ceomobileuat.ceo.wellsfargo.com https://gpowuat.ceo.wellsfargo.com https://achgpuat.ceo.wellsfargo.com https://ceosvuat.wellsfargo.com https://ceomobileuat.wellsfargo.com https://gpowuat.wellsfargo.com https://achgpuat.wellsfargo.com https://ceopyuat.ceo.wellsfargo.com https://cdfconnect-dev.sec.wellsfargo.com:8443 https://cdfconnect-sit.sec.wellsfargo.com:8443 https://cdfconnect-uat.sec.wellsfargo.com https://cdfconnect-pfix.sec.wellsfargo.com:8443 'unsafe-inline'; script-src 'self' https://securedeliveryuat.wellsfargo.com https://lendingmanagement-uat.sec.wellsfargo.com https://commercialconnect-uat.sec.wellsfargo.com https://wcauat.sec.wellsfargo.com https://wcauat.wellsfargo.net https://uat.accesswca.com https://wcauat.wellsfargofunds.com https://wcauat.lcmatrix.com https://wcasit.sec.wellsfargo.com https://wellsofficeuat.ceo.wellsfargo.com https://ceosvuat.ceo.wellsfargo.com https://ceomobileuat.ceo.wellsfargo.com https://gpowuat.ceo.wellsfargo.com https://achgpuat.ceo.wellsfargo.com https://wellsofficeuat.wellsfargo.com https://ceosvuat.wellsfargo.com https://ceomobileuat.wellsfargo.com https://gpowuat.wellsfargo.com https://achgpuat.wellsfargo.com https://ceopyuat.ceo.wellsfargo.com https://cdfconnect-dev.sec.wellsfargo.com:8443 https://cdfconnect-sit.sec.wellsfargo.com:8443 https://cdfconnect-uat.sec.wellsfargo.com https://cdfconnect-pfix.sec.wellsfargo.com:8443 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self' https://securedeliveryuat.wellsfargo.com https://lendingmanagement-uat.sec.wellsfargo.com https://commercialconnect-uat.sec.wellsfargo.com https://wcauat.sec.wellsfargo.com https://wcauat.wellsfargo.net https://uat.accesswca.com https://wcauat.wellsfargofunds.com https://wcauat.lcmatrix.com https://wcasit.sec.wellsfargo.com https://wellsofficeuat.ceo.wellsfargo.com https://ceosvuat.ceo.wellsfargo.com https://ceomobileuat.ceo.wellsfargo.com https://gpowuat.ceo.wellsfargo.com https://achgpuat.ceo.wellsfargo.com https://wellsofficeuat.wellsfargo.com https://ceosvuat.wellsfargo.com https://ceomobileuat.wellsfargo.com https://gpowuat.wellsfargo.com https://achgpuat.wellsfargo.com https://ceopyuat.ceo.wellsfargo.com https://cdfconnect-dev.sec.wellsfargo.com:8443 https://cdfconnect-sit.sec.wellsfargo.com:8443 https://cdfconnect-uat.sec.wellsfargo.com https://cdfconnect-pfix.sec.wellsfargo.com:8443;",
        "Content-Security-Policy: default-src 'none';connect-src 'self' *.wellsfargo.com; object-src 'none'; base-uri 'none';style-src 'unsafe-inline' 'self' *.wellsfargo.com *.wf.com;img-src 'self' *.wellsfargo.com *.wf.com data:;script-src 'self' 'nonce-rszyhwmwdr' *.wellsfargo.com *.wellsfargo.com:* *wf.com;font-src data:;frame-src *.wellsfargo.com; frame-ancestors 'none'",
        "Content-Security-Policy: default-src 'self' *.wellsfargo.com *.wf.com;object-src 'none'; base-uri 'none';style-src 'unsafe-inline' 'self' *.wellsfargo.com *.wf.com;img-src 'self' *.wellsfargo.com *.wf.com data:;script-src 'self' *.wellsfargo.com *wf.com;frame-ancestors *.wellsfargo.com",
        "Content-Security-Policy: default-src 'self' *.wellsfargo.com *.wf.com;object-src 'none'; base-uri 'none';style-src 'unsafe-inline' 'self' *.wellsfargo.com *.wf.com;img-src 'self' *.wellsfargo.com *.wf.com data:;script-src 'self' *.wellsfargo.com *wf.com;frame-ancestors *.wellsfargo.com",
        "Content-Security-Policy: script-src 'self' http: 'unsafe-inline' 'unsafe-eval'",
        "Content-Security-Policy: default-src https: data: 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.wellsfargofunds.com; frame-ancestors 'self' *.wellsfargoassetmanagement.com",
        "Content-Security-Policy: script-src 'self' https://ceomediauat.wf.com 'unsafe-inline' 'unsafe-eval'; object-src 'self'",
        "Content-Security-Policy: default-src 'self' *.coremetrics.com 'unsafe-inline' 'unsafe-eval';",
        "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval' *.wf.com",
        "Content-Security-Policy: default-src https: 'unsafe-inline'; img-src https: data: 'unsafe-inline'; frame-ancestors 'self' *.wellsfargo.com; base-uri https: data:; object-src 'self'; font-src https: data:; script-src 'nonce-3e342037-c266-4561-8097-00d64cc6cac0' https: 'unsafe-inline' 'unsafe-eval'; report-uri https://ort.evetest.wellsfargo.com/reporting/csp"
        "default-src 'none'; form-action 'self' *.wellsfargo.com *.wellsfargo.com:*; prefetch-src 'self' *.wellsfargo.com *.wellsfargomedia.com; connect-src 'self' https://*.wellsfargo.com https://*.wellsfargo.com:* https://*.schemaapp.com https://*.rlcdn.com https://*.tiktok.com https://*.medallia.com https://*.kampyle.com https://*.adobedc.net https://www.google-analytics.com https://*.doubleclick.net https://*.maxymiser.net https://*.eum-appdynamics.com https://*.demdex.net https://www.sjwoe.com https://www.mczbf.com https://s.yimg.com https://bat.bing.com https://*.nod-glb.nuance.com https://resources.digital-cloud-prem.medallia.com https://www.knotch-cdn.com https://www.units.knotch.it https://*.knotch.it/; img-src 'self' data: https://*.wellsfargomedia.com https://*.wellsfargo.com https://*.wellsfargo.com:* https://*.wfinterface.com https://*.wfinterface.com:* https://*.analytics.yahoo.com https://*.everesttech.net https://*.ads.linkedin.com https://*.g.doubleclick.net https://*.google.com https://*.demdex.net https://*.nod-glb.nuance.com https://*.eum-appdynamics.com https://*.virtualearth.net https://*.maxymiser.net https://*.knotch.it https://www.facebook.com https://cx.atdmt.com https://analytics.twitter.com https://t.co https://track.linksynergy.com https://s.amazon-adsystem.com https://ct.pinterest.com https://trc.taboola.com https://www.linkedin.com https://p.adsymptotic.com https://products.gobankingrates.com https://bttrack.com https://b.videoamp.com https://fcmatch.youtube.com https://www.googleadservices.com https://2549153.fls.doubleclick.net https://ad.doubleclick.net https://www.google-analytics.com https://idsync.rlcdn.com https://s.amazon-adsystem.com https://resources.digital-cloud-prem.medallia.com https://udc-neb.kampyle.com https://wellsfargoprod.prod.fire.glass https://s-a.innovid.com https://bat.bing.com https://www.knotch-cdn.com https://*.mworld.com; object-src 'self' https://*.wellsfargo.com https://*.wellsfargo.com:* https://*.wfinterface.com https://*.wfinterface.com:*; child-src 'self' *.wellsfargo.com *.wellsfargo.com:* *.wfinterface.com *.wfinterface.com:* https://*.demdex.net https://*.nod-glb.nuance.com https://2549153.fls.doubleclick.net https://*.advanced-web-analytics.com https://www.units.knotch.it; font-src 'self' data: https://*.wellsfargomedia.com https://*.wellsfargo.com https://*.wellsfargo.com:*; style-src 'self' 'unsafe-inline' *.wellsfargo.com *.wellsfargo.com:* https://*.wfinterface.com https://*.wfinterface.com:* https://*.nod-glb.nuance.com; script-src 'nonce-580b91a0-323a-4fe8-b53e-51b1916acf55' 'self' *.wellsfargo.com *.wellsfargo.com:* *.wfinterface.com *.wfinterface.com:* https://cdn.schemaapp.com https://*.tiktok.com https://*.maxymiser.net https://bat.bing.com https://www.clarity.ms https://snap.licdn.com https://*.ads.linkedin.com https://www.linkedin.com https://s.yimg.com https://sp.analytics.yahoo.com https://p.adsymptotic.com https://*.nod-glb.nuance.com https://www.knotch-cdn.com;media-src 'self' *.wellsfargo.com *.wellsfargomedia.com; frame-ancestors 'self' *.wellsfargo.com; base-uri 'none'; report-uri https://ort.evetest.wellsfargo.com/securereporting/reporting/v1/csp"
    ]

    return sample_list[which_sample]


def print_header():
    version = "CSPV v1.0.1"
    print("\n*******************************************************************")
    print("***\t\t\t\t\t\t\t\t***")
    print("***", end='')
    print(bcolors.OKGREEN + "\t\t\t DTI CSP Validator" + bcolors.ENDC, end='')
    print("\t\t\t***")
    print("***", end='')
    print(bcolors.OKGREEN + "\t\t\t   (" + version + ")" + bcolors.ENDC, end='')
    print("\t\t\t***")
    print("***\t\tContact DTI Service Desk for Support\t\t***")
    print("***\t\t\t\t\t\t\t\t***")
    print("*******************************************************************")
    print("https://wim-jira.wellsfargo.com/servicedesk/customer/portal/4803/create/14739\n")

    print(text2art(version))

# ========== Main =========
# Three States: Pass / Fail / Warn
# logging.basicConfig(level=logging.DEBUG)


def main():
    global url_passed
    global url_host

    print_header()

    inputstr = get_input()
    cspdict = None
    # cspstr = samples(10)

    # Check for URL
    if inputstr.startswith("http:") or inputstr.startswith("https:"):
        url_passed = True
        url_host = inputstr.strip()

        cspstr = process_url(inputstr.strip())
        if cspstr is not None:
            print(cspstr + "\n")
            cspdict = format_csp_str(cspstr)

    else:  # process as CSP string
        url_passed = False
        cspdict = format_csp_str(inputstr.strip())

    # Process the CSP
    check_required_dirs(cspdict.keys())
    check_prohibited_dirs(cspdict.keys())
    rollcall(cspdict)
    # print(cspdict.keys())


# main function
if __name__ == '__main__':
    main()
