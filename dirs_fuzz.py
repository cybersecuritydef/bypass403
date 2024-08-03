import itertools
import requests
import getopt
import sys
import common
import urllib3


urllib3.disable_warnings()


def help():
    print("\t-u URL, --url=URL\tscan url")
    print("\t-w, --wordlist=      \twordlist dict")
    print("\t--hcode=         \tHidden code separate [,]")
    print("\t--hsize=         \tHidden length content separate [,]")
    print("\t--htext=         \tHidden text separate [,]")
    print("\t-c, --cookie     \tset cookie separate [,]")
    print("EXAMPLES: ")    
    print("\tlfi_fuzz.py -u http://example.com -w rockyou.txt")
    print("\tlfi_fuzz.py --url=http://example.com --wordlist=rockyou.txt")
    print("\tlfi_fuzz.py --url=http://example.com --wordlist=rockyou.txt --hcode=404,502")
    print("\tlfi_fuzz.py --url=http://example.com --wordlist=rockyou.txt --hsize=612")
    print("\tlfi_fuzz.py -u http://example.com -w --wordlist=rockyou.txt --cookie session=test,path=/")

    
def dirs(url, payload, hcode=(), hsize=(), htext=(), cookie=None):
    for p in payload:
        resp = requests.get(f"{url}{p}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))


def readfile(filename):
    payloads = []
    with open(filename, "r") as f:
        for line in f:
            payloads.append(line.strip())
    return payloads

        
def main():
    url = None
    wordlist = None
    cookie = None
    hcode = ()
    hsize = ()
    htext = ()
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:w:d:c:", ["url=", "wordlist=", "hcode=", "hsize=", "htext=", "cookie="])
        for opt, arg in opts:            
            if opt in ("-u", "--url"):                    
                url = arg
            elif opt in ("-w", "--wordlist"):                    
                wordlist = arg
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
        if url is not None and wordlist is not None:
            print("\n----------------")
            print("[!] DIRS fuzzing")
            print("----------------\n")
            url = common.parse_url(url)
            wordlist = readfile(wordlist)
            print(f"[*] Count words: {len(wordlist)}\n")
            dirs(url, wordlist, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie)
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
