
from urllib.parse import urlparse


USER_AGENT = {"User-Agent" : "Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/8.0"}

ADDR_LOCALHOST = ("0",
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
                    "localhost:4443")


def good_code(code, text):
    good = "[+]"
    if code >= 400 and code <= 526:
        good = "[-]"
    return good + text


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
    if data:
        for pair in data.split(","):
            key, value = pair.split("=")
            cookie[key] = value
    return cookie

