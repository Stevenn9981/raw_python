import os,re
import urllib.request
import sys

# def getLocation(ip):
#     response = urllib.request.urlopen("http://ip.tool.chinaz.com/" + ip)
#     html = response.read().decode("utf-8")
#     matchObj2 = re.search(r'''<p class="WhwtdWrap bor-b1s col-gray03">\s*<span class="Whwtdhalf w15-0">.*</span>\s*<span class="Whwtdhalf w15-0">.*</span>\s*<span class="Whwtdhalf w15-0">.*</span>\s*<span class="Whwtdhalf w50-0">(.*)</span>\s*''', html)
#     if matchObj2:
#         location = matchObj2.group(1)
#         return location
#     else:
#         return None

def getIp(line):
    matchObj = re.search(r'\d*\.\d*\.\d*\.\d*', line)
    if matchObj:
        ip = matchObj.group()
        return ip
    else:
        return None

if __name__ == '__main__':
    if len(sys.argv) > 1:
        print("正在调用本地路由跟踪，请稍等")
        result = os.popen('mtr ' + sys.argv[1])
        res = result.read()
        for line in res.splitlines():
            ip = getIp(line)
            if ip:
                line += " " # + getLocation(ip)
            print(line)
    else:
        print("参数不完整，请传入ip地址")