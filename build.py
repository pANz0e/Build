# -- coding: utf-8 --**
import nmap, os, json, time
from Wappalyzer import Wappalyzer, WebPage

nma2 = nmap.PortScannerAsync()

os.environ['NO_PROXY'] = 'baidu.com'


# def get_service_app(ip, protocol, port):
#     except_list = ["Windows Server", "CentOS", "Ubuntu", "openSSL", "WordPress", "LiteSpeed", "Jetty", "Java",
#                    "Node.js", "Express", "Microsoft ASP.NET", "PHP", "Microsoft HTTPAPI", "Apache", "IIS", "Nginx",
#                    "OpenResty", "Debian"]
#     service_dic = {}
#     service_list = []
#     webpage = None
#     try:
#         if protocol == "https":
#             webpage = WebPage.new_from_url(url='https://'+ip+':'+str(port), verify=False)
#         elif protocol == "http":
#             webpage = WebPage.new_from_url(url='http://'+ip+':'+str(port), verify=False)
#         wappalyzer = Wappalyzer.latest()
#         service_dic = wappalyzer.analyze_with_versions_and_categories(webpage)
#     except:
#          print("error!")
#          service_dic = {}
#     if not service_dic:
#         for k, v in service_dic.items():
#             if k in except_list:
#                 if k == "Windows Server":
#                     if not v["versions"]:
#                         service_list.append("Windows/N")
#                     else:
#                         service_list.append("Windows/" + v["versions"][0])
#                     if k == "Microsoft ASP.NET":
#                         if not v["versions"]:
#                             service_list.append("ASP.NET/N")
#                         else:
#                             service_list.append("ASP.NET/" + v["versions"][0])
#                 if not v["versions"]:
#                     service_list.append(k + "/N")
#                 else:
#                     service_list.append(k + "/" + v["versions"][0])
#     return service_list


def deal_service_app(service_dic):
    except_list = ["Windows Server", "CentOS", "Ubuntu", "openSSL", "WordPress", "LiteSpeed", "Jetty", "Java",
                   "Node.js", "Express", "Microsoft ASP.NET", "PHP", "Microsoft HTTPAPI", "Apache", "IIS", "Nginx",
                   "OpenResty", "Debian"]
    service_list = []
    if not service_dic:
        for k, v in service_dic.items():
            if k in except_list:
                if k == "Windows Server":
                    if not v["versions"]:
                        service_list.append("Windows/N")
                    else:
                        service_list.append("Windows/" + v["versions"][0])
                    if k == "Microsoft ASP.NET":
                        if not v["versions"]:
                            service_list.append("ASP.NET/N")
                        else:
                            service_list.append("ASP.NET/" + v["versions"][0])
                if not v["versions"]:
                    service_list.append(k + "/N")
                else:
                    service_list.append(k + "/" + v["versions"][0])
    return service_list


# get one port's info
def get_portinfo(ip, port, port_info):
    pro_list = ['ssh', 'http', 'https', 'rtsp', 'ftp', 'telnet', 'amqp', 'mongodb', 'redis', 'mysql']
    protocol = None
    if port_info["name"] in pro_list:
        protocol = port_info["name"]
    result = {"port": port, "protocol": protocol}
    # protocol = result["protocol"]
    service_list = []
    if port_info["product"]:
        if port_info["version"]:
            service_list.append(f'{port_info["product"].split(" ")[0]}/{port_info["version"]}')
        else:
            service_list.append(f'{port_info["product"].split(" ")[0]}/N')
    result["service_app"] = service_list
    return result


# get deviceinfo
def get_deviceinfo(scan_result):
    info_list = []
    pfsense_str = ["freebsd:freebsd:11.2", "freebsd:freebsd:7"]
    device_list = ["hikvision", "Hikvision", "HIKVISION", "Dahua", "dahua", "cisco", "Cisco", "Synology", "synology",
                   "pfSense"]
    device_type = {"hikvision": "Webcam", "Hikvision": "Webcam", "HIKVISION": "Webcam", "Dahua": "Webcam",
                   "dahua": "Webcam", "cisco": "switch", "Cisco": "switch", "Synology": "Nas", "synology": "Nas",
                   "pfSense": "Nas"}
    scan_str = str(scan_result)
    for i in device_list:
        if i in scan_str:
            info_list.append(device_type[i] + "/" + i)
    for i in pfsense_str:
        if i in scan_str:
            info_list.append("firewall/pfsense")
    return info_list


def to_json(ip_dic):
    new_data = ip_dic
    file = open("test.json", 'r')
    length = len(file.read())
    file.close()
    with open("test.json", "r") as json_f:
        if length > 0:
            old_data = json.load(json_f)
        else:
            old_data = {}
        old_data.update(new_data)
    with open("test.json", "w") as json_f:
        json.dump(old_data, json_f, indent=4)


def callback_result(host, scan_result):
    print('------------------')
    print(host, scan_result)
    if not scan_result["scan"]:
        return
    scan_result = scan_result["scan"][host]
    services_list = []
    ipinfo_dic = {}
    pre_port = {}
    if scan_result["tcp"]:
        for k, v in scan_result["tcp"].items():
            if v['state'] == 'open':
                pre_port = get_portinfo(host, k, v)
                services_list.append(pre_port)
                # url = ""
                # if v["name"] == "http":
                #     url = "http://"+host+":"+str(k)
                # if v["name"] == "https":
                #     url = "https://" + host + ":" + str(k)
                # if url:
                #     webpage = WebPage.new_from_url(url=url, verify=False)
                #     wappalyzer = Wappalyzer.latest()
                #     service_dic = wappalyzer.analyze_with_versions_and_categories(webpage)
                #     wapp_list = deal_service_app(service_dic)
                #     services_list = services_list+wapp_list
    ipinfo_dic["services"] = services_list
    device_info = get_deviceinfo(scan_result)
    ipinfo_dic["deviceinfo"] = device_info
    ipinfo_dic["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    ip_result = {host: ipinfo_dic}
    print(ip_result)
    to_json(ip_result)
    print(ip_result)
    services_list = []
    port_dic = {}


def reading(host, scan_result):
    print(host, scan_result)
    webpage = WebPage.new_from_url(url='https://159.65.92.42:443', verify=False)
    wappalyzer = Wappalyzer.latest()
    service_dic = wappalyzer.analyze_with_versions_and_categories(webpage)
    print(service_dic)


def Scan(ip_CIDR):
    nma = nmap.PortScannerAsync()
    nma.scan(hosts=ip_CIDR, arguments='-A', callback=callback_result)
    while nma.still_scanning():
        nma.wait(2)


if __name__ == "__main__":
    # nma.scan(hosts='113.30.191.229', arguments='-A', callback=reading)
    # while nma.still_scanning():
    #     nma.wait(2)
    with open("ip_CIDR.txt") as f:
        hosts = f.readlines()
        for i in hosts:
            Scan(i.strip())
