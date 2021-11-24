import requests
import json
from lxml import html

class SFRBox:
    def __init__(self, ip="192.168.0.1"):
        self.ip = ip
    
    def _get_SessionKey(self, url):
        r = requests.get(url)
        if r.status_code != 200:
            return -1
        sessionKeyStartIndex = r.text.find("var SessionKey") + 18
        sessionKeyEndIndex = r.text[sessionKeyStartIndex:].find("';")
        sessionKey = r.text[sessionKeyStartIndex:sessionKeyEndIndex+sessionKeyStartIndex]
        return sessionKey

    def authenticate(self, password, username="admin"):
        sessionKey = self._get_SessionKey("http://192.168.0.1/login.html")
        if sessionKey == -1:
            return -1
        r = requests.post("http://192.168.0.1/goform/login?sessionKey={}".format(sessionKey),
                          data={"loginUsername": username, "loginPassword": password, "envoyer": "OK"},
                          allow_redirects=False)
        if r.status_code != 302 or r.headers['Location'] != "http://192.168.0.1/config.html":
            return -1
        return 0

    def logout(self):
        r = requests.get("http://192.168.0.1/logout.html")
        if r.status_code != 200:
            return -1
        return 0

    def reboot_gateway(self):
        sessionKey = self._get_SessionKey("http://192.168.0.1/config.html")
        if sessionKey == -1:
            return -1
        r = requests.post("http://192.168.0.1/goform/WebUiOnlyReboot?sessionKey={}".format(sessionKey),
                          data={},
                          headers={"Referer": "http://192.168.0.1/config.html", "Origin": "http://192.168.0.1"})
        if r.status_code != 200:
            return -1
        return 0

    #def led(self, status=True):
    #    sessionKey = self._get_SessionKey("http://192.168.0.1/config.html")
    #    if sessionKey == -1:
    #        return -1
    #    r = requests.post("http://192.168.0.1/goform/RgManagementOfLED?sessionKey={}".format(sessionKey),
    #                      data={"immediateLED": 0 if status else 1, "differedLED": 0},
    #                      allow_redirects=False, headers={"Referer": "http://192.168.0.1/config.html", "Origin": "http://192.168.0.1"})

    def get_DHCP_reserved_leases(self):
        r = requests.get("http://192.168.0.1/reseau-pb1-iplan.html")
        tree = html.fromstring(r.content)
        i = 1
        reserved_leases = []
        element = tree.xpath("//input[@name='DhcpReservedDelete{}']".format(i))
        while len(element) != 0:
            mac = element[0].getparent().getparent().getchildren()[-2].text
            ip = element[0].getparent().getparent().getchildren()[-1].text
            reserved_leases.append((mac, ip))
            i += 1
            element = tree.xpath("//input[@name='DhcpReservedDelete{}']".format(i))
        return reserved_leases

    def del_DHCP_reserved_lease(self, reserved_lease, index):
        if index >= len(reserved_lease) or index < 0:
            return -1
        sessionKey = self._get_SessionKey("http://192.168.0.1/reseau-pb1-iplan.html")
        if sessionKey == -1:
            return -1
        r = requests.post("http://192.168.0.1/goform/WebUiRgLanDhcpReserveIp?sessionKey={}".format(sessionKey),
                          data={"DhcpReservedDelete{}".format(index+1): reserved_lease[index][0], "DhcpReservedIpNum": len(reserved_lease), "RgLanRemoveEntry": "Supprimer"},
                          allow_redirects=False,
                          headers={"Referer": "http://192.168.0.1/reseau-pb1-iplan.html", "Origin": "http://192.168.0.1"})
        if r.status_code != 302 or r.headers['Location'] != "http://192.168.0.1/reseau-pb1-iplan.html":
            return -1
        return 0

    def add_DHCP_reserved_lease(self, mac, ip):
        sessionKey = self._get_SessionKey("http://192.168.0.1/reseau-pb1-iplan.html")
        if sessionKey == -1:
            return -1
        data = {}
        i = 0
        for mac_part in mac.split(':'):
            data["RgLanReserveMac{}".format(i)] = mac_part
            i += 1
        data["RgLanReserveIp3"] = ip.split('.')[3]
        data["RgLanAddEntry"] = "Ajouter"
        r = requests.post("http://192.168.0.1/goform/WebUiRgLanDhcpReserveIp?sessionKey={}".format(sessionKey),
                          data=data,
                          allow_redirects=False,
                          headers={"Referer": "http://192.168.0.1/reseau-pb1-iplan.html", "Origin": "http://192.168.0.1"})
        if r.status_code != 302 or r.headers['Location'] != "http://192.168.0.1/reseau-pb1-iplan.html":
            return -1
        return 0

    def get_dyndns_config(self):
        service_codes = ["", "www.DynDNS.com", "www.dtDNS.com", "www.noip.com", "www.opendns.com"]
        r = requests.get("http://192.168.0.1/reseau-pb4-dydns.html")
        tree = html.fromstring(r.content)
        ddns_service_start_index = r.text.find('var ddns_config') + 19
        ddns_service_code = r.text[ddns_service_start_index:ddns_service_start_index+1]
        ddns_service = service_codes[int(ddns_service_code)]
        ddns_enabled = r.text[r.text.find('"SELECTED" == "SELECTED"'):].find("true") != -1
        ddns_hostname = tree.xpath("//input[@name='RgDDnsHostName']")[0].value
        ddns_username = tree.xpath("//input[@name='RgDDnsUserName']")[0].value
        ddns_password = tree.xpath("//input[@name='RgDDnsPassword']")[0].value
        ddns_status_start_index = r.text.find('RgDDnsStatus").innerHTML') + 26
        ddns_status_end_index = ddns_status_start_index + r.text[ddns_status_start_index:].find('";')
        ddns_status = r.text[ddns_status_start_index:ddns_status_end_index]
        return {"enabled": ddns_enabled, "service": ddns_service, "hostname": ddns_hostname, "username": ddns_username, "password": ddns_password, "status": ddns_status}

    def set_dyndns_config(self, dyndns_config):
        service_codes = ["", "www.DynDNS.com", "www.dtDNS.com", "www.noip.com", "www.opendns.com"]
        sessionKey = self._get_SessionKey("http://192.168.0.1/reseau-pb4-dydns.html")
        if sessionKey == -1:
            return -1
        r = requests.post("http://192.168.0.1/goform/WebUiDDns?sessionKey={}".format(sessionKey),
                          data={"RgDDnsListDynDNSSelected": "1" if dyndns_config["enabled"] else "0", "RgDdnsService": dyndns_config["service"],
                                "RgDDnsHostName": dyndns_config["hostname"], "RgDDnsUserName": dyndns_config["username"], "RgDDnsPassword": dyndns_config["password"]},
                          allow_redirects=False,
                          headers={"Referer": "http://192.168.0.1/reseau-pb4-dydns.html", "Origin": "http://192.168.0.1"})
        if r.status_code != 302 or r.headers['Location'] != "http://192.168.0.1/reseau-pb4-dydns.html":
            return -1
        return 0

    def get_port_forwarding_rules(self):
        r = requests.get("http://192.168.0.1/reseau-pa8-transfertdeports.html")
        port_frwd_list_start_index = r.text.find('aspString="') + 11
        port_frwd_list_end_index = port_frwd_list_start_index + r.text[port_frwd_list_start_index:].find('";')
        port_frwd_list = r.text[port_frwd_list_start_index:port_frwd_list_end_index]
        tree = html.fromstring(port_frwd_list)
        elements = tree.getchildren()
        port_forwarding_list = []
        num = 0
        while len(elements) != 0:
            name = elements.pop(0).text
            ip = elements.pop(0).text
            ext_port = elements.pop(0).text
            int_port = elements.pop(0).text
            proto = elements.pop(0).text
            if proto == '3':
                proto = "UDP"
            elif proto == '4':
                proto = "TCP"
            else:
                proto = "Both"
            tenable = elements.pop(0).text
            num += 1
            if name is not None:
                port_forwarding_list.append({"num": num, "name": name, "ip": ip, "external_port": ext_port, "internal_port": int_port, "protocol": proto})
        return port_forwarding_list

    def add_port_forwarding_rule(self, num, name, external_port, internal_port, protocol, dest_ip):
        sessionKey = self._get_SessionKey("http://192.168.0.1/reseau-pa8-transfertdeports.html")
        if sessionKey == -1:
            return -1
        data = {"RgPortForwardName0{}".format(num): name, "RgPortForwardPortStart0{}".format(num): external_port, "RgPortForwardPortEnd0{}".format(num): internal_port,
                "RgPortForwardEnable0{}".format(num): "1", "RgPortForwardIpAddr030{}".format(num): dest_ip, "RgPortForwardConfig": "Add", "RgPortForwardAction": "1"}
        if protocol == "TCP":
            data["RgPortForwardProtocol0{}".format(num)] = "4"
        elif protocol == "UDP":
            data["RgPortForwardProtocol0{}".format(num)] = "3"
        else:
            data["RgPortForwardProtocol0{}".format(num)] = "254"
        r = requests.post("http://192.168.0.1/goform/WebUiRgPortForward?sessionKey={}".format(sessionKey),
                          data=data,
                          allow_redirects=False,
                          headers={"Referer": "http://192.168.0.1/reseau-pa8-transfertdeports.html", "Origin": "http://192.168.0.1"})
        if r.status_code != 302 or r.headers['Location'] != "http://192.168.0.1/reseau-pa8-transfertdeports.html":
            return -1
        return 0

    def del_port_forwarding_rule(self, num):
        sessionKey = self._get_SessionKey("http://192.168.0.1/reseau-pa8-transfertdeports.html")
        if sessionKey == -1:
            return -1
        data = {"RgPortForwardEnable0{}".format(num): "0", "RgPortForwardConfig": "Delete", "RgPortForwardAction": "2"}
        r = requests.post("http://192.168.0.1/goform/WebUiRgPortForward?sessionKey={}".format(sessionKey),
                          data=data,
                          allow_redirects=False,
                          headers={"Referer": "http://192.168.0.1/reseau-pa8-transfertdeports.html", "Origin": "http://192.168.0.1"})
        if r.status_code != 302 or r.headers['Location'] != "http://192.168.0.1/reseau-pa8-transfertdeports.html":
            return -1
        return 0

    def get_wifi_config(self):
        r = requests.get("http://192.168.0.1/wifi.html")
        wifi_infos_start_index = r.text.find('var wifi52Infos') + 18
        wifi_infos_end_index = wifi_infos_start_index + r.text[wifi_infos_start_index:].find("};") + 1
        wifi_infos = json.loads(r.text[wifi_infos_start_index:wifi_infos_end_index])
        wifi_config_2ghz = {"SSID": wifi_infos["s_primSSID2G"],
                            "password": wifi_infos["s_2GSecurityKey"],
                            "enabled": wifi_infos["i_enable2GService"] == 1,
                            "SSID_broadcast": wifi_infos["i_enable2GBroadcast"] == 1}
        wifi_config_5ghz = {"SSID": wifi_infos["s_primSSID5G"],
                            "password": wifi_infos["s_5GSecurityKey"],
                            "enabled": wifi_infos["i_enable5GService"] == 1,
                            "SSID_broadcast": wifi_infos["i_enable5GBroadcast"] == 1}
        return {"2ghz": wifi_config_2ghz, "5ghz": wifi_config_5ghz}

    def set_wifi_config(self, wifi_config):
        sessionKey = self._get_SessionKey("http://192.168.0.1/wifi.html")
        if sessionKey == -1:
            return -1
        data = {"RgWiFi2GServiceChk": "1" if wifi_config["2ghz"]["enabled"] else "0", "RgWiFi2GBroadcastChk": "1" if wifi_config["2ghz"]["SSID_broadcast"] else "0",
                "RgWiFi2GPrimSSID": wifi_config["2ghz"]["SSID"], "2GRegulatoryMode": "2", "RgWiFibgnMode": "1", "RgWiFi2GBandWidth": "1", "RgWiFi2GChannel": "0",
                "RgWiFi24G_OBSS_Coex": "1", "RgDtimInterval_24g": "1", "RgWiFi5GServiceChk": "1" if wifi_config["5ghz"]["enabled"] else "0",
                "RgWiFi5GBroadcastChk": "1" if wifi_config["5ghz"]["SSID_broadcast"] else "0", "RgWiFi5GPrimSSID": wifi_config["5ghz"]["SSID"], "5GRegulatoryMode": "0",
                "RgWiFi5GBandWidth": "3", "RgWiFi5GChannel": "0", "RgWiFi5G_DFS": "0", "RgDtimInterval_5g": "1", "PrimSecurity2GRadio": "3", "PrimSecurity5GRadio": "3",
                "security2GKey": wifi_config["2ghz"]["password"], "security2GWep": "00000000000000000000000001", "security5GKey": wifi_config["5ghz"]["password"]}
        r = requests.post("http://192.168.0.1/goform/WebUiRgWiFi52Config?sessionKey={}".format(sessionKey),
                          data=data,
                          allow_redirects=False,
                          headers={"Referer": "http://192.168.0.1/wifi.html", "Origin": "http://192.168.0.1"})
        if r.status_code != 302 or r.headers['Location'] != "http://192.168.0.1/wifi.html":
            return -1
        return 0

    def get_wifi_guest_config(self):
        r = requests.get("http://192.168.0.1/wifi-pa2-reseauinvite.html")
        wifi_guest_config = {}
        tree = html.fromstring(r.content)
        wifi_guest_config["password"] = tree.xpath("//input[@name='PreSharedKey']")[0].value
        wifi_guest_config["SSID"] = tree.xpath("//input[@name='RgWiFiGNName']")[0].value
        wifi_guest_config["enabled"] = "checked" in tree.xpath("//input[@id='RgWiFiGNEnableOption']")[0].attrib
        return wifi_guest_config

    def set_wifi_guest_config(self, wifi_guest_config):
        sessionKey = self._get_SessionKey("http://192.168.0.1/wifi-pa2-reseauinvite.html")
        if sessionKey == -1:
            return -1
        data = {"RgWiFiGNEnableOptionValue": "1" if wifi_guest_config["enabled"] else "0", "RgWiFiGNESSIDBroadcastChkBoxValue": "1", "GNSecurityRadio": "3",
                "GNSecurityRadioValue": "3", "WiFi80211NMode": "1", "PreSharedKey": wifi_guest_config["password"], "Wep128NetworkKey1": "00000000000000000000000001",
                "GNScheduleRadioValue": "0", "RgWiFiGNDhcpServerSupport": "1", "RgWiFiGNDhcpServerIpAddr": "192.168.2.1", "RgWiFiGNDhcpStartIpAddr": "192.168.2.10",
                "RgWiFiGNDhcpEndIpAddr": "192.168.2.99", "RgWiFiGNDhcpLeaseDuration": "86400", "RgWiFiGNApplyConfig": "Apply"}
        if wifi_guest_config["enabled"]:
            data["RgWiFiGNName"] = wifi_guest_config["SSID"]
            data["GNScheduleRadio"] = "0"
        r = requests.post("http://192.168.0.1/goform/WebUiRgWiFiGNConfig?sessionKey={}".format(sessionKey),
                          data=data,
                          allow_redirects=False,
                          headers={"Referer": "http://192.168.0.1/wifi-pa2-reseauinvite.html", "Origin": "http://192.168.0.1"})
        if r.status_code != 302 or r.headers['Location'] != "http://192.168.0.1/wifi-pa2-reseauinvite.html":
            return -1
        return 0

    def get_mac_filtering_config(self):
        pass

if "__name__" == "__main__":
    box = SFRBox()
    box.authenticate(password="secret")
    prt_frw_rules = box.get_port_forwarding_rules()
    print(prt_frw_rules)
    box.logout()

