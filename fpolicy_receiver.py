import socket
from datetime import datetime
import xml.dom.minidom as ET
import time
import re
import requests
import json

SEP = ","
black_list = [b"\n", b"\x00", b"\x95", b"\x01", b'<?xml version="1.0"?>']
f = open("log.txt", "a")
date = str(datetime.now())
f.write("starting log at: " + date[:date.rfind(".")] + "\n")
sock = socket.socket()
sock.bind(("", 6789))
sock.listen(1)
conn, ip = sock.accept()
f.write("connected: " + str(ip[0]) + str(ip[1]) + "\n")


def log(msg):
    date = str(datetime.now())
    f.write(date[:date.rfind(".")] + " - " + msg + "\n")

def wrong():
    log("bad request from: " + str(ip[0]) + str(ip[1]) + SEP)
    print("bad request from: " + str(ip[0]) + str(ip[1]) + SEP)


def ban(string_data):
    for i in black_list:
        string_data = string_data.replace(i, b"")
    return string_data


send = lambda x: requests.post("http://localhost:9428/insert/jsonline?_stream_fields=stream&_time_field=date&_msg_field=log._msg", json=x, headers={'Content-Type': 'application/json; charset=utf-8'})

while True:
    sock.settimeout(0.1)
    data = conn.recv(32768)
    if re.search(rb">KEEP_ALIVE<", data):
        continue
    if not data:
        break
    if re.search(rb'>NEGO_REQ<', data):
        try:
            root = ET.parseString(('<?xml version="1.0"?><root>' + str(data)[6:-1].replace('<?xml version="1.0"?>', '') + '</root>').encode('utf-8'))
            UUID = root.getElementsByTagName('VsUUID')[0].firstChild.data
            SessionId = root.getElementsByTagName('SessionId')[0].firstChild.data
            PolicyName = root.getElementsByTagName('PolicyName')[0].firstChild.data
            ContentLen = int(root.getElementsByTagName('ContentLen')[0].firstChild.data)
            new_len = str(len(b'<?xml version="1.0"?><HandshakeResp><VsUUID>' + bytes(UUID, "utf-8") + b'</VsUUID><PolicyName>' + bytes(PolicyName, "utf-8") + b'</PolicyName><SessionId>' + bytes(SessionId, "utf-8") + b'</SessionId><ProtVersion>1.0</ProtVersion></HandshakeResp>\x00') - 1)
            log("NEGO_REQ:UUID:{1}{0}SessionId:{2}{0}PolicyName:{3}".format(SEP, UUID, SessionId, PolicyName))
            print('\033[92mNEGO_REQ{0}UUID:{1}{0}SessionId:{2}{0}PolicyName:{3}\033[0m'.format(SEP, UUID, SessionId, PolicyName))
            conn.send(b"\x22\x00\x00\x01" + bytes([(int(new_len) - 129) % 256]) + b"\x22" + b'<?xml version="1.0"?><Header><NotfType>NEGO_RESP</NotfType><ContentLen>' + bytes(new_len, "utf-8") + b'</ContentLen><DataFormat>XML</DataFormat></Header>' + b'\x0a\x0a<?xml version="1.0"?><HandshakeResp><VsUUID>' + bytes(UUID, "utf-8") + b'</VsUUID><PolicyName>' + bytes(PolicyName, "utf-8") + b'</PolicyName><SessionId>' + bytes(SessionId, "utf-8") + b'</SessionId><ProtVersion>1.0</ProtVersion></HandshakeResp>\x00')
        except:
            wrong()
    elif re.search(rb">SCREEN_REQ<", data):
        data = re.sub(b'\x00\x22\x00\x00\x04.', b'', data[6:-1])
        #root = ET.parseString(('<?xml version="1.0"?><root>' + str(data,'utf-8')[6:-1].replace('<?xml version="1.0"?>', '') + '</root>').encode('utf-8'))
        root = ET.parseString(('<?xml version="1.0"?><root>' + str(data,'utf-8').replace('<?xml version="1.0"?>', '') + '</root>').encode('utf-8'))
        OpType = root.getElementsByTagName("ReqType")[0].firstChild.data
        WinSid = root.getElementsByTagName("WinSid")[0].firstChild.data
        UnixUid = root.getElementsByTagName("UnixUid")[0].firstChild.data
        RdLength = "none"
        WrLength = "none"
        PathName = root.getElementsByTagName("PathName")[0].firstChild.data[2:]
        try:
            PathName = root.getElementsByTagName("TargetAccessPath")[0].getElementsByTagName("PathName")[0].firstChild.data[2:]
        except Exception as e:
            print("Error: {}".format(e))
        try:
            RdLength = root.getElementsByTagName("RdLength")[0].firstChild.data
        except Exception as e:
            print("Error: {}".format(e))
        try:
            WrLength = root.getElementsByTagName("WrLength")[0].firstChild.data
        except Exception as e:
            print("Error: {}".format(e))
        DisplayPath = root.getElementsByTagName("DisplayPath")[0].firstChild.data.replace("\\\\", '\\')
        ip_addr = root.getElementsByTagName("ClientIp")[0].firstChild.data
        size = root.getElementsByTagName("FileSize")[0].firstChild.data
        ren_new_name = root.getElementsByTagName("PathName")[-1].firstChild.data
        print("\033[31mReqType:{1}{0}WinSid:{2}{0}UnixUid:{3}{0}PathName:{4}{0}DisplayPath:{5}{6}{7}\033[0m".format(SEP, OpType, WinSid, UnixUid, PathName, DisplayPath, SEP + "ReadLength:" + RdLength if RdLength != "none" else "", SEP + "WriteLength:" + WrLength if WrLength != "none" else ""))
        log("ReqType:{1}{0}WinSid:{2}{0}UnixUid:{3}{0}PathName:{4}{0}DisplayPath:{5}{6}{7}".format(SEP, OpType, WinSid, UnixUid, PathName, DisplayPath, SEP + "ReadLength:" + RdLength if RdLength != "none" else "", SEP + "WriteLength:" + WrLength if WrLength != "none" else ""))
        js = {}
        js["date"] = "0"
        js["stream"] = "dag_netapp"
        if "REN" not in OpType and "SMB_WR" not in OpType and "SMB_RD" not in OpType:
            j = {"_msg": "{0} {1} {2}".format(ip_addr, OpType, DisplayPath), "operation": OpType, "client_ip": ip_addr, "sid": WinSid, "size": size, "path": DisplayPath}
        elif "REN" in OpType:
            j = {"_msg": "{0} {1} {2}".format(ip_addr, OpType, DisplayPath), "operation": OpType, "client_ip": ip_addr, "sid": WinSid, "size": size, "path": DisplayPath, "new_name": ren_new_name}
        elif "SMB_WR" in OpType:
            j = {"_msg": "{0} {1} {2}".format(ip_addr, OpType, DisplayPath), "operation": OpType, "client_ip": ip_addr, "sid": WinSid, "size": size, "path": DisplayPath, "bytes_write": WrLength}
        else:
            j = {"_msg": "{0} {1} {2}".format(ip_addr, OpType, DisplayPath), "operation": OpType, "client_ip": ip_addr, "sid": WinSid, "size": size, "path": DisplayPath, "bytes_read": RdLength}
        js["log"] = j
        send(js)
    time.sleep(0.001)
f.close()