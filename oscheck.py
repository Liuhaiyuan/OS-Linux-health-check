#!/usr/bin/env python
# -*- coding: utf-8 -*-
# version 0.0.1 2018-3-29 get basic system info
# version 0.0.2 2018-4-21 redirect output to html
# version 0.0.3 2018-4-25 add packet loss/dns check/filesystem&&inode check function
# version 0.0.4 2018-4-27  transfer the ouput to table format
# version 0.0.5 2018-5-4  add /etc/fstab check
# version 0.0.6 2018-5-8  add Euler
# version 0.0.7 2018-5-16 add more check
# version 0.0.8 2018-5-18 transfer output to hand-writing html
# version 0.0.9 2018-5-21 add network connect/iptables/top memory&&cpu usage process
# version 0.1.0 2018-6-4  rebuild the output format
import re
import os
import sys
import subprocess
import glob
import locale
from datetime import datetime
import json
import socket
import fcntl
import struct
import hashlib
import httplib
import urllib
import stat
import commands
from collections import OrderedDict
import time


__support__os__list = ["CentOS","Debian","Euler","Ubuntu"]
ProgressList = ['sshd','crond','dhclient']


class Item:
    ID = 1

    def __init__(self, title, detect, must=False):
        # title indicate check title
        # detect indicate check function
        # detect fucntion must return tuple like
        # (True, "correct") or (False, "something wrong")
        self.title = title
        self.detect = detect
        self.must = must
        self.result = ""
        self.details = ""
        self.id = Item.ID
        Item.ID += 1

    def output(self):
        self.result, self.details = self.detect()
        return {
            "id": self.id,
            "title": self.title,
            "must": self.must,
            "result":    self.result,
            "details": self.details
        }

# execute shell command
# current flow cannot support timeout mechanisms
# must be carefully when use
# not allowed to run interactive comamnd like top
def exe_command(cmd):
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
    stdout, stderr = process.communicate()
    _ = process.poll()
#    return stdout + stderr, cmd + "\n" + stdout + stderr
    return stdout + stderr

# check if service is enable and runing
# para systemc is bool value, True mean service was managed by systemd
def isruning(name, systemd):
    if systemd == True:
        sout, _ = exe_command("systemctl is-enabled " + name)
        if "enabled" not in sout:
            return  False, "%s:not enable" % name
        sout, _ = exe_command("systemctl is-active " + name)
        # sout can return two value:
        # active
        # activing means the service is starting, check again.
        while re.search("^activing", sout) != None:
            time.sleep(1)
            sout, _ = exe_command("systemctl is-active " + name)
        if re.search("^active", sout) == None:
            return False, "%s: not active" % name
        return True, "%s: enable and active" % name
    else:
        # OS use traditional init manage services
        sout, text = exe_command("chkconfig -l " + name)
        if "3:on" not in sout:
            return False, text
        sout, text = exe_command("/etc/init.d/" + name +  " status")
        if "running" not in sout:
            return False, text
        return True, "%s: on and running" % name

def isInstalled(name):
    if linuxos() in ['centos', 'rhel', 'euler', 'suse']:
        rpm_check = "rpm -q "
        cmd = rpm_check + name
        sout = exe_command(cmd)
        cmd_status, output = commands.getstatusoutput(cmd)
        if cmd_status == 0:
            return True
        else:
            return False
    elif linuxos() in ['debian', 'ubuntu']:
        dpkg_check = "dpkg -s "
        cmd = dpkg_check + name
        sout = exe_command(cmd)
        cmd_status, output = commands.getstatusoutput(cmd)
        if cmd_status == 0:
            return True
        else:
            return False


def which(program):
    sout = exe_command("command -v " + program)
    if sout == "":
        return False
    else:
        return True

def linuxos():
    if os.path.isfile("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                line = line.rstrip()
                if line == 'ID=ubuntu':
                    return 'ubuntu'
                if line == 'ID=debian':
                    return 'debian'
                if line == 'ID=opensuse':
                    return 'opensuse'
                if line == 'ID="sles"':
                    return 'suse'
                # centos7
                if line == 'ID="centos"':
                    return 'centos'
                if line == 'ID=fedora':
                    return 'fedora'
    if os.path.isfile("/etc/issue"):
        with open("/etc/issue") as f:
            for line in f:
                line = line.rstrip()
                # Centos6 have /etc/issue instead of /etc/os-release
                if line.startswith('CentOS'):
                    return 'centos'
    if os.path.isfile("/etc/euleros-release"):
        return 'euler'
    if os.path.isfile("/etc/redhat-release"):
        return "rhel"

    return "This OS is not in the  support list."

def osversion():
    #
    line = ''
    if linuxos() == "centos":
        if os.path.isfile("/etc/centos-release"):
            with open("/etc/centos-release") as f:
                return ''.join(f.readlines())
        else:
            return "/etc/centos-release no exist"
    elif linuxos() == "debian":
        if os.path.isfile("/etc/debian-version"):
            with open("etc/debian-version") as f:
                return linuxos().join(f.readlines())
        else:
            return "/etc/debian-version no exist"
    elif linuxos() == "euler":
        if os.path.isfile("/etc/euleros-release"):
            with open("/etc/euleros-release") as f:
                return ''.join(f.readlines())
        else:
            return "/etc/euleros-release not exist"
    elif linuxos() == "opensuse":
        if os.path.isfile("/etc/SuSE-release"):
            with open("/etc/SuSE-release") as f:
                for line in f:
                    line = line.rstrip()
                    if line.startswith('openSUSE'):
                         return line
        else:
            return "/etc/SuSE-release not exist"
    elif linuxos() == "ubuntu":
        if os.path.isfile("/etc/os-release"):
            with open("/etc/os-release") as f:
                for line in f:
                    line = line.rstrip()
                    if line.startswith('PRETTY_NAME'):
                        return line.replace("PRETTY_NAME=", "")
        else:
            return "/etc/os-release not exist"

def  queryVirtualType():
    cmd = """dmidecode -s system-product-name"""
    sout = exe_command(cmd)
    return sout




def queryHostType():
    re = ""
    with open("/proc/cpuinfo") as f:
        content = f.read()
        if "hypervisor" in content:
            re = "Virtual Machine"
        else:
            re = "Physical Machine"
    return re


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
         r =  socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    except IOError:
        r = ""
    return  r

def get_ip_list ():
    addr_list = []
    namelist = os.listdir("/sys/class/net/")
    for i in namelist:
        ip_addr = get_ip_address(i)
        if  ip_addr.strip() and ip_addr != "None" and ip_addr != '127.0.0.1':
            addr_list.append(ip_addr)
    return addr_list


def queryKernel():
    return os.uname()[2]

def queryMemory():
    meminfo = OrderedDict()
    with open('/proc/meminfo') as f:
        for line in f:
            meminfo[line.split(':')[0]] = line.split(':')[1].strip()
    return meminfo
def cpumodel():
    with open('/proc/cpuinfo') as f:
        for line in f:
            line = line.strip()
            if line.startswith("model name"):
                return line.split(':')[1]


def queryCPU():
    cpuinfo = OrderedDict()
    sout = exe_command('lscpu').strip()
    for line in sout.split("\n"):
        cpuinfo[line.split(':')[0]] = line.split(':')[1].strip()
    return cpuinfo


def queryUptime():
    return exe_command('uptime')

def queryHostname():
    return exe_command('hostname')

def detectTimezone():
    cmd = """date +'%:z'"""
    sout = exe_command(cmd).rstrip()
    tz = "+08:00"
    if sout == tz:
        return "timezone is UTC+8"
    else:
        return "Please be noted current timezone is not UTC+8"


# read limits.conf, then limits.conf.d
# later value will override previous value
# add check current status
def detectLimit():
    re1 = False
    re2 = False
    correctline = []
    errline = []
    files = glob.glob("/etc/security/limits.d/*.conf")
    files = sorted(files)
    files.insert(0, "/etc/security/limits.conf")
    existnofile = False
    existnproc = False
    for file in files:
        with open(file) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                # * - nofile 65535
                # * soft nofile 65535
                # * hard nofile 65535
                # - apply to both soft and hard
                n1 = re.compile(r"\s*\*\s+(-|soft|hard)\s+nofile\s+(\d+)").search(line)
                if n1:
                    existnofile = True
                    valueofnofile = int(n1.group(2))

                # * - nproc 65535
                # it apply to both soft and hard
                n2 = re.compile(r"\s*\*\s+(-|soft|hard)\s+nproc\s+(\d+)").search(line)
                if n2:
                    existnproc = True
                    valueofnproc = int(n2.group(2))
    if existnofile == False and existnproc == False:
        return  "miss nofile and nproc"
    elif existnofile == False:
        return  "miss nofile"
    elif existnproc == False:
        return  "miss nproc"
    if valueofnofile < 65535 or valueofnproc < 65535:
        return  "wrong configuration:\nnofile:%s\nnproc:%s\n" % (valueofnofile, valueofnproc)
    # continue check current status
    sout, _ = exe_command("ulimit -n")
    if int(sout.strip()) < 65535:
        return  "wrong nofile real value:%s" % sout
    sout, _ = exe_command("ulimit -u")
    if int(sout.strip()) < 65535:
        return  "wrong nproc real value:%s" % sout
    return  "config and real value is ok"

def detectDNS():
    if os.path.exists("/etc/resolv.conf"):
        errline = []
        totalline = []
        namelist = []
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                n = re.compile(r"^(nameserver)\s+(.+)").search(line)
                if n != None:
                    totalline.append(line)
                    namelist.append(n.group(2))
    else:
        return False, "/etc/resolv.conf file not exist"
    return namelist

#this function  need to be modified
def detectKeyProgress():
    for i in ProgressList:
        sts, output = commands.getstatusoutput("ps ax | grep -v grep | grep -c i")
        errorlist = []
        if sts != 0:
            return "i is running"
        else:
            errorlist.append(i)
    if len(errorlist) == 0:
        return ProgressList, "check okay"
    else:
        return errorlist, "is not running"

def detectFilesystem():
#   split the filsystem output into lines except for tmpfs

#    df_output_lines = [s.split() for s in os.popen("df -Pkh 2>/dev/null | grep -v 'Filesystem' | grep -v tmpfs").read().splitlines()]
    sout = os.popen("""df -Pkh 2>/dev/null | grep -v 'Filesystem' | grep -v tmpfs | grep -v sr0 """)
#   f.close(sout)
    unhealthlist = []
    for line in sout.readlines():
        line = line.split()
#        n = re.compile(r"\s").search(line)
#        line = line.strip()
        if int(line[4].replace('%','')) > 90:
            unhealthlist.append(line[1])
            return line[1], "is not healthy"
    if len(unhealthlist) > 0:
        return unhealthlist,"is unhealthy"
    else:
        return "File system check is okay"

def detectInode():
    sout = os.popen("""df -Pi 2>/dev/null | grep -v 'Filesystem' | grep -v tmpfs | grep -v sr0 """)
    errlist = []
    for line in sout.readlines():
        line = line.split()
        if int(line[4].replace('%', '')) > 90:
            errlist.append(line[1])
    if len(errlist) > 0:
        return errlist, "is unhealthy"
    else:
        return "Inode check is okay"

def is_connected():
# As test result, this does not work in  virtual box vm,
#    try:
#        socket.create_connection(("www.baidu.com",80))
#        return "internet is connected"
#    except OSError:
#        pass
#    return "internet is not connected"
    cmd = """ping -c3 www.baidu.com"""
    cmd_status, output = commands.getstatusoutput(cmd)
    if cmd_status == 0:
        return "Internet is connected"
    else:
        return "Internet is not connected"
#def dns_check():
#    myResolver = dns.resolver.Resolver()
#    myResolver.nameservers = ['114.114.114.114']
#    try:
#        answers = myResolver.query("baidu.com",'A')
#        if len(answers) > 0 :
#            return "name resolved fine"
#        else:
#            return "name resolved failed"
#    except:
#        print "name query failed"

def packetLossCheck():
#compare the netstat -s output between 3 seconds to check if packet loss

    sout = os.popen('netstat -s | grep dropped')
    p1 = subprocess.Popen(args='netstat -s', stdout=subprocess.PIPE,shell=True)
    p2 = subprocess.Popen(args='grep dropped', stdin=p1.stdout, stdout=subprocess.PIPE, shell=True)
    output = p2.communicate()[0]
    list1 = re.findall(r"\d+\.?\d*", output)
    time.sleep(3)
    cmd = """netstat -s | grep dropped"""
    sout = exe_command(cmd)
    list2 = re.findall(r'[0-9]+', sout)
    if len(list1) > 1:
        if list1[0] != list2[0] or list1[1] != list2[1]:
            return "packet is dropping"
        else:
            return "Packet loss check is fine"
    elif len(list1) == 1:
        if list1[0] != list2[0]:
            return "packet is dropping"
        else:
            return "Packet loss check is fine"
    else:
        return "Packet loss check is fine"



def checkFstab():
    errline = []
    sout = []
    warningline = []
    with open("/etc/fstab") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                continue
            data = line.split()
            if len(data) != 6:
                continue
            if   data[3] == "default":
                errline.append("Error, the fourth option should be defaults")
            if data[4] not in ['0', '1', '2']:
                errline.append("the sixth option false")
            if data[5] not in ['0', '1', '2']:
                errline.append("the sixth option false")
            if os.path.isdir(data[1]) == True:
                if os.path.ismount(data[1]) == False:
                    errline.append("it is not a mount point")

        if len(errline) > 0:
            return errline
        else:
            return " /etc/fstab syntax check is okay"

# to be continued
def ntpCheck():
    sout2 = exe_command("chronyc -n sources")
    sout = exe_command("ntpq -np")
    if linuxos() in ['centos', 'rhel', 'euler'] and int(queryKernel()[0:1]) == 3:
    # ntpq -p will hang when /etc/resolv.conf have unreachable DNS server IP
    # so use ntpq -np  instead
    # check each line and see if have line start with "*"
        if len([i for i in sout2.split("\n") if i.startswith("^*")]) == 0:
            if len([i for i in sout.split("\n") if i.startswith("*")]) == 0:
                return "Neither ntpd nor chronyd is not syncing time"
            else:
                return "ntpd is syncing time"
        else:
            return "chronyd is syncing time"
    else:
        if len([i for i in sout.split("\n") if i.startswith("*")]) == 0:
            return "ntpd is syncing time"
        else:
            return "ntpd is not working"


def detectSelinux():
    support_list = ["euler", "centos", "rhel"]
    if linuxos() in support_list:
        if os.path.exists("/etc/selinux/config"):
            match = False
            with open("/etc/selinux/config") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("SELINUX") and \
                            "SELINUXTYPE" not in line:
                        match = True
                        if line != "SELINUX=disabled":
                            return  line
            if match == False:
                return  "No SELINUX item at /etc/selinux/config"
        else:
            return  "no file /etc/selinux/config"
    if which("getenforce") == False:
        return  "no getenforce command"
    else:
        sout = exe_command("getenforce")
        if sout.strip() == "Disabled":
            return  "Status is Disabled"
        else:
            return  "Status is %s" % sout

# /etc/shandow right must below 640
def detectShadowRight():
    file = "/etc/shadow"
    if os.path.exists(file):
        mode = os.stat(file).st_mode
        if (stat.S_IRWXU & mode <= 0600 and
            stat.S_IRWXG & mode <= 0040 and
            stat.S_IRWXO & mode <= 0):
            return True, "correct"
        else:
            return False, "%s is wrong" % oct(stat.S_IMODE(mode))
    else:
        return False, "no file /etc/shadow"

# check service run or not
def detectIPTables():
    support_list = ["euler", "centos", "rhel"]
    if linuxos() in  support_list:
        isrun, text = isruning("iptables", True)
        if isrun == True:
            return False, text
        return True, text
    elif OS == "SLES":
        isrun, text = isruning("SuSEfirewall2", False)
        if isrun == True:
            return False, text
        return True, text
def NetworkManagerCheck():
    cmd_status, output = commands.getstatusoutput("ps aux | grep NetworkManager")
    support_list = ["centos", "rhel"]
    if linuxos() in  support_list  and int(queryKernel()[0:1]) == 2:
        if cmd_status == 0:
            return "NetworkManager is running but it's not recommended"
        else:
            return "NetworkManager is not running"
    elif linuxos() == "centos" or linuxos() == "rhel" and int(queryKernel()[0:1]) == 3:
        if cmd_status == 0:
            return "NetworkManager is running"
        else:
            return "NetworkManager is not running"


def cloudinitCheck():
    if linuxos() in ['centos', 'rhel', 'euler', 'suse']:
        cmd_status, output = commands.getstatusoutput("rpm -q cloud-init")
    elif linuxos() in ['debian', 'ubuntu']:
        cmd_status, output = commands.getstatusoutput("dpkg-query -s cloud-init")
    else:
        cmd_stauts = 0
        return "is not in support OS list"

    if cmd_status != 0:
        return "cloudinit is not installed"
    else:
        sts, output_temp = commands.getstatusoutput("cloud-init init --local")
        if sts == 0:
            return "okay"
        else:
            return "cloudinit status is error"

def hyperv_type():
    sout = exe_command("lscpu")
    if "Xen" in sout:
        return "Xen"
    elif "KVM" in sout:
        return "KVM"
    else:
        return "Unknown"

def NicDriverCheck():
    if hyperv_type() == "Xen":
        cmd_status, output = commands.getstatusoutput("lsmod | grep xen_vnif")
        if sts == 0:
            return "driver is loaded"
        else:
            return "driver is not loaded"
    elif hyperv_type() == "KVM":
        cmd_status, output = commands.getstatusoutput("lsmod | grep virtio_net")
        if sts == 0:
            return "driver is loaded"
        else:
            return "driver is not loaded"
    return "currently this function only support tenant virtual machine"
def localeCheck():
    line = ''
    # check configuration file first
    if os.path.isfile("/etc/locale.conf"):
        # EulerOS rhel debian suse ubuntu
        with open("/etc/locale.conf") as f:
            match = False
            for line in f:
                line = line.strip()
                if line.startswith("LANG="):
                    return line.replace("LANG=","")
            if match == False:
                return "no LANG value in /etc/locale.conf"
    elif os.path.isfile("/etc/default/locale"):
        with open('/etc/default/locale') as f:
            for line in f:
                line = line.strip()
                if line.startswith("LANG"):
                    return line.replace("LANG=","")
    elif os.path.isfile("/etc/sysconfig/language"):
        # SLES
        # check two parameter
        # RC_LANG and ROOT_USES_LANG
        with open("/etc/sysconfig/language") as f:
            match = False
            for line in f:
                line = line.strip()
                if line.startswith("RC_LANG="):
                    match = True
                    return line.replace("RC_LANG=", "")
            if match == False:
                return "no RC_LANG value in /etc/sysconfig/language"
        with open("/etc/sysconfig/language") as f:
            match = False
            for line in f:
                line = line.strip()
                if line.startswith("ROOT_USES_LANG="):
                    match = True
                    return line.replace("ROOT_USES_LANG=", "")
            if match == False:
                return "no ROOT_USES_LANG value at /etc/sysconfig/language"
    # check currect shell environment
    sout = exe_command("env")
    if line.startswith("LANG="):
        return line.replace("LANG=", "")
def detectRootSSHkeys():
    file = "/root/.ssh/authorized_keys"
    if os.path.exists(file):
        return "/root/.ssh/authorized_keys is exist"
    else:
        return "no file /root/.ssh/authorized_keys"
def detectFileMode():
    file = "/etc/exports"
    if os.path.exists(file):
        mode = os.stat(file).st_mode
        print "mode:", oct(stat.S_IMODE(mode))
#        if stat.S_IMODE(mode)

def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
def gatewaypingCheck():
    default_gateway = get_default_gateway_linux()
    cmd = "ping -c3 " + default_gateway
    cmd_status, output = commands.getstatusoutput(cmd)
    if cmd_status == 0:
        return "gateway ping success"
    else:
        return "gateway ping failed"
def mtuCheck():
    namelist = os.listdir("/sys/class/net/")
    list_mtu = []
    for i in namelist:
        cmd = """cat /sys/class/net/{name}/mtu""".format(name=i)
        dict = {}
        cmd_status, output = commands.getstatusoutput(cmd)
        dict[i] = output
        list_mtu.append(dict)
    return list_mtu

def topCpuUsage():
    cmd = """ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head"""
    sout = exe_command(cmd)
    return sout

def topMemoryUsage():
    cmd = """ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head"""
    sout = exe_command(cmd)
    return sout

def listIptables():
    cmd = """iptables -L"""
    sout = exe_command(cmd)
    return sout

def RouteTable():
    cmd = """ip route"""
    sout = exe_command(cmd)
    return sout

def ulimit():
    with open('/proc/self/limits') as f:
        content = f.read()
    return content

def ss_result():
    cmd = """ss -s"""
    sout = exe_command(cmd)
    return sout

def CpuLoad():
        if isInstalled("sysstat"):
            cmd = """mpstat -P ALL 2 2"""
            sout = exe_command(cmd)
            return sout
        else:
            return "package sysstat need to be installed"

def BootOptionCheck():
    if linuxos() in ["euler", "centos", "rhel"] and int(queryKernel()[0:1]) == 3:
        cmd = "systemctl list-unit-files"
        sout = exe_command(cmd)
        return sout
    elif linuxos() in ["euler", "centos", "rhel"] and int(queryKernel()[0:1]) == 2:
        cmd = "chkconfig --list"
        sout = exe_command(cmd)
        return sout

def iostat():
    if isInstalled("sysstat"):
        cmd = """iostat -d -k -x 2 3 """
        sout = exe_command(cmd)
        return sout
    else:
        return "package sysstat need to be installed"


if __name__ == '__main__':
    print "begin running, please wait..."
    cpuinfo = queryCPU()
    cpucores = cpuinfo['CPU(s)']
    meminfo = queryMemory()
    mem_total = int(meminfo['MemTotal'].replace("kB",""))/1024
    mem_free = int(meminfo['MemFree'].replace("kB", "")) / 1024
    swap_total = int(meminfo['SwapTotal'].replace("kB", "")) / 1024
    swap_free  = int(meminfo['SwapFree'].replace("kB", "")) / 1024
    f = open("/tmp/oscheck.html",'w')
    message = """
<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">
<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">
<head>
<title>UNIX Health Check for Red Hat Enterprise Linux</title>
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\" />
<style type="text/css">
a:link, a:hover {
    color: #5C81A7;
}
p, td, table, body {
    font-family: "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
    font-size: 12px;
}
td pre {
    font-size: 12px;
    text-align: left;
    font-family: "Consolas", monospace, "Courier New";
    word-wrap: break-word;
    white-space: pre-wrap; /* CSS2.1 compliant */
    white-space: -moz-pre-wrap; /* Mozilla-based browsers */
    white-space: o-pre-wrap; /* Opera 7+ */
    padding: 0px;
    margin: 0px;
}
td pre em {
    color: #ff0000;
    font-weight: normal;
    font-style: normal;
    font-size: 12px;
}
table {
    padding: 0px;
    margin: 0px;
    border: 1px dotted #314263;
    width: 100%;
    table-layout: fixed;
}
td {
    padding: 2px;
    border: 1px solid #f0f4fb;
    background-color: #fcf7ec;
}
.firstcell {
    width: 250px;
}
#uhc-content-head.uhc-content-subtitle p {
    padding: 0px 0px 20px;
}
#uhc-content-head p {
    height: 1%;
}
#uhc-content-head p em {
    color: #666666;
    font-family: "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
    font-size: 15px;
    font-style: normal;
    font-weight: bold;
}
p em {
    color: #666666;
    font-family: "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
    font-size: 15px;
    font-style: normal;
    font-weight: bold;
}
#uhc-content-head em {
    font-family: "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
    font-size: 12px;
    font-style: normal;
    font-weight: bold;
}
em {
    font-family: "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
    font-size: 15px;
    font-style: normal;
    font-weight: bold;
}
#uhc-content-head h1 {
    font-family: "Trebuchet MS", Verdana, Arial, Helvetica, sans-serif;
    font-size: 24px;
    font-style: normal;
    font-weight: bold;
    color: #000000;
}
</style>
</head>
<body>
<h1>Linux OS HEALTH CHECK </h1>
<p>This report currently only support python2 and Centos/Rhel/SUSE/ubuntu/Euler/Debian OS
</p>
<h2>System Info</h2>
    """
    f.write(message)

    sysinfo = """
<table>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Host Type</b></td><td>{hosttype}</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>OS Release</b></td><td>{release}</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Kernel</b></td><td>{querykernel}</td></tr>  
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Hostname</b></td><td>{hostname}</td></tr> 
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Ip addr</b></td><td>{ipAddr}</td></tr> 
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Uptime</b></td><td>{uptime}</td></tr> 
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>CPU Info</b></td><td> {cores} cores, {model},</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Memory info</b></td><td>Total Mem: {mem_total} MB, Free Mem: {mem_free}  MB,  Total Swap: {swap_total} MB, Free Swap: {swap_free}  MB</td></tr>
</table>
""".format(hosttype=queryHostType(), release=osversion(), querykernel=queryKernel(), hostname=queryHostname(), \
           ipAddr=get_ip_list(), uptime=queryUptime(), cores=cpucores, model=cpumodel(), mem_total=mem_total, mem_free=mem_free, \
            swap_total=swap_total, swap_free=swap_free )
    f.write(sysinfo)


    fscheck = """
<h2>File system check</h2>
<table> 
<tr><td><b>Check Items</b></td><td><b>Check Result</b></td><td><b>Description</b></td>  
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Filesystem Usage Check</b></td><td>{fscheck}</td><td>check if file system usage larger than 90%</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>/etc/fstab syntax Check</b></td><td>{fssyntaxcheck}</td><td>check /etc/fstab syntax</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Inode Check</b></td><td>{inodecheck}</td><td>check if inode usage larger than 90%</td></tr>
</table>
    """.format(fscheck=detectFilesystem(), fssyntaxcheck= checkFstab(), inodecheck=detectInode())
    f.write(fscheck)
    NetworkingCheck = """
<h2>Networking check</h2>
<table>
<tr><td><b>Check Items</b></td><td><b>Check Result</b></td><td><b>Description</b></td>  
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Internet connect check</b></td><td>{is_connected}</td><td>check if internet is connected</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Packet loss check</b></td><td>{packetlosscheck}</td><td>check if having packet dropping</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>NetworkManager status</b></td><td>{networkmanagerstatus}</td><td>regarding Centos/Euler/Rhel</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Gateway Ping check</b></td><td>{gatewaycheck}</td><td>ping default gateway</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>NIC mtu check</b></td><td>{mtucheck}</td><td>check NIC mtu</td></tr>
 </table>   
    """.format(is_connected=is_connected(), packetlosscheck=packetLossCheck(), networkmanagerstatus= NetworkManagerCheck(),
               gatewaycheck=gatewaypingCheck(), mtucheck=mtuCheck())
    f.write(NetworkingCheck)

    systemSettingCheck = """
<h2>System setting check</h2>
<table>
<tr><td><b>Check Items</b></td><td><b>Check Result</b></td><td><b>Description</b></td>  
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Name Server</b></td><td>{nameserver}</td></td><td>list current name servers</td></tr> 
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Timezone Check</b></td><td>{timezonecheck}</td><td>check if timezone is UTC+8'</td></tr> 
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Key Progress Check</b></td><td>{keyprogresscheck}</td><td>sshd/crond/dhclient progress running check</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Cloudinit Check</b></td><td>{cloudinitcheck}</td><td>check if cloudinit is running</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Selinux Status</b></td><td>{selinuxcheck}</td><td>regarding Centos/Euler/Rhel</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Ntp Check</b></td><td>{ntpcheck}</td><td>ntp check</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Locale Check</b></td><td>{localecheck}</td><td>locale check</td></tr>
<tr><td style=\"background-color: #6FFF6F;\" width=\"500\"><b>Root ssh Key Check</b></td><td>{rootkeycheck}</td><td>check root ssh key</td></tr>
</table>
    """.format(nameserver=detectDNS(), ulimitcheck=detectLimit(), timezonecheck=detectTimezone(), \
               keyprogresscheck=detectKeyProgress(),
                cloudinitcheck=cloudinitCheck(), selinuxcheck=detectSelinux(), \
               ntpcheck=ntpCheck(), localecheck=localeCheck(), \
               gatewaycheck= gatewaypingCheck(), rootkeycheck=detectRootSSHkeys())
    f.write(systemSettingCheck)

    system_load = """
<h2> System load</h2>    
    """
    f.write(system_load)
    cpu_usage = """
<br>
<table>
<tr>
<td style=\"background-color: #6FFF6F;\" width=\"500\"><b>CPU load</b></td>
<tr><td class=\"firstcell\" valign=\"top\"><pre>{cpuload}</pre></tr>  
</tr> 
</table>   
    """.format(cpuload=CpuLoad())
    f.write(cpu_usage)
    DiskIO = """
<br>
<table>
<tr>
<td style=\"background-color: #6FFF6F;\" width=\"500\"><b>IO status</b></td>
<tr><td class=\"firstcell\" valign=\"top\"><pre>{iostatus}</pre></tr>  
</tr> 
</table>      
    """.format(iostatus=iostat())
    f.write(DiskIO)

    cmd_status, output = commands.getstatusoutput("netstat -tulnp")
    net_conn = """
<h2>Networking Info and statistics</h2>
<br>
<table>
<tr>
<td style=\"background-color: #6FFF6F;\" width=\"500\"><b>current connect</b></td>
<tr><td class=\"firstcell\" valign=\"top\"><pre>{name}</pre></tr>  
</tr>
</table>
""".format(name=output)
    f.write(net_conn)
    iptable_rules = """
<br>
<table>
<tr>
<td style=\"background-color: #6FFF6F;\" width=\"500\"><b>iptable rules</b></td>
<tr><td class=\"firstcell\" valign=\"top\"><pre>{rules}</pre></tr>  
</tr> 
</table>
""".format(rules=listIptables())
    f.write(iptable_rules)
    routetable = """
<br>
<table>
<tr>
<td style=\"background-color: #6FFF6F;\" width=\"500\"><b>route table</b></td>
<tr><td class=\"firstcell\" valign=\"top\"><pre>{routetable}</pre></tr>  
</tr> 
</table>
""".format(routetable=RouteTable())
    f.write(routetable)
    cpu_usage = """
<h2>Top usage process<h2>
<table>
<tr>
<td style=\"background-color: #6FFF6F;\" width=\"500\"><b>top cpu usage</b></td>
<tr><td class=\"firstcell\" valign=\"top\"><pre>{cpu_usage}</pre></tr>  
</tr> 
</table>
""".format(cpu_usage=topCpuUsage())
    f.write(cpu_usage)
    mem_usage = """
<br>
<table>
<tr>
<td style=\"background-color: #6FFF6F;\" width=\"500\"><b>top memory usage</b></td>
<tr><td class=\"firstcell\" valign=\"top\"><pre>{mem_usage}</pre></tr>  
</tr> 
</table>
""".format(mem_usage=topMemoryUsage())
    f.write(mem_usage)

    ulimitvalue = """
<br>
<table>
<tr>
<td style=\"background-color: #6FFF6F;\" width=\"500\"><b>ulimit value</b></td>
<tr><td class=\"firstcell\" valign=\"top\"><pre>{ulimit}</pre></tr>  
</tr> 
</table>
""".format(ulimit=ulimit())
    f.write(ulimitvalue)

    bootoption = """
<br>
<table>
<tr>
<td style=\"background-color: #6FFF6F;\" width=\"500\"><b>service boot option</b></td>
<tr><td class=\"firstcell\" valign=\"top\"><pre>{bootoption}</pre></tr>  
</tr> 
</table>
    """.format(bootoption=BootOptionCheck())
    if linuxos() in ["centos", "rhel", "euler"]:
        f.write(bootoption)

    f.close
    print "Output file is /tmp/oscheck.html"