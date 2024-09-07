#!/usr/bin/python3

from bcc import BPF
from pyroute2 import IPRoute # to access netlink
import sys
from ctypes import c_uint32

ipr = IPRoute()
device = sys.argv[1]

INGRESS="ffff:ffff2"
EGRESS="ffff:ffff3"

#b = BPF(text=bpf_text, debug=0)
b = BPF(src_file="pingpong.bpf.c")
fn = b.load_func("tc_pingpong", BPF.SCHED_CLS)
idx = ipr.link_lookup(ifname=device)[0]

ipr.tc("add", "clsact", idx)
ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent=INGRESS, classid=1, direct_action=True)

'''
pong mode
0 = normal
1 = disguise
2 = baigaeshi
3 = super bot fight
'''

pong_mode = b.get_table("pong_mode")
key = c_uint32(0)
mode = c_uint32(1)
pong_mode[key] = mode

while 1:
    try:
        aa = b.trace_fields() # read from /sys/kernel/debug/tracing/trace_pipe
        print(aa)
    except KeyboardInterrupt:
        exit()
