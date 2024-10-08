#!/usr//python3

from bcc import BPF
from pyroute2 import IPRoute # to access netlink
import sys
import ctypes as ct
from ctypes import c_uint32
from enum import Enum

ipr = IPRoute()
device = sys.argv[1]

INGRESS="ffff:ffff2"
EGRESS="ffff:ffff3"

#b = BPF(text=bpf_text, debug=0)
b = BPF(src_file="pingpong.bpf.c")
fn = b.load_func("tc_pingpong", BPF.SCHED_CLS)
idx = ipr.link_lookup(ifname=device)[0]

'''
pong mode
0 = normal
1 = disguise
2 = baigaeshi
3 = super bot fight
'''

class Mode(Enum):
    NORMAL = c_uint32(0)
    DISGUISE = c_uint32(1)
    BAIGAESHI = c_uint32(2)
    SUPER_BOT_FIGHT = c_uint32(3)

print("Select a mode:")
for i, mode in enumerate(Mode):
    print(f"{i}: {mode.name}")


mode_idx = input("Enter the index: ")
selected_index = int(mode_idx)
selected_mode = list(Mode)[selected_index]
mode = selected_mode.value;

print(f"{selected_mode.name} mode specified!")

pong_mode = b.get_table("pong_mode")
key = c_uint32(0)
pong_mode[key] = mode

flexkey = c_uint32(1)
if selected_index == 0 or selected_index == 1:
    flexflg = int(input("Flex mode on? (yes=1, no=0): "))
    pong_mode[flexkey] = c_uint32(flexflg)
    print(f"flex mode on!")
else:
    pong_mode[flexkey] = c_uint32(0)
    print(f"flex mode off")

ipr.tc("add", "clsact", idx)
ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent=INGRESS, classid=1, direct_action=True)

class Data(ct.Structure):
    _fields_ = [("saddr", ct.c_uint32),
                ("daddr", ct.c_uint32)]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print(f"ping from {(event.saddr>>24) & 0xFF}.{(event.saddr>>16 & 0xFF)}.{(event.saddr>>8 & 0xFF)}.{(event.saddr & 0xFF)}")

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        #aa = b.trace_fields() # read from /sys/kernel/debug/tracing/trace_pipe
        #print(aa)

        v = b.get_table("pong_mode")[c_uint32(0)]
        v = int.from_bytes(v, byteorder='little')
        mode = list(Mode)[v]
        print(f"{mode.name} mode now")

        b.perf_buffer_poll(); # use perf output to get data from kernel space

        for addr,cnt in b.get_table("ip_count").items():
            addr = int.from_bytes(addr, byteorder='little')
            cnt = int.from_bytes(cnt, byteorder='little')
            print(f"{(addr>>24) & 0xFF}.{(addr>>16 & 0xFF)}.{(addr>>8 & 0xFF)}.{(addr & 0xFF)}, count = {cnt}")
            if b.get_table("pong_mode")[c_uint32(1)]: # 1 = flex mode
                if cnt == 10:
                    print("too many request. Changing to SUPER BOT FIGHT mode!!!")

    except KeyboardInterrupt:
        break

print("Detaching ebpf program...")
ipr.tc("del", "clsact", idx)
