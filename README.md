# pingpong
reply ping message from ebpf program attached on tc

ping to attached host and then you'll get reply from 1.1.1.1 or something else.\
Ctrl-C to stop. ebpf program will be detached and stop.

There are four types for pong mode:
- 0: NORMAL\
  just send back icmp echo reply with ttl modified.
  ```
  $ ping 10.2.93.230
  PING 10.2.93.230 (10.2.93.230) 56(84) bytes of data.
  64 bytes from 10.2.93.230: icmp_seq=1 ttl=125 time=0.228 ms
  ```
- 1: DISGUISE\
  send back icmp echo reply changed the src ip to 1.1.1.1 (receiver get icmp echo reply from 1.1.1.1)
  ```
  $ ping 10.2.93.230
  PING 10.2.93.230 (10.2.93.230) 56(84) bytes of data.
  64 bytes from 1.1.1.1: icmp_seq=1 ttl=125 time=0.275 ms (DIFFERENT ADDRESS!)
  ```
- 2: BAIGAESHI\
  send back two icmp echo reply. 倍返しだ！
  ```
  $ ping 10.2.93.230
  PING 10.2.93.230 (10.2.93.230) 56(84) bytes of data.
  64 bytes from 10.2.93.230: icmp_seq=1 ttl=125 time=0.214 ms
  64 bytes from 10.2.93.230: icmp_seq=1 ttl=125 time=0.215 ms (DUP!)
  ```
- 3: SUPER BOT FIGHT\
  send back one hundred icmp echo reply. 百倍返しだ！！
  ```
  too much to paste here...!
  ```

Example usage:
```
$ make
sudo python3 -E pingpong.py enp6s18
Select a mode:
0: NORMAL
1: DISGUISE
2: BAIGAESHI
3: SUPER_BOT_FIGHT
Enter the index: 3
SUPER_BOT_FIGHT mode specified!
ping from x.x.x.x
ping from x.x.x.x
^CDetaching ebpf program...
```
