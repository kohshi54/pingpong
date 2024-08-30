all: up

up:
	sudo python3 -E pingpong.py enp6s18

down:
	sudo tc qdisc del dev enp6s18 parent ffff:

status:
	sudo tc -s qdisc show dev enp6s18

watch:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
