FILES=keepalive_subagent trap_subagent wifi_subagent
CFLAGS=-g -I ../../noxcore/src/include -I ../../noxcore/src/include/openflow -I ../../openflow/lib
CC=net-snmp-config --compile-subagent
.PHONY: all clean

all: $(FILES)

clean:
	rm $(FILES) *~

keepalive_subagent: keepAliveNotif.c iwlib.c 
	$(CC) $@ --cflags "$(CFLAGS)" $^ ../../openflow/lib/libopenflow.a

trap_subagent: wifiNotif.c iwlib.c 
	$(CC) $@ --cflags "$(CFLAGS)" $^ ../../openflow/lib/libopenflow.a


wifi_subagent: bitrate.c channel.c dpid.c essid.c txpower.c wifiMac.c wifiPort.c iwlib.c
	$(CC) $@ --cflags "$(CFLAGS)" $^ ../../openflow/lib/libopenflow.a

