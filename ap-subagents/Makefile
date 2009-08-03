FILES=keepalive_subagent trap_subagent

.PHONY: all clean

all: $(FILES)

clean:
	rm $(FILES) *~

keepalive_subagent: keepAliveNotif.c iwlib.c 
	net-snmp-config --compile-subagent $@ --cflags "-g -I ../../noxcore/src/include -I ../../noxcore/src/include/openflow -I ../../openflow/lib" $^ ../../openflow/lib/libopenflow.a

trap_subagent: wifiNotif.c iwlib.c 
	net-snmp-config --compile-subagent $@ --cflags "-g -I ../../noxcore/src/include -I ../../noxcore/src/include/openflow -I ../../openflow/lib" $^ ../../openflow/lib/libopenflow.a

