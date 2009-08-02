#! /bin/sh

net-snmp-config --compile-subagent keepalive_subagent_orig \
--cflags "-g -I ../nox/src/include -I ../nox/src/include/openflow -I ../openflow/lib" \
keepAliveNotif.c iwlib.c ../openflow/lib/libopenflow.a

#net-snmp-config --compile-subagent keepalive_subagent_my \
#--cflags "-I ../nox/src/include -I ../nox/src/include/openflow -I ../openflow/lib" \
#keepAliveNotif.my.c iwlib.c ../openflow/lib/libopenflow.a

#net-snmp-config --compile-subagent trap_subagent_my \
#--cflags "-I ../nox/src/include -I ../nox/src/include/openflow -I ../openflow/lib" \
#wifiNotif.my.c iwlib.c ../openflow/lib/libopenflow.a

net-snmp-config --compile-subagent trap_subagent_orig \
--cflags "-I ../nox/src/include -I ../nox/src/include/openflow -I ../openflow/lib" \
wifiNotif.c iwlib.c ../openflow/lib/libopenflow.a
