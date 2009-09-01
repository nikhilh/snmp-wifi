#!/bin/bash
scp config-files/POMI-MOBILITY-MIB.txt $1:/usr/share/snmp/mibs/.
ssh $1 "echo POMI-MOBILITY-MIB POMI-MOBILITY-MIB.txt >> /usr/share/snmp/mibs/.index"
scp config-files/snmpd.conf ap-subagents/*_subagent $1:/etc/snmp/.
scp config-files/openroads $1:/etc/init.d/.
ssh $1 "ln -s /etc/init.d/openroads /etc/rc2.d/S99openroads"

