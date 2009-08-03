FILES=snmp_executor traphandler keepalivehandler

.PHONY: all clean

all: $(FILES)

clean:
	rm $(FILES) *~

snmp_executor: snmp_executor.cc
	g++ -I../coreapps -lnetsnmp -o snmp_executor snmp_executor.cc

traphandler : traphandler.cc
	g++ -I../coreapps -lnetsnmp -o traphandler traphandler.cc

keepalivehandler : keepalivehandler.cc
	g++ -I../coreapps -lnetsnmp -o keepalivehandler keepalivehandler.cc
