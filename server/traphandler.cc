#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_bonding.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <inttypes.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif


#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>


#include "../../noxcore/src/nox/coreapps/snmp/snmp-message.hh"
#include "../../noxcore/src/nox/coreapps/messenger/message.hh"

#define NOX_IP "127.0.0.1"
#define NOX_PORT 2603
#define CONTROLLERS_CONF "/etc/snmp/controllers.conf"

using namespace std;

typedef unsigned long long u64;	/* hack, so we may include kernel's ethtool.h */
typedef __uint32_t u32;		/* ditto */
typedef __uint16_t u16;		/* ditto */
typedef __uint8_t u8;		/* ditto */

int main()
{
        // read controller hosts and ports from controllers.conf
        vector<string> nox_ip;
        vector<int> nox_port;
        char ip_port[256];
        fstream infile(CONTROLLERS_CONF, ios::in);
        if(infile.fail()) {
                cout << "Could not open " << CONTROLLERS_CONF << " for reading" << endl;
                return 0;
        }
        while(!infile.getline(ip_port, 256).eof()) {
                string ip_port_str(ip_port);
                size_t break_pt = ip_port_str.find(' ');
                if(break_pt == string::npos)
                        continue;
                string ip = ip_port_str.substr(0, break_pt);
                int port = atoi(ip_port_str.substr(break_pt+1).c_str());

                nox_ip.push_back(ip);
                nox_port.push_back(port);
        }

        string oid, value, host, ip;
        char oid_val[256];

        int msg_size = sizeof(messenger_msg) + sizeof(snmp_msg) + sizeof(snmp_host_msg);
        struct messenger_msg *msg = (struct messenger_msg*)malloc(msg_size);
        msg->length = htons((uint16_t)msg_size);
        msg->type = MSG_SNMP;

        int disconn_msg_size = sizeof(messenger_msg); 
        struct messenger_msg *disconn_msg = (struct messenger_msg*)malloc(disconn_msg_size);
        disconn_msg->length = htons((uint16_t)disconn_msg_size);
        disconn_msg->type = MSG_DISCONNECT;

        while(!cin.getline(oid_val, 256).eof()) {
                // Parse trap messages
                string oid_val_str(oid_val);
                size_t break_pt = oid_val_str.find(' ');
                if(break_pt == string::npos)
                        continue;
                string oid_str = oid_val_str.substr(0, break_pt);
                string val_str = oid_val_str.substr(break_pt+1);

                // Case-1: oid == hostJoinLeave
                if(oid_str.find("hostJoinLeave") != string::npos) {
                        break_pt = val_str.find(' ');
                        if(break_pt == string::npos)
                                continue;
                        string event_type = val_str.substr(0, break_pt);
                        if(event_type == "Join") {
                                ((snmp_msg*)(msg->body))->subtype = htons(SNMP_HOST_JOIN);
                        }
                        else if(event_type == "Leave") {
                                ((snmp_msg*)(msg->body))->subtype = htons(SNMP_HOST_LEAVE);
                        }
                        else {
                                cout << "Unknown event" << endl;
                        }
                        string host_mac_str = val_str.substr(break_pt+1);
                        while((break_pt = host_mac_str.find(':')) != string::npos) {
                                host_mac_str.erase(break_pt, 1);
                        }
                        while(host_mac_str.length() < 16) {
                                host_mac_str = "0" + host_mac_str;
                        }
                        uint64_t host_mac_host, host_mac_net;
                        stringstream ss(host_mac_str);
                        ss >> setbase(16) >> host_mac_host >> setbase(10);
                        host_mac_net = htonl(host_mac_host);
                        host_mac_net = (host_mac_net << 32) + htonl(host_mac_host >> 32);
                        //host_mac_net = htonll(host_mac_host);
                        ((snmp_host_msg*)(((snmp_msg*)(msg->body))->body))->hostMac = host_mac_net;
                }
                // Case-2: oid == dpid
                else if(oid_str.find("dpid") != string::npos) {
                        while(val_str.length() < 16) {
                                val_str = "0" + val_str;
                        }
                        uint64_t dpid_host, dpid_net;
                        stringstream ss(val_str);
                        ss >> setbase(16) >> dpid_host >> setbase(10);
                        dpid_net = htonl(dpid_host);
                        dpid_net = (dpid_net << 32) + htonl(dpid_host >> 32);
                        //dpid_net = htonl(dpid_host);
                        ((snmp_host_msg*)(((snmp_msg*)(msg->body))->body))->dpid = dpid_net;
                }
                // Case-3: oid == wifiPort
                else if(oid_str.find("wifiPort") != string::npos) {
                        uint16_t port;
                        stringstream ss(val_str);
                        ss >> port;
                        ((snmp_host_msg*)(((snmp_msg*)(msg->body))->body))->port = htons(port);
                }
                else {
                        cout << "Unparsed string: " << oid_val_str << endl;
                }
        }

	cout << "Host join mac : " << setbase(16) << ((snmp_host_msg*)(((snmp_msg*)(msg->body))->body))->hostMac << ", dpid : " << ((snmp_host_msg*)(((snmp_msg*)(msg->body))->body))->dpid << ", port : " << setbase(10) << ((snmp_host_msg*)(((snmp_msg*)(msg->body))->body))->port << endl;

    for(int i = 0; i < nox_ip.size(); i++) {

            /* Open nox-socket connection 
             * nox_sock: is the socket to nox
             */
            int nox_sock;
            struct sockaddr_in *nox_host= (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in *));
            nox_host->sin_family = AF_INET;
            int tmpres = inet_pton(AF_INET, nox_ip[i].c_str(), (void *)(&(nox_host->sin_addr.s_addr)));
            if( tmpres < 0) {
                    perror("Can't set nox_host->sin_addr.s_addr");
                    continue;
            }
            else if(tmpres == 0) {
                    fprintf(stderr, "%s is not a valid IP address\n", nox_ip[i].c_str());
                    continue;
            }
            nox_host->sin_port = htons(nox_port[i]);
            if((nox_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
                    perror("Can't create NOX TCP socket");
                    continue;
            }
            if(connect(nox_sock, (struct sockaddr *)nox_host, sizeof(struct sockaddr)) < 0){
                    perror("Could not connect to nox_host");
		    cout << "Could not connect to " << nox_ip[i] << ":" << nox_port[i] << endl;
                    continue;
            }
            cout << "Connected to NOX controller on IP address " << nox_ip[i] << ":" << nox_port[i] << endl;

            int bytes_out = 0;
            while(bytes_out < msg_size) {
                    tmpres = write(nox_sock, msg+bytes_out, msg_size-bytes_out);
                    if (tmpres < 0) 
                            perror("ERROR writing to nox_sock");
                    bytes_out += tmpres;
            }
            cout << "Written out message to NOX controller." << endl;
            bytes_out = 0;
            while(bytes_out < disconn_msg_size) {
                    tmpres = write(nox_sock, disconn_msg+bytes_out, disconn_msg_size-bytes_out);
                    if (tmpres < 0) 
                            perror("ERROR writing to nox_sock");
                    bytes_out += tmpres;
            }
            cout << "Written out disconnection message to NOX controller." << endl;
            close(nox_sock);
    }

    free(msg);
    free(disconn_msg);
}
