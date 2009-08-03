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

//net-snmp headers
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

/* change the word "define" to "undef" to try the (insecure) SNMPv1 version */
#undef DEMO_USE_SNMP_VERSION_3

#ifdef DEMO_USE_SNMP_VERSION_3
#include "net-snmp/transform_oids.h"
const char *our_v3_passphrase = "The Net-SNMP Demo Password";
#endif

//nox-messenger headers
#include "../../noxcore/src/nox/coreapps/snmp/snmp-message.hh"
#include "../../noxcore/src/nox/coreapps/messenger/message.hh"

#define NOX_IP "127.0.0.1"
#define NOX_PORT 2603
#define SLEEP_MAX 300
#define MAX_MSG_SIZE 256

using namespace std;

typedef unsigned long long u64;	/* hack, so we may include kernel's ethtool.h */
typedef __uint32_t u32;		/* ditto */
typedef __uint16_t u16;		/* ditto */
typedef __uint8_t u8;		/* ditto */

string 
ip_to_str(uint32_t ip)
{
        char ip_cstr[16];
        sprintf(ip_cstr, "%u.%u.%u.%u",
                        ((unsigned char *)&ip)[0],
                        ((unsigned char *)&ip)[1],
                        ((unsigned char *)&ip)[2],
                        ((unsigned char *)&ip)[3]);
        return string(ip_cstr);
}

string 
snmp_get(uint32_t ip, string oid_str)
{
        cout << "Calling snmp_get on IP " << ip_to_str(ip) << " and OID " << oid_str << endl;

        string ret;
        struct snmp_session session, *ss;
        struct snmp_pdu *pdu;
        struct snmp_pdu *response;

        oid get_OID[MAX_OID_LEN];
        size_t get_OID_len = MAX_OID_LEN;
        string ip_str = ip_to_str(ip);
        char *agentip = new char[ip_str.length() + 1];
        strncpy(agentip, ip_str.c_str(), ip_str.length()+1);

        struct variable_list *vars;
        int status;
        /*
         * Initialize a "session" that defines who we're going to talk to
         */
        snmp_sess_init( &session );                   /* set up defaults */
        session.peername = agentip;

        /* set the SNMP version number */
        session.version = SNMP_VERSION_2c;

        /* set the SNMPv1 community name used for authentication */
        char comm[] = "public";
        session.community = (u_char*)comm;
        session.community_len = strlen(comm);

        /* windows32 specific initialization (is a noop on unix) */
        SOCK_STARTUP;

        /*
         * Open the session
         */
        ss = snmp_open(&session);                     /* establish the session */
        if (!ss) {
                snmp_perror("ack");
                snmp_log(LOG_ERR, "something horrible happened!!!\n");
                exit(2);
        }
        /*
         * Create the PDU for the data for our request.
         *   1) We're going to GET the system.sysDescr.0 node.
         */
        pdu = snmp_pdu_create(SNMP_MSG_GET);
        if (!snmp_parse_oid(oid_str.c_str(), get_OID, &get_OID_len)) {
            snmp_perror(oid_str.c_str());
            snmp_close(ss);
            SOCK_CLEANUP;
            return ret;
        }
        else {
                snmp_add_null_var(pdu, get_OID, get_OID_len);
        }
        /*
         * Send the Request out.
         */
        status = snmp_synch_response(ss, pdu, &response);
        /*
         * Process the response.
         */
        if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
                /*
                 * SUCCESS: Print the result variables
                 */
                for(vars = response->variables; vars; vars = vars->next_variable)
                        print_variable(vars->name, vars->name_length, vars);

                /* manipulate the information ourselves */
                for(vars = response->variables; vars; vars = vars->next_variable) {
                        int count=1;
                        if (vars->type == ASN_OCTET_STR) {
                                char *sp = (char *)malloc(1 + vars->val_len);
                                memcpy(sp, vars->val.string, vars->val_len);
                                sp[vars->val_len] = '\0';
                                ret = string(sp);
                                free(sp);
                        }
                        else
                                printf("value #%d is NOT a string! Ack!\n", count++);
                }

        } 
        else {
                /*
                 * FAILURE: print what went wrong!
                 */

                if (status == STAT_SUCCESS)
                        fprintf(stderr, "Error in packet\nReason: %s\n",
                                        snmp_errstring(response->errstat));
                else
                        snmp_sess_perror("snmpget", ss);

        }
        /*
         * Clean up:
         *  1) free the response.
         *  2) close the session.
         */
        if (response)
                snmp_free_pdu(response);
        snmp_close(ss);

        /* windows32 specific cleanup (is a noop on unix) */
        SOCK_CLEANUP;

        return ret;

}

string 
snmp_set(uint32_t ip, string oid_str, string val)
{
        cout << "Calling snmp_set on IP " << ip_to_str(ip) << ", OID " << oid_str << ", and value " << val << endl;
        string ret;
        struct snmp_session session, *ss;
        struct snmp_pdu *pdu;
        struct snmp_pdu *response;

        oid set_OID[MAX_OID_LEN];
        size_t set_OID_len = MAX_OID_LEN;

        string ip_str = ip_to_str(ip);
        char *agentip = new char[ip_str.length() + 1];
        strncpy(agentip, ip_str.c_str(), ip_str.length()+1);

        struct variable_list *vars;
        int status;

        /*
         * Initialize a "session" that defines who we're going to talk to
         */
        snmp_sess_init( &session );                   /* set up defaults */
        session.peername = agentip;

        /* set the SNMP version number */
        session.version = SNMP_VERSION_2c;

        /* set the SNMPv1 community name used for authentication */
        char comm[] = "public";
        session.community = (u_char*)comm;
        session.community_len = strlen(comm);

        /* windows32 specific initialization (is a noop on unix) */
        SOCK_STARTUP;

        /*
         * Open the session
         */
        ss = snmp_open(&session);                     /* establish the session */
        if (!ss) {
                snmp_perror("ack");
                snmp_log(LOG_ERR, "something horrible happened!!!\n");
                exit(2);
        }

        /*
         * create PDU for SET request and add object names and values to request 
         */
        pdu = snmp_pdu_create(SNMP_MSG_SET);
        bool fail = false;
        if (snmp_parse_oid(oid_str.c_str(), set_OID, &set_OID_len) == NULL) {
                snmp_perror(oid_str.c_str());
                fail = true;
        } 
        else if (snmp_add_var(pdu, set_OID, set_OID_len, 's', val.c_str())) {
                snmp_perror(oid_str.c_str());
                fail = true;
        }

        if(fail) {
                snmp_close(ss);
                SOCK_CLEANUP;
                return ret;
        }

        /*
         * Send the Request out.
         */
        status = snmp_synch_response(ss, pdu, &response);
        /*
         * Process the response.
         */
        if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
                /*
                 * SUCCESS: Print the result variables
                 */
                for(vars = response->variables; vars; vars = vars->next_variable)
                        print_variable(vars->name, vars->name_length, vars);

                /* manipulate the information ourselves */
                for(vars = response->variables; vars; vars = vars->next_variable) {
                        int count=1;
                        if (vars->type == ASN_OCTET_STR) {
                                char *sp = (char *)malloc(1 + vars->val_len);
                                memcpy(sp, vars->val.string, vars->val_len);
                                sp[vars->val_len] = '\0';
                                ret = string(sp);
                                free(sp);
                        }
                        else
                                printf("value #%d is NOT a string! Ack!\n", count++);
                }

        } 
        else {
                /*
                 * FAILURE: print what went wrong!
                 */

                if (status == STAT_SUCCESS)
                        fprintf(stderr, "Error in packet\nReason: %s\n",
                                        snmp_errstring(response->errstat));
                else
                        snmp_sess_perror("snmpget", ss);

        }
        /*
         * Clean up:
         *  1) free the response.
         *  2) close the session.
         */
        if (response)
                snmp_free_pdu(response);

        snmp_close(ss);

        /* windows32 specific cleanup (is a noop on unix) */
        SOCK_CLEANUP;

        return ret;
}

void nox_disconnect(int nox_sock)
{
    int msg_size = sizeof(messenger_msg);
    struct messenger_msg *msg = (struct messenger_msg *)malloc(msg_size);
    msg->length = htons((uint16_t)msg_size);
    msg->type = MSG_DISCONNECT;

    int bytes_out = 0;
    while(bytes_out < msg_size) {
	int tmpres = write(nox_sock, msg+bytes_out, msg_size-bytes_out);
	if (tmpres < 0) 
	    perror("ERROR writing to nox_sock");
	bytes_out += tmpres;
    }
    cout << "Written out DISCONNECT message to NOX controller." << endl;
    free(msg);
    close(nox_sock);
}

int nox_connect(struct sockaddr_in *nox_host)
{
    int sleep_interval = 1;
    int nox_sock;

    if((nox_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
	perror("Can't create NOX TCP socket");
	exit(1);
    }

    while(connect(nox_sock, (struct sockaddr *)nox_host, sizeof(struct sockaddr)) < 0){
	cout << "Could not connect to nox_host - retrying after " << sleep_interval << " seconds" << endl;
	sleep(sleep_interval);
	sleep_interval *= 2;
	if(sleep_interval > SLEEP_MAX) {
	    perror("Could not connect to nox_host - exiting");
	    exit(1);
	}
    }
    cout << "Connected to NOX controller" << endl;

    int msg_size = sizeof(messenger_msg) + sizeof(snmp_msg);
    struct messenger_msg *msg = (struct messenger_msg *)malloc(msg_size);
    msg->length = htons((uint16_t)msg_size);
    msg->type = MSG_SNMP;
    ((snmp_msg*)msg->body)->subtype = htons(SNMP_HELLO);

    int bytes_out = 0;
    while(bytes_out < msg_size) {
	int tmpres = write(nox_sock, msg+bytes_out, msg_size-bytes_out);
	if (tmpres < 0) 
	    perror("ERROR writing to nox_sock");
	bytes_out += tmpres;
    }
    cout << "Written out SNMP_HELLO message to NOX controller." << endl;
    free(msg);
    return nox_sock;
}

int nox_reconnect(int sock, struct sockaddr_in *nox_host)
{
    cout << "Reconnecting to the NOX controller" << endl;
    nox_disconnect(sock);
    return nox_connect(nox_host);
}

int main()
{
        /* Open nox-socket connection 
         * nox_sock: is the socket to nox
         */
        int nox_sock;
        char nox_ip[] = NOX_IP;
        struct sockaddr_in *nox_host= (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in *));
        nox_host->sin_family = AF_INET;
        int tmpres = inet_pton(AF_INET, nox_ip, (void *)(&(nox_host->sin_addr.s_addr)));
        if( tmpres < 0) {
                perror("Can't set nox_host->sin_addr.s_addr");
                exit(1);
        }
        else if(tmpres == 0) {
                fprintf(stderr, "%s is not a valid IP address\n", nox_ip);
                exit(1);
        }
        nox_host->sin_port = htons(NOX_PORT);

	nox_sock = nox_connect(nox_host);

        // ignore sigchld
        if(signal(SIGCHLD, SIG_IGN)) {
                perror("signal(SIGCHLD, SIG_IGN)");
        }
        char buffer[MAX_MSG_SIZE];
        while(true) {
                // read the message
                memset(buffer, '\0', MAX_MSG_SIZE);
                int buf_pt;
                bool read_error = false;
                for(buf_pt = 0; buf_pt < sizeof(messenger_msg); buf_pt++) {
                        int n = read(nox_sock, buffer+buf_pt, 1);
                        if(n < 0) {
                                perror("Error reading from socket");
                                read_error = true;
                                break;
                        }
                }
                if(read_error) {
		    nox_sock = nox_reconnect(nox_sock, nox_host);
                        continue;
                }
                messenger_msg *msg = (messenger_msg*)buffer;
                cout << "New message length = " << ntohs(msg->length) << endl;
                if(ntohs(msg->length) < sizeof(messenger_msg)) {
                        cout << "Malformed message" << endl;
		    nox_sock = nox_reconnect(nox_sock, nox_host);
                        continue;
                }
                if((uint8_t)(msg->type) != MSG_SNMP) {
                        cout << "Not MSG_SNMP : 0x" << (uint8_t)(msg->type) << " - ignoring" << endl;
                        continue;
                }
                for(; buf_pt < ntohs(msg->length); buf_pt++) {
                        int n = read(nox_sock, buffer+buf_pt, 1);
                        if(n < 0) {
                                perror("Error reading from socket");
                                read_error = true;
                                break;
                        }
                }
                if(read_error) {
		    nox_sock = nox_reconnect(nox_sock, nox_host);
                        continue;
                }

                // fork
                int pid = fork();
                if(pid == 0) {
                        init_snmp("snmpapp");
                        uint16_t length = ntohs(msg->length);
                        uint16_t subtype = ntohs(((snmp_msg*)(msg->body))->subtype);
                        uint32_t ip, val_size;
                        uint16_t oid_size;
                        string oid, ret;
                        // do sync snmp get/set calls, and 
                        if(subtype == SNMP_GET_STRING) {
                                ip = ntohl(((snmp_get_string*)(((snmp_msg*)(msg->body))->body))->ip_addr);
                                oid_size = ntohs(msg->length) - (sizeof(messenger_msg) + sizeof(snmp_msg) + sizeof(snmp_get_string));
                                oid = string(((snmp_get_string*)(((snmp_msg*)(msg->body))->body))->oid);
                                ret = snmp_get(ip, oid);
                                cout << "SNMP_GET_STRING : oid = " << oid << " return value = " << ret << endl;
                        }
                        else if(subtype == SNMP_SET_STRING) {
                                ip = ntohl(((snmp_sr_string*)(((snmp_msg*)(msg->body))->body))->ip_addr);
                                oid_size = ntohs(((snmp_sr_string*)(((snmp_msg*)(msg->body))->body))->oid_size);
                                oid = string(((snmp_sr_string*)(((snmp_msg*)(msg->body))->body))->oid_str);
                                string val = string(((snmp_sr_string*)(((snmp_msg*)(msg->body))->body))->oid_str + oid_size);
                                ret = snmp_set(ip, oid, val);
                                cout << "SNMP_SET_STRING : oid = " << oid << " return value = " << ret << endl;
                        }
                        else {
                                cout << "Unknown subtype : 0x" << setbase(16) << subtype << " - ignoring" << endl;
                                exit(0);
                        }

                        // return message via snmp-message
                        val_size = ret.length() + 1;
                        int msg_size = sizeof(messenger_msg) + sizeof(snmp_msg) + sizeof(snmp_sr_string) + oid_size + val_size;
                        messenger_msg *reply_msg = (messenger_msg*)malloc(msg_size);
                        reply_msg->type = MSG_SNMP;
                        reply_msg->length = htons(msg_size);
                        ((snmp_msg*)(reply_msg->body))->subtype = htons(SNMP_REPLY_STRING);
                        ((snmp_sr_string*)(((snmp_msg*)(reply_msg->body))->body))->ip_addr = htonl(ip);
                        ((snmp_sr_string*)(((snmp_msg*)(reply_msg->body))->body))->oid_size = htons(oid_size);
                        strncpy(((snmp_sr_string*)(((snmp_msg*)(reply_msg->body))->body))->oid_str, oid.c_str(), oid_size);
                        strncpy(((snmp_sr_string*)(((snmp_msg*)(reply_msg->body))->body))->oid_str + oid_size, ret.c_str(), val_size);

                        int bytes_out = 0;
                        while(bytes_out < msg_size) {
                                tmpres = write(nox_sock, reply_msg+bytes_out, msg_size-bytes_out);
                                if (tmpres < 0) {
                                        perror("ERROR writing to nox_sock");
                                        break;
                                }
                                bytes_out += tmpres;
                        }
                        cout << "Written out SNMP_REPLY_STRING to NOX controller." << endl;

                        free(reply_msg);
                        exit(0);
                }
        }

        return 0;
}
