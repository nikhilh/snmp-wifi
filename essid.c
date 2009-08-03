/*
 * Note: this file originally auto-generated by mib2c using
 *        : mib2c.scalar.conf 11805 2005-01-07 09:37:18Z dts12 $
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "essid.h"
#include "iwlib.h"		
#include "util.h"		

/**************************** CONSTANTS ****************************/

/*
 * Error codes defined for setting args
 */
#define IWERR_ARG_NUM		-2
#define IWERR_ARG_TYPE		-3
#define IWERR_ARG_SIZE		-4
#define IWERR_ARG_CONFLICT	-5
#define IWERR_SET_EXT		-6
#define IWERR_GET_EXT		-7

/**************************** VARIABLES ****************************/

/*
 * Ugly, but deal with errors in set_info() efficiently...
 */
static int	errarg;
static int	errmax;

/*------------------------------------------------------------------*/
/*
 * Set ESSID
 */
static int
set_essid(int		skfd,
	       char *		ifname,
	       char *		args[],		/* Command line args */
	       int		count)		/* Args count */
{
        struct iwreq wrq;
        int	i = 1;
        char essid[IW_ESSID_MAX_SIZE + 1];
        int	we_kernel_version;

        if((!strcasecmp(args[0], "off")) || (!strcasecmp(args[0], "any"))) {
                wrq.u.essid.flags = 0;
                essid[0] = '\0';
        }
        else
                if(!strcasecmp(args[0], "on")) {
                        /* Get old essid */
                        memset(essid, '\0', sizeof(essid));
                        wrq.u.essid.pointer = (caddr_t) essid;
                        wrq.u.essid.length = IW_ESSID_MAX_SIZE + 1;
                        wrq.u.essid.flags = 0;
                        if(iw_get_ext(skfd, ifname, SIOCGIWESSID, &wrq) < 0)
                                return(IWERR_GET_EXT);
                        wrq.u.essid.flags = 1;
                }
                else {
                        i = 0;
                        /* '-' or '--' allow to escape the ESSID string, allowing
                         * to set it to the string "any" or "off".
                         * This is a big ugly, but it will do for now */
                        if((!strcmp(args[0], "-")) || (!strcmp(args[0], "--"))) {
                                if(++i >= count)
                                        return(IWERR_ARG_NUM);
                        }

                        /* Check the size of what the user passed us to avoid
                         * buffer overflows */
                        if(strlen(args[i]) > IW_ESSID_MAX_SIZE) {
                                errmax = IW_ESSID_MAX_SIZE;
                                return(IWERR_ARG_SIZE);
                        }
                        else {
                                int		temp;
                                wrq.u.essid.flags = 1;
                                strcpy(essid, args[i]);	/* Size checked, all clear */
                                i++;

                                /* Check for ESSID index */
                                if((i < count) && (sscanf(args[i], "[%i]", &temp) == 1) &&
                                   (temp > 0) && (temp < IW_ENCODE_INDEX)) {
                                        wrq.u.essid.flags = temp;
                                        ++i;
                                }
                        }
                }

        /* Get version from kernel, device may not have range... */
        we_kernel_version = iw_get_kernel_we_version();

        /* Finally set the ESSID value */
        wrq.u.essid.pointer = (caddr_t) essid;
        wrq.u.essid.length = strlen(essid);
        if(we_kernel_version < 21)
                wrq.u.essid.length++;

        if(iw_set_ext(skfd, ifname, SIOCSIWESSID, &wrq) < 0)
                return(IWERR_SET_EXT);

        /* Var args */
        return(i);
}

/** Initializes the essid module */
void
init_essid(void)
{
    static oid essid_oid[] = { 1,3,6,1,3,108,0,4 };

  DEBUGMSGTL(("essid", "Initializing\n"));

    netsnmp_register_scalar(
        netsnmp_create_handler_registration("essid", handle_essid,
                               essid_oid, OID_LENGTH(essid_oid),
                               HANDLER_CAN_RWRITE
        ));
}

int
handle_essid(netsnmp_mib_handler *handler,
                          netsnmp_handler_registration *reginfo,
                          netsnmp_agent_request_info   *reqinfo,
                          netsnmp_request_info         *requests)
{
    int ret;

    static int skfd;
    struct iwreq wrq;
    char essid[IW_ESSID_MAX_SIZE + 1];
	memset(essid, '\0', sizeof(essid));

    /* We are never called for a GETNEXT if it's registered as a
       "instance", as it's "magically" handled for us.  */

    /* a instance handler also only hands us one request at a time, so
       we don't need to loop over a list of requests; we'll only get one. */
    
    switch(reqinfo->mode) {

        case MODE_GET:
                printf("essid MODE_GET\n");
                /* Create a channel to the NET kernel. */
                if((skfd = iw_sockets_open()) >= 0) {
                        /* Get essid*/
                        wrq.u.essid.pointer = (caddr_t) essid;
                        wrq.u.essid.length = IW_ESSID_MAX_SIZE + 1;
                        wrq.u.essid.flags = 0;
                        if(iw_get_ext(skfd, INTERFACE, SIOCGIWESSID, &wrq) >= 0) {
                                // Does it matter what I do here?
                        }
                        /* Close the socket. */
                        iw_sockets_close(skfd);
                }
                snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,
                                (u_char *) essid, strlen(essid));
            break;

        /*
         * SET REQUEST
         *
         * multiple states in the transaction.  See:
         * http://www.net-snmp.org/tutorial-5/toolkit/mib_module/set-actions.jpg
         */
        case MODE_SET_RESERVE1:
                printf("essid MODE_SET_RESERVE1\n");
                /* or you could use netsnmp_check_vb_type_and_size instead */
            ret = netsnmp_check_vb_type(requests->requestvb, ASN_OCTET_STR);
            if ( ret != SNMP_ERR_NOERROR ) {
                netsnmp_set_request_error(reqinfo, requests, ret );
            }
            break;

        case MODE_SET_RESERVE2:
                printf("essid MODE_SET_RESERVE2\n");
            /* malloc "undo" storage buffer */
            if((skfd = iw_sockets_open()) < 0) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_RESOURCEUNAVAILABLE);
            }
            break;

        case MODE_SET_FREE:
                printf("essid MODE_SET_FREE\n");
            /* free resources allocated in RESERVE1 and/or
               RESERVE2.  Something failed somewhere, and the states
               below won't be called. */
            if(skfd >= 0)
                    iw_sockets_close(skfd);
            break;

        case MODE_SET_ACTION:
                printf("essid MODE_SET_ACTION\n");
            /* perform the value change here */
            ret = set_essid(skfd, INTERFACE, (char**)&(requests->requestvb->val.string), 1);
            if (ret <= 0) {
                netsnmp_set_request_error(reqinfo, requests, ret);
            }
            break;

        case MODE_SET_COMMIT:
                printf("essid MODE_SET_COMMIT\n");
            /* delete temporary storage */
            if(skfd >= 0)
                    iw_sockets_close(skfd);
            break;

        case MODE_SET_UNDO:
                printf("essid MODE_SET_UNDO\n");
            break;

        default:
            /* we should never get here, so this is a really bad error */
            snmp_log(LOG_ERR, "unknown mode (%d) in handle_essid\n", reqinfo->mode );
            return SNMP_ERR_GENERR;
    }

                printf("essid - return\n");
    return SNMP_ERR_NOERROR;
}