
/*
 *
 *The config file for n2IP.
 *
 */
 
#ifndef _N2IP_CONFIG_H_
#define _N2IP_CONFIG_H_

#include "rtthread.h"

//n2IP's format output.
//extern void rt_kprintf(const char *fmt, ...);
#define n2IP_printf		rt_kprintf

//n2IP's alloc free interface.
////extern void *rt_malloc(unsigned int size);
//#define n2IP_alloc		rt_malloc
////extern void rt_free(void *rmem);
//#define n2IP_free		rt_free
extern char tx_buf[2000];
#define n2IP_alloc(tmp)		(void *)(tx_buf)
#define n2IP_free(tmp)					

//n2IP debug configuration.
#define ETHERNET		1
#define LLC802_2		1
#define ARPPRO			1
#define IPPRO				1
#define ICMPPRO				1
#define N2IP_LAYER		1	//n2IP²ã
#define UDPPRO				1
#define TCPPRO				1
//#define ETHERNET		0
//#define LLC802_2		0
//#define ARPPRO			0
//#define IPPRO				0
//#define ICMPPRO				0
//#define N2IP_LAYER		0	//n2IP²ã

//ARP »º´æµÄARP±íÏî
#define ARP_CACHE_MAX_ENTRY		10
#define ARP_ENTRY_TIME_LIFE		100
#define ARP_ENTRY_REQ_TRY			10

//IP's options.
#define IP_PACK_TTL		128

//ICMP's options.
#define ICMP_PING_CONTENT		"Embedded Internet PING!"
#define ICMP_PING_IDETIFY		0xEE

#endif 
