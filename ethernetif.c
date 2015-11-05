/*
 *	Author:		GalaIO
 *	Date:			2015-9-9 11:17 AM
 *	Description:
 *		build the n2IP's Ethernet Interface.
 *
 *	Updates note:
 *			1.code the simply function to handle the base Ethernet Frame.
 *
 *
**/

#include "n2IP.h"
#include "rtuser.h"
#include "string.h"

//defien the interface of ethernet.
Netif_t eth_if;
char tx_buf[2000];

/*
 *Display the specific Ethernet segment which received.
 *
 *@param eth, the info of ethernet.
 *
 *@return .
 *
**/
static void ethPacket_displayInfo(Ethernet_t *eth){
		
	n2IP_log(ETHERNET, "Destination addr: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x",
								eth->dAddr[0],eth->dAddr[1],eth->dAddr[2],eth->dAddr[3],
								eth->dAddr[4],eth->dAddr[5]);
	n2IP_log(ETHERNET, "Source addr: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x",
								eth->sAddr[0],eth->sAddr[1],eth->sAddr[2],eth->sAddr[3],
								eth->sAddr[4],eth->sAddr[5]);
	
	n2IP_log(ETHERNET, "The protol type: 0x%04x\r\n", ntohs(eth->pType));
}

/*
 *A simple handler for Ethernet Packet.
 *
 *@param eth_buf, data from interface.
 *
 *@return .
 *
**/
static err_t ethernet_poll(Netif_t *eth_if, U8_t *eth_buf, U32_t size){
	
	Ethernet_t *eth = (Ethernet_t *)eth_buf;
	
	//display info.
	ethPacket_displayInfo(eth);
	
	//match EthernetII.
	if(ntohs(eth->pType) > 0x05DC){
		eth_if->pType = ntohs(eth->pType);
		eth_if->inBuf = eth->pData;
	}else{
		//match 802.3.
		LLC802_t *llc = (LLC802_t *)eth->pData;
		n2IP_log(ETHERNET, "a 802.2 LLC!!");
		//just ignore the LLC segment.
		eth_if->pType = ntohs(eth->pType);
		eth_if->inBuf = llc->pData;
	}
	
	eth_if->ibSize = size;
	
	//poll to n2IP kernel.
	return eth_if->poll(eth_if);

//		return ERR_NONE;
	
}

void ethernetif_show(Netif_t *eth_if){
	n2IP_log(ETHERNET, "The EthernetIF's TYPE: ETHERNET");
	n2IP_log(ETHERNET, "The EthernetIF's MAC:  %02x %02x %02x %02x %02x %02x ", 
													eth_if->hAddr[0], eth_if->hAddr[1], eth_if->hAddr[2], 
													eth_if->hAddr[3], eth_if->hAddr[4], eth_if->hAddr[5]);
	n2IP_log(ETHERNET, "The EthernetIF's IP:   %d.%d.%d.%d", 
													eth_if->pAddr[0], eth_if->pAddr[1], eth_if->pAddr[2], 
													eth_if->pAddr[3]);
	n2IP_log(ETHERNET, "The EthernetIF's GATE: %d.%d.%d.%d", 
													eth_if->pgAddr[0], eth_if->pgAddr[1], eth_if->pgAddr[2], 
													eth_if->pgAddr[3]);
	n2IP_log(ETHERNET, "The EthernetIF's MASK: %d.%d.%d.%d", 
													eth_if->pmAddr[0], eth_if->pmAddr[1], eth_if->pmAddr[2], 
													eth_if->pmAddr[3]);
}

err_t ethernetif_drag(Netif_t *eth_if){
	
	Ethernet_t *eth = (Ethernet_t *)eth_if->outBuf;
	
	//fill eth head.
	memcpy(eth->dAddr, eth_if->dhAddr, eth_if->haLen);
	memcpy(eth->sAddr, eth_if->hAddr, eth_if->haLen);
	eth->pType = htons(eth_if->pType);
	eth_if->obSize = eth_if->obSize+n2IP_calen(IFTYPE_ETHERNET, 0);
	//show info.
	ethPacket_displayInfo(eth);
	n2IP_log(ETHERNET, "\r\n\r\n");
	
	return eth_if->low_output(eth_if->outBuf, eth_if->obSize);
	
}

/*
 *Init a etherner interface.
 *
 *@param eth_if, if hander.
 *
 *@return err code.
 *
**/
err_t ethernetif_init(Netif_t *eth_if){
	
	eth_if->If = IFTYPE_ETHERNET;
	eth_if->haLen = 6;
	eth_if->paLen = 4;
	eth_if->obSize = 0;
	eth_if->paType = PROTYPE_IP;
	eth_if->pType = PROTYPE_UNKNOWN;
	
	memcpy(eth_if->hAddr, "abcdefgh", eth_if->haLen);
	n2IP_IPv4Cast(eth_if->pAddr, "192.168.1.8");
	n2IP_IPv4Cast(eth_if->pgAddr, "192.168.1.1");
	n2IP_IPv4Cast(eth_if->pmAddr, "255.255.255.0");
	
	eth_if->low_output = NULL;
	
	eth_if->low_input = ethernet_poll;
	eth_if->poll = n2IP_poll;
	eth_if->drag = ethernetif_drag;
	
	eth_if->inBuf = NULL;
	eth_if->ibSize = 0;
	eth_if->obSize = 0;
	
	eth_if->outBuf = NULL;
	
	//show the log info of the if.
	ethernetif_show(eth_if);
	
	return ERR_NONE;
	
}

/*
 *Init a etherner interface.
 *
 *@param eth_if, if hander.
 *
 *@return err code.
 *
**/
err_t ethernetif_initParams(Netif_t *eth_if, char *mac, char *ip, char *gatway, char *mask){
	
	eth_if->If = IFTYPE_ETHERNET;
	eth_if->haLen = 6;
	eth_if->paLen = 4;
	eth_if->obSize = 0;
	eth_if->paType = PROTYPE_IP;
	eth_if->pType = PROTYPE_UNKNOWN;
	
	memcpy(eth_if->hAddr, mac, eth_if->haLen);
	n2IP_IPv4Cast(eth_if->pAddr, ip);
	n2IP_IPv4Cast(eth_if->pgAddr, gatway);
	n2IP_IPv4Cast(eth_if->pmAddr, mask);
	
	eth_if->low_output = NULL;
	
	eth_if->low_input = ethernet_poll;
	eth_if->poll = n2IP_poll;
	eth_if->drag = ethernetif_drag;
	
	eth_if->inBuf = NULL;
	eth_if->ibSize = 0;
	eth_if->obSize = 0;
	
	eth_if->outBuf = NULL;
	
	//show the log info of the if.
	ethernetif_show(eth_if);
	
	return ERR_NONE;
	
}
