/*
 *	Author:		GalaIO
 *	Date:			2015-9-9 11:17 AM
 *	Description:
 *		build the n2IP's ipv4 handle.
 *
 *	Updates note:
 *			1.code the simply function to handle ipv4.
 *
 *
**/

#include "n2IP.h"
#include "string.h"

static U16_t IP_id = 0;

/*
 *
 *Show IP Packet Header.
 *
 *@Param ip, the handler of ip header.
 *
 *return ERR_CODE.
 *
**/
err_t ip_showInfo(IPv4_t *ip){
	
	n2IP_log(IPPRO,"IP's Version    Type:   %d", ip->IPver_HEADLen>>4);
	n2IP_log(IPPRO,"IP's Header   Length:   %d", (ip->IPver_HEADLen&0x0F)*4);
	n2IP_log(IPPRO,"IP's Type of Service:   0x%02x", ip->DiffServ);
	n2IP_log(IPPRO,"IP's Total    Length:   %d", ntohs(ip->TotalLen));
	n2IP_log(IPPRO,"IP's Identify  Count:   %d", ntohs(ip->IdentifyCount));
	n2IP_log(IPPRO,"IP's Fragment   Flag:   0x%04x", ntohs(ip->Flag_FragOffset));
	n2IP_log(IPPRO,"IP's Time  To   Live:   %d", ip->TTL);
	n2IP_log(IPPRO,"IP's   Protocol Type:   %d", ip->ProtoclType);
	n2IP_log(IPPRO,"IP's Header CheckSum:   0x%04x", ntohs(ip->CheckNum));
	n2IP_log(IPPRO,"IP's Source  Address:   %d.%d.%d.%d", ip->srcAddr[0], 
													ip->srcAddr[1], ip->srcAddr[2], ip->srcAddr[3]);
	n2IP_log(IPPRO,"IP's Dstina  Address:   %d.%d.%d.%d", ip->dstAddr[0], 
													ip->dstAddr[1], ip->dstAddr[2], ip->dstAddr[3]);
	
	
	return ERR_NONE;
}

/*
 *
 *IP_drag from the higher level.
 *
 *@Param netif, the internet if.
 *
 *@Param ipDest, the dest ip.
 *
 *return ERR_CODE.
 *
**/
err_t ip_drag(Netif_t *netif){

	U16_t ip_len = 0;
	U8_t ip_head_len = 0;
	err_t err;
	IPv4_t *ip = (IPv4_t *)(netif->outBuf+n2IP_calen(IFTYPE_ETHERNET, 0));
	ip_head_len = n2IP_calen(PROTYPE_IP, 0) / 4;
	ip->IPver_HEADLen = ip_head_len&0x0F;
	ip->IPver_HEADLen |= 0x40&0xF0;
	ip_head_len = n2IP_calen(PROTYPE_IP, 0);
	ip->DiffServ = 0x00;
	ip_len = netif->obSize+ip_head_len;
	ip->TotalLen = htons(ip_len);
	ip->IdentifyCount = htons(IP_id++);
	ip->Flag_FragOffset = 0x0000;
	ip->TTL = IP_PACK_TTL;
	ip->ProtoclType = netif->pType;
	ip->CheckNum = 0x00;
	memcpy(ip->dstAddr, netif->spAddr, netif->paLen);
	memcpy(ip->srcAddr, netif->pAddr, netif->paLen);
	
//	ip->CheckNum = htons(n2IP_chksum16(ip, ip_head_len, 0 ,1));
	ip->CheckNum = n2IP_chksum16(ip, ip_head_len, 0 ,1);
	
	netif->pType = PROTYPE_IP;
	netif->obSize = ip_len;
	ip_showInfo(ip);
	//query mac addr.
	err = arp_query(netif, netif->spAddr, netif->dhAddr);
	//if there has arp-resolving, just output, else just free the memary.
	if(err != ERR_NOMAC){
		err = netif->drag(netif);
		//free the mem.
		n2IP_free(netif->outBuf);
		netif->obSize = 0;
	}
	
	return err;
}
/*
 *
 *IP_poll from the lower level.
 *
 *@Param netif, the internet if.
 *
 *return ERR_CODE.
 *
**/
err_t ip_poll(Netif_t *netif){
	
	IPv4_t *ip = (IPv4_t *)(netif->inBuf);
	
	//debug info.
	ip_showInfo(ip);
	
	//only support ipv4 version.
	if((ip->IPver_HEADLen & 0xF0) != 0x40){
		n2IP_waring(IPPRO, "IP packet version not support!!");
		return ERR_UNKNOWN;
	}
	//cannot support header option.
	if((ip->IPver_HEADLen & 0x0F) != 0x05){
		n2IP_waring(IPPRO, "IP header options not support!!");
		return ERR_UNKNOWN;
	}
	//cannot support fragmented packets.
	if((htons(ip->Flag_FragOffset) & 0x1FFF) != 0x0000){
		n2IP_waring(IPPRO, "IP cannot support fragmented packets!!");
		return ERR_UNKNOWN;
	}
	
	//verify the ip check num.
	do{
		U16_t chksum1 = ip->CheckNum, chksum2;
		ip->CheckNum = 0x0000;
		chksum2 = n2IP_chksum16((void *)ip, 4*(ip->IPver_HEADLen&0x0F), 0, 1);
		if(chksum2 != chksum1){
			n2IP_waring(IPPRO, "IP Bad CheckSum 0x%04x(it should be 0x%04x)!!",chksum1,chksum2);
			return ERR_EPARAM;
		}
		//reback the chksum segment.
		ip->CheckNum = chksum1;
	}while(0);
	//if the packet is for me.
	if(memcmp(ip->dstAddr, netif->pAddr, netif->paLen)) return ERR_EPARAM;
	//get ip Packet size.
	netif->ibSize = ntohs(ip->TotalLen) - (ip->IPver_HEADLen&0x0F)*4;
	netif->inBuf = ip->pData;
	//copy the request ip.
	memcpy(netif->spAddr, ip->srcAddr, netif->paLen);
	switch(ip->ProtoclType){
		
		case IP_PRO_ICMP:
			return icmp_poll(netif);
		
		case IP_PRO_UDP:
			return udp_poll(netif);
		
		case IP_PRO_TCP:
			return tcp_poll(netif);
	}
	//send icmp unreachable respone.
	n2IP_err(IPPRO, "unknow type!!");
	return icmp_drag(netif, ICMP_TYPE_DESUNREACH, ICMP_TYPE_DESUNREACH_PRO, (U8_t *)ip);
}
