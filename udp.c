
#include "n2IP.h"
#include "string.h"

/*
 *Display the info of udp.
 *
 *@Param udp, the handle od udp. 
 *
 *@return .
 *
**/
void udpDisplay(UDP_t *udp){ 
	
	int i;
	
	n2IP_log(UDPPRO, "UDP message:");
	n2IP_log(UDPPRO, "Source Port:  		 %d", ntohs(udp->srcPort));
	n2IP_log(UDPPRO, "Destination Port:  %d", ntohs(udp->destPort));
	n2IP_log(UDPPRO, "Total Length:  		 %d", ntohs(udp->totalLen));
	n2IP_log(UDPPRO, "Check Sum:			   %d", udp->chksum);
	n2IP_log(UDPPRO, "Cotent Data:");
	
	for(i=0; i<(ntohs(udp->totalLen)-8); i++){
		n2IP_print(UDPPRO, "%c", udp->pData[i]);
	}
	n2IP_print(UDPPRO, "\r\n-------------------------------------------\r\n");
}
/*
 *poll data from ip layer.
 *
 *@return ERR code.
 *
**/
err_t udp_poll(Netif_t *netif){
	
	PSEUDO_IPV4_HDR_t p_hdr;
	UDP_t  *udp = (UDP_t *)(netif->inBuf);
	//show info of udp.
	udpDisplay(udp);
	
	//check the chksum segment.
	if(udp->chksum != 0x0000){
		U16_t chksum1,chksum2;
		//clear the chksum segment.
		if(udp->chksum == 0xFFFF){
			udp->chksum = 0x0000;
			chksum1 = 0x0000;
		}else{
			chksum1 = udp->chksum;
			udp->chksum = 0x0000;
		}
		//construct the pseudo header.
		memcpy(&(p_hdr.srcIP), netif->spAddr, netif->paLen);
		memcpy(&(p_hdr.destIP), netif->pAddr, netif->paLen);
		p_hdr.zero = 0x00;
		p_hdr.pType = IP_PRO_UDP;
		p_hdr.tLen = udp->totalLen;
		chksum2 = n2IP_chksum16(&p_hdr, sizeof(p_hdr), 0, 0);
		//add to chksum2.
		chksum2 = n2IP_chksum16(udp, ntohs(udp->totalLen), chksum2, 1);
		if(chksum1 != chksum2){
			n2IP_waring(UDPPRO, "Bad Check %04x(it should be %04x)", chksum1, chksum2);
			return ERR_ECHKSUM;
		}
		//recover the chksum of udp.
		if(chksum2 == 0x0000){
			udp->chksum = 0xFFFF;
		}else{
			udp->chksum = chksum2;
		}
		
	}
	//unreachable the Port.
	return icmp_drag(netif, ICMP_TYPE_DESUNREACH, ICMP_TYPE_DESUNREACH_PORT, netif->inBuf-n2IP_calen(PROTYPE_IP, 0));

}

