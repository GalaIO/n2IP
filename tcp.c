
#include "n2IP.h"
#include "string.h"

/*
 *Display the info of udp.
 *
 *@Param udp, the handle of tcp. 
 *
 *@Param len, the total len of tcp, get from ip segment. 
 *
 *@return .
 *
**/
void tcpDisplay(const TCP_t *tcp, U32_t len){
	
	int i;
	n2IP_log(TCPPRO, "TCP message:");
	n2IP_log(TCPPRO, "Source Port:          %d", ntohs(tcp->srcPort));
	n2IP_log(TCPPRO, "Destination Port:     %d", ntohs(tcp->destPort));
	n2IP_log(TCPPRO, "Sequence Number:      %u", ntohs(tcp->seq));
	n2IP_log(TCPPRO, "Acknowledg,Number:    %u", tcp->ack);
	if(((tcp->dataOffset)>>4) != 0x00){
		U32_t opLen = ((tcp->dataOffset)>>4)*4 - n2IP_ipcalen(IP_PRO_TCP, 0);
		len = len-opLen-n2IP_ipcalen(IP_PRO_TCP, 0);
		n2IP_log(TCPPRO, "Data Offset:        %d bytes(Options Length: %d bytes / Data Len: %d bytes)", ((tcp->dataOffset)>>4)*4, opLen, len);
	}else{
		len = 0;
		n2IP_log(TCPPRO, "Data Offset:        0 bytes");
	}
	n2IP_log(TCPPRO, "TCP Flags:            0x%02x", tcp->flags);
	if(tcp->flags & TCP_FLAG_FIN){
		n2IP_log(TCPPRO, "           --FIN");
	}
	if(tcp->flags & TCP_FLAG_SYN){
		n2IP_log(TCPPRO, "           --SYN");
	}
	if(tcp->flags & TCP_FLAG_FIN){
		n2IP_log(TCPPRO, "           --FIN");
	}
	if(tcp->flags & TCP_FLAG_RST){
		n2IP_log(TCPPRO, "           --RST");
	}
	if(tcp->flags & TCP_FLAG_PSH){
		n2IP_log(TCPPRO, "           --PSH");
	}
	if(tcp->flags & TCP_FLAG_ACK){
		n2IP_log(TCPPRO, "           --ACK");
	}
	n2IP_log(TCPPRO, "Windows:               %d", ntohs(tcp->window));
	n2IP_log(TCPPRO, "CheckSum:              0x%04x", tcp->chksum);
	n2IP_log(TCPPRO, "Urgent Pointer:        %d", ntohs(tcp->urgentPtr));
	n2IP_log(TCPPRO, "Content Data:");
	
	for(i=0; i<len; i++){
		n2IP_print(TCPPRO, "%c", tcp->pData[i]);
	}
	n2IP_print(TCPPRO, "\r\n-------------------------------------------\r\n");
}

err_t tcp_poll(Netif_t *netif){
	
	PSEUDO_IPV4_HDR_t p_hdr;
	TCP_t  *tcp = (TCP_t *)(netif->inBuf);
	//check the chksum segment.
	U16_t chksum1,chksum2;
	//show info of udp.
	tcpDisplay(tcp, netif->ibSize);
	
	//clear the chksum segment.
	chksum1 = tcp->chksum;
	tcp->chksum = 0x0000;
	//construct the pseudo header.
	memcpy(&(p_hdr.srcIP), netif->spAddr, netif->paLen);
	memcpy(&(p_hdr.destIP), netif->pAddr, netif->paLen);
	p_hdr.zero = 0x00;
	p_hdr.pType = IP_PRO_TCP;
	//pseudo header is tcp's len, from ip hdr.
	p_hdr.tLen = htons(netif->ibSize);
	chksum2 = n2IP_chksum16(&p_hdr, sizeof(p_hdr), 0, 0);
	//add to chksum2.
	chksum2 = n2IP_chksum16(tcp, netif->ibSize, chksum2, 1);
	if(chksum1 != chksum2){
		n2IP_waring(TCPPRO, "Bad Check 0x%04x(it should be 0x%04x)", chksum1, chksum2);
		return ERR_ECHKSUM;
	}
	//recover the chksum of tcp.
	tcp->chksum = chksum2;
		
	//unreachable the Port.
	return icmp_drag(netif, ICMP_TYPE_DESUNREACH, ICMP_TYPE_DESUNREACH_PORT, netif->inBuf-n2IP_calen(PROTYPE_IP, 0));

}

