
#include "n2IP.h"
#include "string.h"

/*
 *Udp_init 初始化udp套接字
 *
 *@Param netif, the handler of netif
 *
 *@return .
 *
**/
void udp_init(Netif_t *netif){
	int iSocket;
	UCB_t	*pSocket = netif->ucb_table;
	
	//依次初始化 各参数
	for(iSocket=0; iSocket<netif->ucb_size; iSocket++){
		pSocket[iSocket].state = UDP_SOCKET_FREE;
		pSocket[iSocket].local_port = 0x0000;
		pSocket[iSocket].event_handler = NULL;
		pSocket[iSocket].options = 0x00;
	}
	
}

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
	n2IP_log(UDPPRO, "Check Sum:			   0x%4x", udp->chksum);
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
			//wrong udp, just throw it.
			return ERR_ECHKSUM;
		}
		//recover the chksum of udp.
		if(chksum2 == 0x0000){
			udp->chksum = 0xFFFF;
		}else{
			udp->chksum = chksum2;
		}
		
	}
	do{
		U16_t i;
		//find the socket, and exec the callback.
		for(i=0; i<netif->ucb_size; i++){
			if(netif->ucb_table[i].local_port == ntohs(udp->destPort) &&
					netif->ucb_table[i].state != UDP_SOCKET_FREE){
				//传递给一个udp 客户端
				if(netif->ucb_table[i].options & UDP_SOCKET_CLIENT){
					//需要检查 对方的ip是否符合
					if(memcmp(netif->spAddr, netif->ucb_table[i].remote_ip, netif->paLen) == 0){
						netif->ucb_table[i].event_handler(netif->ucb_table+i, udp->pData, ntohs(udp->totalLen)-n2IP_ipcalen(IP_PRO_UDP, 0));
						return ERR_NONE;
					}else{
						return ERR_NOSOCKET;
					}
					
				}else if(netif->ucb_table[i].options & UDP_SOCKET_SERVER){
					//如果传递给一个服务器，需要复制传递来的ip和port端口号,这是服务器需要知道的基本信息。
					memcpy(netif->ucb_table[i].remote_ip, netif->spAddr, netif->paLen);
					netif->ucb_table[i].remote_port = ntohs(udp->srcPort);
					netif->ucb_table[i].event_handler(netif->ucb_table+i, udp->pData, ntohs(udp->totalLen)-n2IP_ipcalen(IP_PRO_UDP, 0));
					return ERR_NONE;
					
				}else{
					//no error.
					return ERR_NOSOCKET;
				}
			}
		}
	}while(0);
	//unreachable the Port.
	return icmp_drag(netif, ICMP_TYPE_DESUNREACH, ICMP_TYPE_DESUNREACH_PORT, netif->inBuf-n2IP_calen(PROTYPE_IP, 0));

}
/*
 *
 *drag data from udp to ip layer.
 *
 *@param netif, the handle of net interface.
 *
 *@param udp_socket, the handle of udp socket.
 *
 *@param data, the first address of data.
 *
 *@param len, the total len of data.
 *
 *@return ERR_CODE.
 *
**/
err_t udp_drag(Netif_t *netif, UCB_t *udp_socket, U8_t *data, U32_t len){
	
	UDP_t *udp;
	PSEUDO_IPV4_HDR_t p_hdr;
	U16_t	chksum;
	
	netif->obSize = n2IP_calen(IFTYPE_ETHERNET, 0)+
													n2IP_calen(PROTYPE_IP, 0)+
													n2IP_ipcalen(IP_PRO_UDP, len);
	//申请空间
	n2IP_drag(netif);
	//没有申请到空间，返回错误
	if(netif->obSize == 0) return ERR_NOMEM;
	
	udp = (UDP_t *)(netif->outBuf+n2IP_calen(IFTYPE_ETHERNET, 0)+n2IP_calen(PROTYPE_IP, 0));
	
	//填充udp
	udp->destPort = htons(udp_socket->remote_port);
	udp->srcPort = htons(udp_socket->local_port);
	udp->totalLen = htons(n2IP_ipcalen(IP_PRO_UDP, len));
	memcpy(udp->pData, data, len);
	udp->chksum = 0x0000;
	
	//填充udp的伪首部
	p_hdr.pType = IP_PRO_UDP;
	p_hdr.tLen = udp->totalLen;
	p_hdr.zero = 0x00;
	memcpy(p_hdr.destIP, udp_socket->remote_ip, netif->paLen);
	memcpy(p_hdr.srcIP, netif->pAddr, netif->paLen);
	chksum = n2IP_chksum16(&p_hdr, sizeof(p_hdr), 0, 0);
	//add to chksum2.
	chksum = n2IP_chksum16(udp, ntohs(udp->totalLen), chksum, 1);
	//填充udp校验码
	if(chksum != 0x0000){
		udp->chksum = chksum;
	}else{
		udp->chksum = 0xFFFF;
	}
	udpDisplay(udp);
	netif->obSize = n2IP_ipcalen(IP_PRO_UDP, len);
	//把目标ip复制到netif的临界存储空间中
	memcpy(netif->spAddr, udp_socket->remote_ip, netif->paLen);
	netif->pType = IP_PRO_UDP;
	//交给ip层
	return ip_drag(netif);
	
}

/*
 *以客户端模式打开一个udp的socket连接
 *
 *@param destip, the destination ip of udp socket.
 *
 *@param pLen, the len of ip addr.
 *
 *@param destPort, the destination port of udp socket. 
 *
 *@param event_handler, the callback handler of udp socket.
 *
 *@return a handle of socket.
 *
*/
UCB_t *udp_socket_connect(Netif_t *netif, char *strip, U8_t pLen, U16_t destPort, 
			void  (*event_handler)(struct ucb *socket, U8_t *inBuf, U32_t tLen)){
	
	//find a avlivable ucb.
	int i;
	UCB_t *ucb;
	U8_t 	destip[4];
	if(pLen != 4)  return NULL;
	n2IP_IPv4Cast(destip,strip);
	for(i=0; i<netif->ucb_size; i++){
		if(netif->ucb_table[i].state == UDP_SOCKET_FREE) break;
	}
	if(i >= netif->ucb_size) return NULL;
	
	ucb = netif->ucb_table+i;
	memcpy(ucb->remote_ip, destip, pLen);
	ucb->remote_port = destPort;
	ucb->local_port = UDP_SOCKET_PORT_START+i;
	ucb->event_handler = event_handler;
	ucb->pLen = pLen;
	ucb->state = UDP_SOCKET_USED;
	ucb->options |= UDP_SOCKET_CLIENT;
		
	return ucb;
	
}


/*
 *以服务器模式打开一个udp的socket连接,监听到来的数据
 *
 *@param destip, the destination ip of udp socket.
 *
 *@param localPort, the local port of udp socket. 
 *
 *@param event_handler, the callback handler of udp socket.
 *
 *@return a handle of socket.
 *
*/
UCB_t *udp_socket_listen(Netif_t *netif, U16_t localPort, 
			void  (*event_handler)(struct ucb *socket, U8_t *inBuf, U32_t tLen)){
	
	//find a avlivable ucb.
	int i;
	UCB_t *ucb;
	for(i=0; i<netif->ucb_size; i++){
		if(netif->ucb_table[i].state == UDP_SOCKET_FREE) break;
	}
	if(i >= netif->ucb_size) return NULL;
	
	ucb = netif->ucb_table+i;
	ucb->local_port = localPort;
	ucb->event_handler = event_handler;
	ucb->state = UDP_SOCKET_USED;
	ucb->options |= UDP_SOCKET_SERVER;
		
	return ucb;
	
}
			
err_t udp_socket_close(UCB_t *ucb){
	
	if(ucb != NULL){
		ucb->state = UDP_SOCKET_FREE;
		ucb->local_port = 0x00;
		ucb->options = 0x00;
	}
	
	return ERR_NONE;
}

			
err_t udp_socket_write(Netif_t *netif, UCB_t *udp_socket, U8_t *data, U32_t len){
	
	return udp_drag(netif, udp_socket, data, len);
	
}


