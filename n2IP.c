
#include "n2IP.h"

err_t n2IP_init(void){
	
	//init arp table.
	return arp_init();
	
}

/*
 *Poll the Packet from net interface to n2IP's TCP/IP kernel.
 *
 *@param netif, a netif from low level.
 *
 *@return error code.
 *
**/
err_t n2IP_poll(Netif_t *netif){
	
	switch(netif->pType){
		case PROTYPE_IP:
				ip_poll(netif);
			break;
		case PROTYPE_ARP:
				arp_poll(netif);
			break;
		default:
			//just throw it.
			n2IP_log(N2IP_LAYER,"unknow protocol type!");
			return ERR_UNKNOWN;
	}
	
	return ERR_NONE;
	
}


/*
 *Drag from n2IP's TCP/IP kernel to netif.
 *
 *@param netif, a netif from low level.
 *
 *@return error code.
 *
**/
err_t n2IP_drag(Netif_t *netif){
	
	if(netif->outBuf)	n2IP_free(netif->outBuf);
	//alloc buf for output.
	switch(netif->If){
		case IFTYPE_ETHERNET:
			//最小帧
			if(netif->obSize < 46){
				netif->obSize = 46;
				netif->outBuf = n2IP_alloc(46);
				return ERR_NONE;
			}
			//超过最大帧
			if(netif->obSize > 1500){
				netif->obSize = 0;
				return ERR_NONE;
			}
		case IFTYPE_802_3:
			//最小帧
			if(netif->obSize < 40){
				netif->obSize = 40;
				netif->outBuf = n2IP_alloc(40);
				return ERR_NONE;
			}
			//超过最大帧
			if(netif->obSize > 1494){
				netif->obSize = 0;
				return ERR_NONE;
			}
	}
	n2IP_log(N2IP_LAYER,"alloc buf for output!");
	netif->outBuf = n2IP_alloc(netif->obSize);
	
	return ERR_NONE;
	
}


/*
 *Calulate the head len of n2IP.
 *
 *@param pType, cal the pType head len.
 *
 *@param opLen, addtition the opLen.
 *
 *@return error code.
 *
**/
U32_t n2IP_calen(U16_t pType, U32_t opLen){
	
	switch(pType){
		//PRO's head + opLen.
		case IFTYPE_ETHERNET:
			return 14 + opLen;
		case IFTYPE_802_3:
			return 20 + opLen;
		case PROTYPE_IP:
			return 20 + opLen;
		case PROTYPE_ARP:
			return 8 + opLen;
		default:
			n2IP_waring(N2IP_LAYER,"unknown type to calculate!");
			return (U32_t)-1;
	}
	
}


/*
 *Calulate the head len of ip n2IP.
 *
 *@param pType, cal the pType head len.
 *
 *@param opLen, addtition the opLen.
 *
 *@return error code.
 *
**/
U32_t n2IP_ipcalen(U16_t pType, U32_t opLen){
	
	switch(pType){
		//PRO's head + opLen.
		case IP_PRO_ICMP:
			return 4 + opLen;
		case IP_PRO_UDP:
			return 8 + opLen;
		case IP_PRO_TCP:
			return 20 + opLen;
		default:
			n2IP_waring(N2IP_LAYER,"unknown type to calculate!");
			return (U32_t)-1;
	}
	
}

/*
 *Display the netif.
 *
 *@param netif, the specific netif.
 *
 *@return .
 *
**/
/*void n2IP_netifShow(Netif_t *netif){
	
	n2IP_log(N2IP_LAYER, "Source addr: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x",
								eth->sAddr[0],eth->sAddr[1],eth->sAddr[2],eth->sAddr[3],
								eth->sAddr[4],eth->sAddr[5]);
	
}*/
/*
 *Compare the two IP address.
 *
 *@param remoteIP, the remote IP.
 *
 *@param localIP, the local IP.
 *
 *@param subMask, the subnetMask.
 *
 *@param len, the len of ip address.
 *
 *@return error code.
 *
**/
U8_t differ_subnet(U8_t *remoteIP, U8_t *localIP, U8_t *subMask, U8_t len){
	
	U8_t i = 0;
	
	while(len--){
		i |= (remoteIP[len]&subMask[len])^(subMask[len]&localIP[len]);
	}
	
	return i;
	
}

/*
 *Cast the IPv4's str to hex.
 *
 *@param ipdest, ip hex buf.
 *
 *@param str, the string of buf.
 *
 *@return.
 *
**/
void n2IP_IPv4Cast(U8_t *ipdest, char *str){
	
	U16_t tmp = 0;
	
	while(*str != 0){
		if(*str == '.'){
			*ipdest++ = tmp&0x00FF;
			tmp = 0;
		}else{
			tmp = tmp*10+*str-'0';
		}
		str++;
		
	}
	*ipdest = tmp&0x00FF;
	
}

/*
 *Calculate the 16bit check sum.
 *
 *@param ipdest, ip hex buf.
 *
 *@param str, the string of buf.
 *
 *@return.
 *
**/
U32_t n2IP_chksum16(void *buf, U32_t len, U32_t chksum, char complement){
	
	U16_t *tmp = (U16_t *)buf;
	
	while(len > 0){
		
		if(len == 1){
			chksum += ((*tmp)&0x00FF);
			break;
		}else{
			chksum += *tmp++;
		}
		len -= 2;
		
	}
	//加上进位，权值
	while(chksum & 0xFFFF0000){
		chksum = (chksum>>16)+(chksum&0xFFFF);
	}
	if(complement){
		//求反码
		return (U16_t)(~chksum);
	}
	return chksum;
	
}
