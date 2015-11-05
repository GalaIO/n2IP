/*
 *	Author:		GalaIO
 *	Date:			2015-10-30 19:32 PM
 *	Description:
 *		build the n2IP's icmp handle.
 *
 *	Updates note:
 *			1.code the simply function to handle icmp.
 *
 *
**/

#include "n2IP.h"
#include "string.h"

/*
 *
 *Show the detail of icmp.
 *
 *@Param icmp, icmp header.
 *
 *return .
 *
**/
void icmp_showInfo(ICMP_t *icmp){
	
	n2IP_log(ICMPPRO, "ICMP pack's Header: ");
	n2IP_log(ICMPPRO, "  Type: %d", icmp->type);
	n2IP_log(ICMPPRO, "  Code: %d", icmp->code);
	n2IP_log(ICMPPRO, "  CheckSum: 0x%04x", icmp->chksum);

}

/*
 *
 *icmp_roll from the lower level.
 *
 *@Param netif, the internet if.
 *
 *return ERR_CODE.
 *
**/
err_t icmp_drag(Netif_t *netif, U8_t type, U8_t code, void *data){
	
	ICMP_t *icmp;
	static U8_t idd;
	switch(type){
		//ping request
		case ICMP_TYPE_REQUESTREPLY:
				netif->obSize = n2IP_calen(IFTYPE_ETHERNET, 0)+
													n2IP_calen(PROTYPE_IP, 0)+
													n2IP_ipcalen(IP_PRO_ICMP, 4+sizeof(ICMP_PING_CONTENT));
				//alloc for memery.
				n2IP_drag(netif);
				icmp = (ICMP_t *)(netif->outBuf+n2IP_calen(IFTYPE_ETHERNET, 0)+n2IP_calen(PROTYPE_IP, 0));
				//copy data
				memcpy(icmp+4+n2IP_ipcalen(IP_PRO_ICMP, 0), ICMP_PING_CONTENT, sizeof(ICMP_PING_CONTENT));
				icmp->type = ICMP_TYPE_REQUESTREPLY;
				icmp->code = 0x00;
				(*(icmp->pData+4)) = ICMP_PING_IDETIFY;
				(*(icmp->pData+5)) = 0x00;
				(*(icmp->pData+6)) = ++idd;
				(*(icmp->pData+7)) = 0x00;
				//set the procotol type for lower level.
				netif->pType = IP_PRO_ICMP;
				//update the mem's affect size.
				netif->obSize = n2IP_ipcalen(IP_PRO_ICMP, 4+sizeof(ICMP_PING_CONTENT));
//				//get destination ip.
//				memcpy(netif->spAddr, data, netif->paLen);
//				icmp->chksum = htons(n2IP_chksum16(icmp, netif->obSize, 0, 1));
//				//drag to ip.
//				return ip_drag(netif);
				break;
		//ping respone
		case ICMP_TYPE_RESPONEREPLY:
				//fix value.
				((ICMP_t *)data)->type = type;
				((ICMP_t *)data)->code = 0;
				netif->obSize = n2IP_calen(IFTYPE_ETHERNET, 0)+
													n2IP_calen(PROTYPE_IP, 0)+
													n2IP_ipcalen(IP_PRO_ICMP, netif->ibSize-4);
				//alloc for memery.
				n2IP_drag(netif);
				//copy data
				icmp = (ICMP_t *)(netif->outBuf+n2IP_calen(IFTYPE_ETHERNET, 0)+n2IP_calen(PROTYPE_IP, 0));
				memcpy(icmp, data, netif->ibSize);
				//set the procotol type for lower level.
				netif->pType = IP_PRO_ICMP;
				//update the mem's affect size.
				netif->obSize = netif->ibSize;
//				//drag to ip.
//				return ip_drag(netif);
				break;
		//destination unreachable.
		case ICMP_TYPE_DESUNREACH:
				netif->obSize = n2IP_calen(IFTYPE_ETHERNET, 0)+
													n2IP_calen(PROTYPE_IP, 0)+
													n2IP_ipcalen(IP_PRO_ICMP, n2IP_calen(PROTYPE_IP, 4+8));
				//alloc for memery.
				n2IP_drag(netif);
				icmp = (ICMP_t *)(netif->outBuf+n2IP_calen(IFTYPE_ETHERNET, 0)+n2IP_calen(PROTYPE_IP, 0));
				icmp->type = ICMP_TYPE_DESUNREACH;
				icmp->code = code;
				//reserved.
				/*icmp->pData[0] = 0x00;
				icmp->pData[1] = 0x00;
				icmp->pData[2] = 0x00;
				icmp->pData[3] = 0x00;*/
				memset(icmp->pData, 0x00, 4);
				do{
					IPv4_t *ip = (IPv4_t *)data;
					//copy the ip header + 8 bytes of data segment.
					if(ntohs(ip->TotalLen) - (ip->IPver_HEADLen&0x0F)*4 < 8){
						memcpy(icmp->pData+4, data, ntohs(ip->TotalLen));
					}else{
						memcpy(icmp->pData+4, data, (ip->IPver_HEADLen&0x0F)*4+8);
					}
				}while(0);
				//set the procotol type for lower level.
				netif->pType = IP_PRO_ICMP;
				//update the mem's affect size.
				netif->obSize = n2IP_ipcalen(IP_PRO_ICMP, n2IP_calen(PROTYPE_IP, 4+8));
//				//get destination ip.
//				memcpy(netif->spAddr, data, netif->paLen);
//				icmp->chksum = htons(n2IP_chksum16(icmp, netif->obSize, 0, 1));
//				//drag to ip.
//				return ip_drag(netif);
				break;
		default:
			n2IP_log(ICMPPRO, "unsupport icmp packet type!");
			return ERR_UNKNOWN;
	}
	icmp->chksum = 0;
//	icmp->chksum = htons(n2IP_chksum16(icmp, netif->obSize, 0, 1));
	icmp->chksum = n2IP_chksum16(icmp, netif->obSize, 0, 1);
	icmp_showInfo(icmp);
  //drag to ip.
	return ip_drag(netif);
}

/*
 *
 *icmp_roll from the lower level.
 *
 *@Param netif, the internet if.
 *
 *return ERR_CODE.
 *
**/
err_t icmp_poll(Netif_t *netif){
	
	ICMP_t *icmp = (ICMP_t *)(netif->inBuf);
	icmp_showInfo(icmp);
	//check the CheckSum.
	do{
		U16_t chksum1,chksum2;
		chksum1 = icmp->chksum;
		icmp->chksum = 0;
		chksum2 = n2IP_chksum16(icmp, netif->ibSize, 0, 1);
		if(chksum1 != chksum2){
			n2IP_log(ICMPPRO, "Bad checksum 0x%04x(it should be 0x%04x)!",chksum1, chksum2);
			return ERR_EPARAM;
		}
		icmp->chksum = chksum1;
	}while(0);
	//handle the type of icmp.
	switch(icmp->type){
		
		case ICMP_TYPE_REQUESTREPLY:
			n2IP_log(ICMPPRO, "This is a ping request!");
			return icmp_drag(netif, ICMP_TYPE_RESPONEREPLY, 0, (void *)icmp);
		
		case ICMP_TYPE_RESPONEREPLY:
			n2IP_log(ICMPPRO, "Ping reply , ping ok!");
			break;
		
		case ICMP_TYPE_DESUNREACH:
			switch(icmp->code){
				case 0x02:
					n2IP_log(ICMPPRO, "ICMP Dest Unreachable received: Protocol %d Unreachable", *(icmp->pData+13));
					break;
				case 0x03:
					n2IP_log(ICMPPRO, "ICMP Dest Unreachable received: Port %d Unreachable", (*(icmp->pData+26)<<8)+*(icmp->pData+27));
					break;
				default:
					n2IP_log(ICMPPRO, "ICMP Dest Unreachable received: Unknow code %d", icmp->code);
			}
			break;
		
		default:
			n2IP_log(ICMPPRO, "ICMP Unknow type!");
			return ERR_UNKNOWN;
	}
	return ERR_NONE;
}

