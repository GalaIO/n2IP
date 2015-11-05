
#include "n2IP.h"
#include "string.h"

//ARP 表项缓存单元
static ARP_entry_t arp_cache[ARP_CACHE_MAX_ENTRY];

#define ARP_ENTRY_TIME_OUT		0

/*
 *Alloc a unuse arp entry.
 *
 *@return the table index.
 *
**/
U32_t arp_alloc(void){
	
	U32_t i,j,k=0xFFFFFFFF;
	for(i=0; i<ARP_CACHE_MAX_ENTRY; i++){
		if(arp_cache[i].enState == ARP_STATE_FREE){
			return i;
		}	
	}
	for(i=0; i<ARP_CACHE_MAX_ENTRY; i++){
		if(arp_cache[i].enQuery < k){
			j = i;
			k = arp_cache[i].enQuery;
		}	
	}
	return j;
}

void arp_showlog(ARP_t *arp){
	
	int i;
	
	n2IP_log(ARPPRO,"ARP's HardWare Type:   0x%04x", ntohs(arp->hType));
	n2IP_log(ARPPRO,"ARP's Procol   Type:   0x%04x", ntohs(arp->pType));
	n2IP_log(ARPPRO,"ARP's HardWare PROLEN: 0x%02x", arp->haLen);
	n2IP_log(ARPPRO,"ARP's Procol PROLEN:   0x%02x", arp->paLen);
	n2IP_log(ARPPRO,"ARP's Operate  Code:   0x%04x", ntohs(arp->opCode));
	
	n2IP_printh(ARPPRO,"ARP's Source HAddr:  ");
	for(i=0; i<arp->haLen; i++){
		n2IP_print(ARPPRO, "0x%02x ", ARP_T_SHA(arp)[i]);
	}
	n2IP_print(ARPPRO, "\r\n");
	n2IP_printh(ARPPRO,"ARP's Source PAddr:  ");
	for(i=0; i<arp->paLen; i++){
		n2IP_print(ARPPRO, "0x%02x ", ARP_T_SPA(arp)[i]);
	}
	n2IP_print(ARPPRO, "\r\n");
	n2IP_printh(ARPPRO,"ARP's Ddestination HAddr:  ");
	for(i=0; i<arp->haLen; i++){
		n2IP_print(ARPPRO, "0x%02x ", ARP_T_DHA(arp)[i]);
	}
	n2IP_print(ARPPRO, "\r\n");
	n2IP_printh(ARPPRO,"ARP's Ddestination PAddr:  ");
	for(i=0; i<arp->paLen; i++){
		n2IP_print(ARPPRO, "0x%02x ", ARP_T_DPA(arp)[i]);
	}
	n2IP_print(ARPPRO, "\r\n");
	
}

/*
 *Poll the Packet from Low interface to n2IP's ARP unit.
 *
 *@param arp_buf, arp_buf from LLC.
 *
 *@return error code.
 *
**/
err_t arp_poll(Netif_t *netif){
	
	int i;
	ARP_t *arp = (ARP_t *)netif->inBuf;
	ARP_entry_t *entry = NULL;
	
	//show arp info.
	arp_showlog(arp);
	if(!(arp->haLen == netif->haLen && arp->paLen == netif->paLen)){
		n2IP_log(ARPPRO,"receive wrong data!");
	}
	//check if the device has the same network no.
	if(!(differ_subnet(ARP_T_SPA(arp), netif->pAddr, netif->pmAddr, netif->paLen))){
		//update the arp entry cache.
		//first check, if it already exits in cache.
		for(i=0; i<ARP_CACHE_MAX_ENTRY; i++){
			if(arp_cache[i].enState == ARP_STATE_FREE){
				continue;
			}
			if(memcmp(arp_cache[i].pAddr, ARP_T_SPA(arp), netif->paLen) == 0){
				//if find it, record it and update.
				entry = &arp_cache[i];
				arp_cache[i].enState = ARP_STATE_OK;
				arp_cache[i].tOut = ARP_ENTRY_TIME_LIFE;
				arp_cache[i].enRetry = ARP_ENTRY_REQ_TRY;
				break;
			}
		}
		//second, if it's a new ARP entry, then alloc a entry.
		if(i >= ARP_CACHE_MAX_ENTRY && entry == NULL){
			i = arp_alloc();
			entry = arp_cache+i;
			memcpy(entry->pAddr, ARP_T_SPA(arp), netif->paLen);
			memcpy(entry->hAddr, ARP_T_SHA(arp), netif->haLen);
			entry->enState = ARP_STATE_OK;
			entry->tOut = ARP_ENTRY_TIME_LIFE;
			entry->enRetry = ARP_ENTRY_REQ_TRY;
			entry->enQuery = 0;
		}
		//if the arp's sended for us.
		if(memcmp(ARP_T_DPA(arp), netif->pAddr, netif->paLen) == 0){
			//if it's a arp request for us.
			if(ntohs(arp->opCode) == ARP_OPCODE_ARP_REQUEST){
				//send a arp respone for it.
//				//fill in destination.
//				memcpy(ARP_T_DPA(arp), ARP_T_SPA(arp), netif->paLen);
//				memcpy(ARP_T_DHA(arp), ARP_T_SHA(arp), netif->haLen);
//				//fill in netif's info.
//				memcpy(ARP_T_SPA(arp), netif->pAddr, netif->paLen);
//				memcpy(ARP_T_SHA(arp), netif->hAddr, netif->haLen);
//				arp->haLen = netif->haLen;
//				arp->paLen = netif->paLen;
//				arp->hType = htons(netif->If);
//				arp->opCode = htons(ARP_OPCODE_ARP_RESPONE);
//				arp->pType = htons(netif->paType);
				n2IP_log(ARPPRO,"return respone!");
//				netif->low_output((U8_t*)arp,sizeof(arp->haLen)+
//					sizeof(arp->hType)+sizeof(arp->opCode)+sizeof(arp->paLen)+sizeof(arp->pType)
//						+2*arp->haLen+2*arp->paLen);
				//drag to n2IP.
				arp_drag(netif, ARP_OPCODE_ARP_RESPONE, (void *)arp);
			}else{
				n2IP_log(ARPPRO,"throw the arp packet!");
			}
		}
	}else{
		n2IP_log(ARPPRO,"the remote is not in the subnet!");
	}
	
	return ERR_NONE;
}

/*
 *Init the arp entry.
 *
 *@param void.
 *
 *@return error code.
 *
**/
err_t arp_init(void){
	
	int i;
	//依次更新表项
	for(i=0; i<ARP_CACHE_MAX_ENTRY; i++){
		
		arp_cache[i].enState = ARP_STATE_FREE;
		
	}
	
	return ERR_NONE;
}


/*
 *When you need send a packet for a subnet device, query the mac address by IP.
 *
 *@param void.
 *
 *@return error code.
 *
**/
err_t arp_drag(Netif_t *netif, U16_t opCode, void *data){
	
	ARP_t	*arp;
	
	//alloc enough room for output.
	netif->obSize = n2IP_calen(IFTYPE_ETHERNET, 0)+n2IP_calen(PROTYPE_ARP, 2*netif->paLen+2*netif->haLen);
	n2IP_drag(netif);
	
	arp = (ARP_t *)(netif->outBuf+n2IP_calen(IFTYPE_ETHERNET, 0));
	
	arp->haLen = netif->haLen;
	arp->paLen = netif->paLen;
	arp->hType = htons(netif->If);
	arp->pType = htons(netif->paType);
	arp->opCode = htons(opCode);
	memcpy(ARP_T_SHA(arp), netif->hAddr, netif->haLen);
	memcpy(ARP_T_SPA(arp), netif->pAddr, netif->paLen);
	
	switch(opCode){
		case ARP_OPCODE_ARP_REQUEST:
			memset(ARP_T_DHA(arp), 0x00, netif->haLen);
			memcpy(ARP_T_DPA(arp), data, netif->paLen);
			//fill destination mac.
			memset(netif->dhAddr, 0x00, netif->haLen);
		break;
		case ARP_OPCODE_ARP_RESPONE:
			memcpy(ARP_T_DHA(arp), ARP_T_SHA((ARP_t *)data), netif->haLen);
			memcpy(ARP_T_DPA(arp), ARP_T_SPA((ARP_t *)data), netif->paLen);
			//fill destination mac.
			memcpy(netif->dhAddr, ARP_T_DHA(arp), netif->haLen);
		break;
	}
	//fill the ptype, drag from arp.
	netif->pType = PROTYPE_ARP;
	netif->obSize = n2IP_calen(PROTYPE_ARP, 2*netif->paLen+2*netif->haLen);
	arp_showlog(arp);
	
	//drag to if.
	netif->drag(netif);
	
	//free the mem.
	n2IP_free(netif->outBuf);
	netif->obSize = 0;
	
	return ERR_NONE;
}
/*
 *Request a specific ARP entry.
 *
 *@param netif, the interface of net.
 *
 *@param ipdest, the destination's ip.
 *
 *@param hwdest, the destination's hardware address.
 *
 *@return error code.
 *
**/
err_t arp_query(Netif_t *netif, U8_t *ipdest, U8_t *hwdest){
	
	int i;
	//there is not in the same subnet.
	if(differ_subnet(ipdest, netif->pAddr, netif->pmAddr, netif->paLen)){
		for(i=0; i<ARP_CACHE_MAX_ENTRY; i++){
			if(arp_cache[i].enState == ARP_STATE_FREE){
				continue;
			}
			if(memcmp(netif->pgAddr, arp_cache[i].pAddr, netif->paLen) == 0){
				memcpy(hwdest, arp_cache[i].hAddr, netif->haLen);
				arp_cache[i].enQuery++;
				return ERR_NONE;
			}
		}
		//request for gateway addr.
		arp_drag(netif, ARP_OPCODE_ARP_REQUEST, netif->pgAddr);
	}else{
		for(i=0; i<ARP_CACHE_MAX_ENTRY; i++){
			if(arp_cache[i].enState == ARP_STATE_FREE){
				continue;
			}
			if(memcmp(ipdest, arp_cache[i].pAddr, netif->paLen) == 0){
				memcpy(hwdest, arp_cache[i].hAddr, netif->haLen);
				arp_cache[i].enQuery++;
				return ERR_NONE;
			}
		}
		//request for the specific addr.
		arp_drag(netif, ARP_OPCODE_ARP_REQUEST, ipdest);
	}
	
	n2IP_err(ARPPRO,"no find the ip!");
	return ERR_NOMAC;
}

/*
 *Arp's time frame is over.
 *
 *@param void.
 *
 *@return error code.
 *
**/
err_t arp_timeOut(Netif_t *netif){
	
	int i;
	
	for(i=0; i<ARP_CACHE_MAX_ENTRY; i++){
		//if state is free, there is nothing to handle.
		if(arp_cache[i].enState == ARP_STATE_FREE){
			continue;
		}
		//if the arp entry's life is over, and request arp again or retry it.
		if(arp_cache[i].tOut == ARP_ENTRY_TIME_OUT){
			switch(arp_cache[i].enState){
				//request arp entry again.
				case ARP_STATE_OK:
					arp_drag(netif, ARP_OPCODE_ARP_REQUEST, arp_cache[i].pAddr);
					arp_cache[i].enState = ARP_STATE_RESOLVING;
					break;
				//retry it until enRetry == 0.
				case ARP_STATE_RESOLVING:
					if(arp_cache[i].enRetry > 0){
						arp_cache[i].enRetry--;
						arp_drag(netif, ARP_OPCODE_ARP_REQUEST, arp_cache[i].pAddr);
					}else{
						arp_cache[i].enState = ARP_STATE_FREE;
					}
					break;
				default:
					n2IP_err(ARPPRO,"Invaild State!");
					return ERR_UNKNOWN;
			}
		}
		
	}
	
	return ERR_NONE;
}
