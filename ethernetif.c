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
err_t ethernetif_initParams(Netif_t *eth_if, char *mac, char *ip, char *gatway, char *mask, err_t (*low_output)(U8_t *,U32_t )){
	
	//初始化 网络接口类型
	eth_if->If = IFTYPE_ETHERNET;
	//网络接口  硬件地址长度
	eth_if->haLen = 6;
	//网络接口 协议地址长度
	eth_if->paLen = 4;
	//协议地址的 类型
	eth_if->paType = PROTYPE_IP;
	//当前处理的协议栈 位置，即当前协议名称
	eth_if->pType = PROTYPE_UNKNOWN;
	//复制传入硬件地址
	memcpy(eth_if->hAddr, mac, eth_if->haLen);
	//复制传入协议地址
	n2IP_IPv4Cast(eth_if->pAddr, ip);
	//复制网关的协议地址
	n2IP_IPv4Cast(eth_if->pgAddr, gatway);
	//复制网关协议地址
	n2IP_IPv4Cast(eth_if->pmAddr, mask);
	
	//赋值 底层输出函数， 一般连接网卡驱动层
	eth_if->low_output = low_output;
	//底层输入函数， 连接网卡驱动层
	eth_if->low_input = ethernet_poll;
	//从网络接入层提交到TCP/IP协议栈中，即n2IP内核中
	eth_if->poll = n2IP_poll;
	//从TCP/IP协议栈 输出数据到网络接口层
	eth_if->drag = ethernetif_drag;
	
/*以下元素  是kernel能完整传递不同 层数据同时保证层间松耦合性的关键，
 *由netif只传递数据的指针，而不是发生上下文的拷贝；如果需要回溯数据内容，
 *直接由额外的指针索引。
**/
	//输入数据 句柄
	eth_if->inBuf = NULL;
	//输入数据 大小
	eth_if->ibSize = 0;
	//输出数据 大小
	eth_if->obSize = 0;
	//输出数据 句柄
	eth_if->outBuf = NULL;
	
	//show the log info of the if.
	ethernetif_show(eth_if);
	
	//init ids.
	eth_if->ip_id = 0x01;
	eth_if->icmp_id = 0x01;
	
	//进行必要的初始化步骤
	//初始化netif的arp表项
	eth_if->arp_size = ARP_CACHE_MAX_ENTRY;
	arp_init(eth_if);
	
	//初始化netif的udp表项
	eth_if->ucb_size = UDP_SOCKET_MAX_SIZE;
	udp_init(eth_if);
	
	return ERR_NONE;
	
}
