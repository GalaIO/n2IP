/*
 *	Author:		GalaIO
 *	Date:			2015-9-4 21:39 PM
 *	Description:
 *		build a tcp/ip code n2IP,called node to IP, mean for every hardware node with TCP/IP.
 *    n2IP的意思是 node to IP，理解上就是让每个节点连入IP，主要是小巧，处理TCP/IP简洁、灵活，
 *		要多吸取现有TCP/IP栈的优势，同时主要体现是简洁，简单，有效，灵活的节点，目前处理到4-8k的数据即可，
 *		主要是json数据交换、http客户端等节点作用。不用做服务器。
 *
 *	Updates note:
 *			1.add Ethernet 802.3 format.
 *			2.add host to network and network to host tools for handle byte order.
 *
 *
 *
 *	Author:		GalaIO
 *	Date:			2015-10-22 19:36 PM
 *	Description:
 *		设计原则：1.TCP/IP协议栈一整体存在，n2IP.h为所有TCP/IP协议栈的集合头文件，所有TCP/IP的操作只需要包
 *					含它即可（负责网际层（arp、IP、ICMP）、传输层（TCP、UDP）、应用层（SMTP、HTTP、FTP、TELNET、
 *					DNS、TFTP、SNMP、DHCP）），然后每一个功能对应一个.c文件。
 *							2.对于某个特定的网络接口层有一组具体的.c .h文件，.c文件包含了接口的具体的实现，.h向外部暴露了接口。
 *							3.对于802.x的LLC层，由于是一致的，不同于802.x的mac层，各类型迥异，所以也设计一组接口来设计802.x的LLC。
 *					对于具有802.x的标准的网络接口，从物理介质上读取到数据后，处理802.x的mac，然后交给802.xLLC，随后上交给网际层。
 *							4.考虑嵌入式的执行效率和有限的ARM空间，对于一般的结构（Eth、ARP等较固定部分），采用事先申请号的内存块，不适用动态分配。
 *							5.使用socket进行编程，介入标准的socket的接口，来实现网络通信。
 *
**/
#ifndef _N2IP_H_
#define _N2IP_H_

#include "n2IP_config.h"

/*----------------------------------------------------Data Struct Defination------------------------------------------------------------*/
typedef unsigned int 		U32_t;
typedef int							S32_t;
typedef unsigned char 	U8_t;
typedef char						S8_t;
typedef unsigned short 	U16_t;
typedef short						S16_t;
typedef float 					F32_t;
typedef double					F64_t;
typedef U8_t						err_t;

#define ERR_NONE				0x00
#define ERR_EPARAM			0x01
#define ERR_UNKNOWN			0x02
#define ERR_NOMAC				0x03
#define ERR_ECHKSUM			0x04

/*----------------------------------------------------Debugger------------------------------------------------------------*/
#define n2IP_print(logger,format,...)				if(logger) n2IP_printf(format, ##__VA_ARGS__)
#define n2IP_printh(logger,format,...)			if(logger) n2IP_printf("[n2IP]["#logger"][Log]: "format, ##__VA_ARGS__)
#define n2IP_log(logger,format,...)					if(logger) n2IP_printf("[n2IP]["#logger"][Log]: "format"\r\n", ##__VA_ARGS__)
#define n2IP_err(logger,format,...)					if(logger) n2IP_printf("[n2IP]["#logger"][Error][%s:%4d]: "format"\r\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define n2IP_waring(logger,format,...)			if(logger) n2IP_printf("[n2IP]["#logger"][Waring]: "format"\r\n", ##__VA_ARGS__)

/*-----------------------------------------------------net interface-------------------------------------------------------------*/
#define PROTYPE_UNKNOWN		0x0000

//Pro type defination.
#define PROTYPE_IP			0x0800  //IP数据报
#define PROTYPE_ARP			0x0806  //ARP数据报
#define PROTYPE_SNMP		0x814C  //简单网络管理协议SNMP
#define PROTYPE_IPV6		0x86DD  //网际协议v6 IPv6
#define PROTYPE_PPP			0x880B  //点对点协议 PPP， 更多类型搜索以太网帧类型速查。

//the protocol based on IP.
#define IP_PRO_REVERD 	0x00		//reserved
#define IP_PRO_ICMP			0x01		//internet control manage protocol
#define IP_PRO_IGMP			0x02		//internet group manage protocol
#define IP_PRO_GATEWAY	0x03		//protocol of gateway to gateway
#define IP_PRO_IP				0x04		//ip in ip
#define IP_PRO_STREAM		0x05		//stream protocol
#define IP_PRO_TCP			0x06		//transmit control protocol
#define IP_PRO_EGATE		0x08		//external gateway protocol
#define IP_PRO_UDP			0x11		//uer data protocol

//指定第二层硬件类型，某些常用类型值。
#define IFTYPE_ETHERNET		0x0001	//10 Mbps 以太网
#define IFTYPE_802_3			0x0006	//IEEE 802以太网
#define IFTYPE_ARC_NET		0x0007	//ArcNet
#define IFTYPE_FRN				0x000F	//帧中继
#define IFTYPE_ATM				0x0010	//ATM
#define IFTYPE_HDLC				0x0011	//HDLC
#define IFTYPE_FDDI				0x0012	//光纤通信
#define IFTYPE_SLIP				0x0014	//串行线路


#define PRO_LEN_MAX	16
#define HARDWARE_LEN_MAX	6

typedef struct Netif{
	//if's meida.
	U16_t	If;
	//hardware address length == HARDWARE_LEN_MAX
	U8_t	haLen;
	//hardware address
	U8_t	hAddr[HARDWARE_LEN_MAX];
	//destination hardware address
	U8_t	dhAddr[HARDWARE_LEN_MAX];
	
	//protocl address  length == PRO_LEN_MAX
	U8_t	paLen;
	//protocl address
	U8_t	pAddr[PRO_LEN_MAX];
	//protocl mask address
	U8_t	pmAddr[PRO_LEN_MAX];
	//protocl gateway address
	U8_t	pgAddr[PRO_LEN_MAX];
	//specific protocl address
	U8_t	spAddr[PRO_LEN_MAX];
	//if's protocol address type.
	U16_t	paType;
	//if's protocol type.
	U16_t	pType;

	//source port
	U16_t sPort;
	//destination port
	U16_t dPort;
	
//	//if's input buf.
	U8_t	*inBuf;
	U32_t ibSize;
	//if's output buf.
	U8_t	*outBuf;
	U32_t	obSize;
	
	//interface input;
	err_t (*low_input)(struct Netif *eth_if, U8_t *eth_buf, U32_t size);
	//interface output;
	err_t (*low_output)(U8_t *hBuf,U32_t len);
	
	//interface input;
	err_t (*poll)(struct Netif *eth_if);
	//interface output;
	err_t (*drag)(struct Netif *eth_if);
	
	//if's extra options.
	U16_t	ifOp;
	
}Netif_t;

/*----------------------------------------------------ethernetif.c------------------------------------------------------------*/
/*分析以太网协议 长度
 *据RFC894的说明，以太网封装IP数据包的最大长度是1500字节，也就是说以太网最大帧长应该是以太网首部加上1500，
 *再加上7字节的前导同步码和1字节的帧开始定界符，具体就是：7字节前导同步吗＋1字节帧开始定界符＋6字节的目的MAC
 *＋6字节的源MAC＋2字节的帧类型＋1500＋4字节的FCS。
 *按照上述，最大帧应该是1526字节，但是实际上我们抓包得到的最大帧是1518字节，为什么不是1526字节呢？原因是当数据帧到达网卡时，
 *在物理层上网卡要先去掉前导同步码和帧开始定界符，然后对帧进行CRC检验，如果帧校验和错，就丢弃此帧。如果校验和正确，
 *就判断帧的目的硬件地址是否符合自己的接收条件（目的地址是自己的物理硬件地址、广播地址、可接收的多播硬件地址等），如果符合，
 *就将帧交“设备驱动程序”做进一步处理。这时我们的抓包软件才能抓到数据，因此，抓包软件抓到的是去掉前导同步码、帧开始分界符之外的数据，
 *其最大值是6＋6＋2＋1500+4＝1518。

 *同时以太网规定，以太网帧数据域部分最小为46字节，也就是以太网帧最小是6＋6＋2＋46＋4＝64。当数据字段的长度小于46字节时，
 *MAC子层就会在数据字段的后面填充以满足数据帧长不小于64字节。由于填充数据是由MAC子层负责，也就是设备驱动程序。
*/
/*以太网帧格式：
------------------------------------------------------------------------------------------------------
  |							|							 |						|				 |						|						|					  |				 |
  |	前导同步码  | 帧起始定界符 |  目的地址  | 源地址 | 长度／类型 |  LLC数据  |   填充    | 帧校验 |
  |					    |							 |						|				 |						|						|					  |				 |
  |	   7字节    |    1字节		 |		6字节   |	 6字节 |   2字节    | 0~1500字节|  0~64字节 |  4字节 |
  |							|							 |						|				 |						|						|						|				 |
------------------------------------------------------------------------------------------------------
*/
#define ETHERNET_DATA_LEN_MAX	1500

typedef struct Ethernet{
	//DA(目的MAC)：6字节
	U8_t	dAddr[6];
	//SA(源MAC)：6字节
	U8_t 	sAddr[6];
	//类型/长度：2字节，0～1500保留为长度域值，1536～65535保留为类型域值(0x0600～0xFFFF)
	//0x0800  IP数据报
	//0x0806  ARP数据报
	//0x814C  简单网络管理协议SNMP
	//0x86DD  网际协议v6 IPv6
	//0x880B  点对点协议 PPP， 更多类型搜索以太网帧类型速查。
	//如果pType > 0x5dc，则表示是802.3格式
	U16_t 	pType;
	//数据：46～1500字节
	//+帧校验序列(FCS)：4字节，使用CRC计算从目的MAC到数据域这部分内容而得到的校验和。
	U8_t	pData[ETHERNET_DATA_LEN_MAX+4];
	
}Ethernet_t;

err_t ethernetif_init(Netif_t *eth_if);

err_t ethernetif_initParams(Netif_t *eth_if, char *mac, char *ip, char *gatway, char *mask);

/*-----------------------------------------------------misc.c-------------------------------------------------------------*/
//byte order convertion.
//host to network, 2byte convertion.
U16_t htons(U16_t tmp);
//host to network, 4byte convertion.
U32_t htonl(U32_t tmp);
//network to host , 2byte convertion.
U16_t ntohs(U16_t tmp);
//network to host , 4byte convertion.
U32_t ntohl(U32_t tmp);


/*-----------------------------------------------------802.2 LLC-------------------------------------------------------------*/
//只能用于网络接口的内存映射。
typedef struct LLC802{
	//----LLC 逻辑链路控制  PDU
	//目标服务接入点~
	U8_t	DSAP;
	//源服务接入点
	U8_t	SSAP;
	//控制字段
	U8_t	UI;
	//----SNAP子网接入协议  PDU
	//协议标识符
	U8_t	OUI;
	//协议类型
	U16_t	pType;
	//协议数据的起始位置.
	U8_t	pData[1];
}LLC802_t;
	
/*-----------------------------------------------------n2IP.c-------------------------------------------------------------*/

err_t n2IP_init(void);

err_t n2IP_poll(Netif_t *netif);

U8_t differ_subnet(U8_t *remoteIP, U8_t *localIP, U8_t *subMask, U8_t len);

err_t n2IP_drag(Netif_t *netif);

U32_t n2IP_calen(U16_t pType, U32_t opLen);
U32_t n2IP_ipcalen(U16_t pType, U32_t opLen);

void n2IP_IPv4Cast(U8_t *ipdest, char *str);

U32_t n2IP_chksum16(void *buf, U32_t len, U32_t chksum, char complement);

/*------------------------------------------------------arp.c-------------------------------------------------------------*/
//由于该报文格式可以用于其他报文类型，所以用操作码指定报文类型
#define ARP_OPCODE_ARP_REQUEST			0x0001	//ARP请求
#define ARP_OPCODE_ARP_RESPONE			0x0002	//ARP应答
#define ARP_OPCODE_RARP_REQUEST			0x0003	//RARP请求
#define ARP_OPCODE_RARP_RESPONE			0x0004	//RARP应答
#define ARP_OPCODE_DRARP_REQUEST		0x0005	//DRARP请求
#define ARP_OPCODE_DRARP_RESPONE		0x0006	//DRARP应答
#define ARP_OPCODE_DRARP_ERR			  0x0007	//DRARP错误
#define ARP_OPCODE_INARP_REQUEST		0x0008	//InARP请求
#define ARP_OPCODE_INARP_RESPONE		0x0009	//InARP应答
#define ARP_OPCODE_ARP_NAK				0x000A	//ARP-NAK

//ARP 状态集
#define ARP_STATE_FREE					0x01
#define ARP_STATE_OK					0x02
#define ARP_STATE_RESOLVING				0x04

//只能用于网络接口的内存映射。
#define ARP_T_SHA(p)	((p)->aData)				//发送者硬件地址
#define ARP_T_SPA(p)	((p)->aData+(p)->haLen)		//发送者协议地址
#define ARP_T_DHA(p)	((p)->aData+(p)->haLen+(p)->paLen)	//目标硬件地址
#define ARP_T_DPA(p)	((p)->aData+(p)->haLen+(p)->paLen+(p)->haLen)	//目标协议地址
typedef struct Arp{
	//硬件类型
	U16_t	hType;
	//协议类型
	U16_t	pType;
	//硬件地址长度
	U8_t	haLen;
	//协议地址长度
	U8_t	paLen;
	//操作码
	U16_t	opCode;
//	//发送者硬件地址
//	U8_t	*shAddr;
//	//发送者协议地址
//	U8_t	*spAddr;
//	//目标硬件地址
//	U8_t	*dhAddr;
//	//目标协议地址
//	U8_t	*dpAddr;
	//地址数据
	U8_t	aData[1];
	
}ARP_t;

//ARP 缓存表项~
typedef struct Arp_entry{
	//协议地址
	U8_t	pAddr[PRO_LEN_MAX];
	//硬件地址
	U8_t	hAddr[HARDWARE_LEN_MAX];
	//ARP表项状态
	U8_t	enState;
	//ARP表项时延
	U16_t	tOut;
	//ARP请求次数
	U8_t	enRetry;
	//ARP请求查询次数，用于ARP表项删除策略
	U16_t	enQuery;
}ARP_entry_t;

err_t arp_poll(Netif_t *netif);

err_t arp_init(void);

err_t arp_drag(Netif_t *netif, U16_t opCode, void *data);

err_t arp_query(Netif_t *netif, U8_t *ipdest, U8_t *hwdest);

err_t arp_timeOut(Netif_t *netif);
/*------------------------------------------------------ipv4.c-------------------------------------------------------------*/
typedef struct IPv4{
	//ip 版本(高四位),指 IP 协议的版本目前的 IP 协议版本号为 4 (即 IPv4)
	//首部长度(低四位),可表示的最大数值是15个单位(一个单位为 4 字节)因此IP 的首部长度的最大值是 60 字节,最小是5.
	U8_t	IPver_HEADLen;
	//区分服务，占8位，用来获得更好服务,在旧标准中叫做服务类型,但实际上一直未被使用过.1998 年这个字段改名为区分服务.
	//只有在使用区分服务(DiffServ)时,这个字段才起作用.一般的情况下都不使用这个字段
	U8_t	DiffServ;
	//总长度，占16位,指首部和数据之和的长度,单位为字节,因此数据报的最大长度为 65535 字节.总长度必须不超过最大
	//传送单元 MTU
	U16_t	TotalLen;
	//标识，占16位，它是一个计数器,用来产生数据报的标识
	U16_t	IdentifyCount;
	//标记，前三位，最高位保留，必须为0；MF，标志字段的最低位是 MF (More Fragment)，MF=1 表示后面“还有分片”。MF=0 表示最后一个分片；
	//DF，标志字段中间的一位是 DF (Don't Fragment)，只有当 DF=0 时才允许分片
	//分片偏移，后13位，高头部指示了该分片在所属数据报中的位置，分片偏移以8字节为计量单位，第一个分片为0.
	U16_t	Flag_FragOffset; 
	//生存时间，占8位,记为TTL (Time To Live) 数据报在网络中可通过的路由器数的最大值,TTL 字段是由发送端初始设置一个 8 bit字段.
	//推荐的初始值由分配数字 RFC 指定,当前值为 64.发送 ICMP 回显应答时经常把 TTL 设为最大值 255
	U8_t	TTL;
	//协议，占8位，指出此数据报携带的数据使用何种协议以便目的主机的IP层将数据部分上交给哪个处理过程, 1表示为 ICMP 协议, 2表示为 IGMP 协议, 
	//6表示为 TCP 协议, 17表示为 UDP 协议
	U8_t	ProtoclType;
	//首部检验和,占16位,只检验数据报的首部不检验数据部分,是头部所有16位字的和，.这里不采用 CRC 检验码而采用简单的计算方法
	U16_t	CheckNum;
	//源IP地址，占32位.
	U8_t	srcAddr[4];
	//目标IP地址，占32位.
	U8_t	dstAddr[4];
	//data
	U8_t	pData[1];
}IPv4_t;

err_t ip_drag(Netif_t *netif);

err_t ip_poll(Netif_t *netif);

/*------------------------------------------------------icmp.c-------------------------------------------------------------*/
//用于差错报告的icmp报文类型.
#define ICMP_TYPE_DESUNREACH			0x03	//目标不可达
#define ICMP_TYPE_SOURCECONTROL  	0x04	//源端抑制
#define ICMP_TYPE_REDIRECTION			0x05  //重定向
#define ICMP_TYPE_TIMEOUT  				0x0B  //超时
#define ICMP_TYPE_WRONGPARAM  		0x0C  //参数问题

//（不含差错报文）icmp报文类型.
#define ICMP_TYPE_RESPONEREPLY		0x00  //回送应答
#define ICMP_TYPE_REQUESTREPLY	  0x08  //回送请求
#define ICMP_TYPE_CALLTOROUTE			0x09  //路由器通告
#define ICMP_TYPE_QUERYROUTE		  0x0A  //路由器查询
#define ICMP_TYPE_TIMETIPREQUEST	0x0D  //时间戳请求
#define ICMP_TYPE_TIMETIPRESPONE  0x0E  //时间戳应答
#define ICMP_TYPE_MASKREQUEST			0x11  //地址掩码的请求
#define ICMP_TYPE_MASKRESPONE		  0x12  //地址掩码应答
#define ICMP_TYPE_TRACEROUTE  		0x1E	//追踪路由

//目标不可达 错误代码
#define ICMP_TYPE_DESUNREACH_NET	0x00	//网络不可达
#define ICMP_TYPE_DESUNREACH_HOST	0x01	//主机不可达
#define ICMP_TYPE_DESUNREACH_PRO	0x02	//协议非法
#define ICMP_TYPE_DESUNREACH_PORT	0x03  //端口不可达

typedef struct ICMP{
	//the type of packet.
	U8_t  type;
	//the code of subType.
	U8_t  code;
	//check of icmp.
	U16_t chksum;
	//data.
	U8_t  pData[1];
}ICMP_t;

err_t icmp_drag(Netif_t *netif, U8_t type, U8_t code, void *data);

err_t icmp_poll(Netif_t *netif);

/*------------------------------------------------------udp.c-------------------------------------------------------------*/
typedef struct UDP{
	
	//源端口
	U16_t srcPort;
	//目的端口
	U16_t destPort;
	//长度
	U16_t totalLen;
	//校验和
	U16_t chksum;
	//数据
	U8_t  pData[1];
	
}UDP_t;

typedef struct PSEUDO_IPV4_HDR{
	U8_t  srcIP[4];
	U8_t  destIP[4];
	U8_t	zero;
	U8_t	pType;
	U16_t	tLen;
}PSEUDO_IPV4_HDR_t;

err_t udp_poll(Netif_t *netif);

/*------------------------------------------------------tcp.c-------------------------------------------------------------*/
#define TCP_FLAG_FIN	0x01
#define TCP_FLAG_SYN	0x02
#define TCP_FLAG_RST	0x04
#define TCP_FLAG_PSH	0x08
#define TCP_FLAG_ACK	0x10
#define TCP_FLAG_URG	0x20
typedef struct TCP{
	//source port
	U16_t srcPort;
	//destination port
	U16_t destPort;
	//sequence number
	U16_t seq;
	//ACK number
	U16_t ack;
	//data offset 
	U8_t  dataOffset;
	//flag & control
	U8_t  flags;
	//the size of windows
	U16_t window;
	//TCP chksum
	U16_t chksum;
	//urgent pointer
	U16_t urgentPtr;
	//pdata
	U8_t  pData[1];
}TCP_t;

err_t tcp_poll(Netif_t *netif);


#endif
