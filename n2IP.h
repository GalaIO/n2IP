/*
 *	Author:		GalaIO
 *	Date:			2015-9-4 21:39 PM
 *	Description:
 *		build a tcp/ip code n2IP,called node to IP, mean for every hardware node with TCP/IP.
 *    n2IP����˼�� node to IP������Ͼ�����ÿ���ڵ�����IP����Ҫ��С�ɣ�����TCP/IP��ࡢ��
 *		Ҫ����ȡ����TCP/IPջ�����ƣ�ͬʱ��Ҫ�����Ǽ�࣬�򵥣���Ч�����Ľڵ㣬Ŀǰ����4-8k�����ݼ��ɣ�
 *		��Ҫ��json���ݽ�����http�ͻ��˵Ƚڵ����á���������������
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
 *		���ԭ��1.TCP/IPЭ��ջһ������ڣ�n2IP.hΪ����TCP/IPЭ��ջ�ļ���ͷ�ļ�������TCP/IP�Ĳ���ֻ��Ҫ��
 *					�������ɣ��������ʲ㣨arp��IP��ICMP��������㣨TCP��UDP����Ӧ�ò㣨SMTP��HTTP��FTP��TELNET��
 *					DNS��TFTP��SNMP��DHCP������Ȼ��ÿһ�����ܶ�Ӧһ��.c�ļ���
 *							2.����ĳ���ض�������ӿڲ���һ������.c .h�ļ���.c�ļ������˽ӿڵľ����ʵ�֣�.h���ⲿ��¶�˽ӿڡ�
 *							3.����802.x��LLC�㣬������һ�µģ���ͬ��802.x��mac�㣬���������죬����Ҳ���һ��ӿ������802.x��LLC��
 *					���ھ���802.x�ı�׼������ӿڣ�����������϶�ȡ�����ݺ󣬴���802.x��mac��Ȼ�󽻸�802.xLLC������Ͻ������ʲ㡣
 *							4.����Ƕ��ʽ��ִ��Ч�ʺ����޵�ARM�ռ䣬����һ��Ľṹ��Eth��ARP�ȽϹ̶����֣���������������ŵ��ڴ�飬�����ö�̬���䡣
 *							5.ʹ��socket���б�̣������׼��socket�Ľӿڣ���ʵ������ͨ�š�
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
#define PROTYPE_IP			0x0800  //IP���ݱ�
#define PROTYPE_ARP			0x0806  //ARP���ݱ�
#define PROTYPE_SNMP		0x814C  //���������Э��SNMP
#define PROTYPE_IPV6		0x86DD  //����Э��v6 IPv6
#define PROTYPE_PPP			0x880B  //��Ե�Э�� PPP�� ��������������̫��֡�����ٲ顣

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

//ָ���ڶ���Ӳ�����ͣ�ĳЩ��������ֵ��
#define IFTYPE_ETHERNET		0x0001	//10 Mbps ��̫��
#define IFTYPE_802_3			0x0006	//IEEE 802��̫��
#define IFTYPE_ARC_NET		0x0007	//ArcNet
#define IFTYPE_FRN				0x000F	//֡�м�
#define IFTYPE_ATM				0x0010	//ATM
#define IFTYPE_HDLC				0x0011	//HDLC
#define IFTYPE_FDDI				0x0012	//����ͨ��
#define IFTYPE_SLIP				0x0014	//������·


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
/*������̫��Э�� ����
 *��RFC894��˵������̫����װIP���ݰ�����󳤶���1500�ֽڣ�Ҳ����˵��̫�����֡��Ӧ������̫���ײ�����1500��
 *�ټ���7�ֽڵ�ǰ��ͬ�����1�ֽڵ�֡��ʼ�������������ǣ�7�ֽ�ǰ��ͬ����1�ֽ�֡��ʼ�������6�ֽڵ�Ŀ��MAC
 *��6�ֽڵ�ԴMAC��2�ֽڵ�֡���ͣ�1500��4�ֽڵ�FCS��
 *�������������֡Ӧ����1526�ֽڣ�����ʵ��������ץ���õ������֡��1518�ֽڣ�Ϊʲô����1526�ֽ��أ�ԭ���ǵ�����֡��������ʱ��
 *�������������Ҫ��ȥ��ǰ��ͬ�����֡��ʼ�������Ȼ���֡����CRC���飬���֡У��ʹ��Ͷ�����֡�����У�����ȷ��
 *���ж�֡��Ŀ��Ӳ����ַ�Ƿ�����Լ��Ľ���������Ŀ�ĵ�ַ���Լ�������Ӳ����ַ���㲥��ַ���ɽ��յĶಥӲ����ַ�ȣ���������ϣ�
 *�ͽ�֡�����豸������������һ��������ʱ���ǵ�ץ���������ץ�����ݣ���ˣ�ץ�����ץ������ȥ��ǰ��ͬ���롢֡��ʼ�ֽ��֮������ݣ�
 *�����ֵ��6��6��2��1500+4��1518��

 *ͬʱ��̫���涨����̫��֡�����򲿷���СΪ46�ֽڣ�Ҳ������̫��֡��С��6��6��2��46��4��64���������ֶεĳ���С��46�ֽ�ʱ��
 *MAC�Ӳ�ͻ��������ֶεĺ����������������֡����С��64�ֽڡ����������������MAC�Ӳ㸺��Ҳ�����豸��������
*/
/*��̫��֡��ʽ��
------------------------------------------------------------------------------------------------------
  |							|							 |						|				 |						|						|					  |				 |
  |	ǰ��ͬ����  | ֡��ʼ����� |  Ŀ�ĵ�ַ  | Դ��ַ | ���ȣ����� |  LLC����  |   ���    | ֡У�� |
  |					    |							 |						|				 |						|						|					  |				 |
  |	   7�ֽ�    |    1�ֽ�		 |		6�ֽ�   |	 6�ֽ� |   2�ֽ�    | 0~1500�ֽ�|  0~64�ֽ� |  4�ֽ� |
  |							|							 |						|				 |						|						|						|				 |
------------------------------------------------------------------------------------------------------
*/
#define ETHERNET_DATA_LEN_MAX	1500

typedef struct Ethernet{
	//DA(Ŀ��MAC)��6�ֽ�
	U8_t	dAddr[6];
	//SA(ԴMAC)��6�ֽ�
	U8_t 	sAddr[6];
	//����/���ȣ�2�ֽڣ�0��1500����Ϊ������ֵ��1536��65535����Ϊ������ֵ(0x0600��0xFFFF)
	//0x0800  IP���ݱ�
	//0x0806  ARP���ݱ�
	//0x814C  ���������Э��SNMP
	//0x86DD  ����Э��v6 IPv6
	//0x880B  ��Ե�Э�� PPP�� ��������������̫��֡�����ٲ顣
	//���pType > 0x5dc�����ʾ��802.3��ʽ
	U16_t 	pType;
	//���ݣ�46��1500�ֽ�
	//+֡У������(FCS)��4�ֽڣ�ʹ��CRC�����Ŀ��MAC���������ⲿ�����ݶ��õ���У��͡�
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
//ֻ����������ӿڵ��ڴ�ӳ�䡣
typedef struct LLC802{
	//----LLC �߼���·����  PDU
	//Ŀ���������~
	U8_t	DSAP;
	//Դ��������
	U8_t	SSAP;
	//�����ֶ�
	U8_t	UI;
	//----SNAP��������Э��  PDU
	//Э���ʶ��
	U8_t	OUI;
	//Э������
	U16_t	pType;
	//Э�����ݵ���ʼλ��.
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
//���ڸñ��ĸ�ʽ�������������������ͣ������ò�����ָ����������
#define ARP_OPCODE_ARP_REQUEST			0x0001	//ARP����
#define ARP_OPCODE_ARP_RESPONE			0x0002	//ARPӦ��
#define ARP_OPCODE_RARP_REQUEST			0x0003	//RARP����
#define ARP_OPCODE_RARP_RESPONE			0x0004	//RARPӦ��
#define ARP_OPCODE_DRARP_REQUEST		0x0005	//DRARP����
#define ARP_OPCODE_DRARP_RESPONE		0x0006	//DRARPӦ��
#define ARP_OPCODE_DRARP_ERR			  0x0007	//DRARP����
#define ARP_OPCODE_INARP_REQUEST		0x0008	//InARP����
#define ARP_OPCODE_INARP_RESPONE		0x0009	//InARPӦ��
#define ARP_OPCODE_ARP_NAK				0x000A	//ARP-NAK

//ARP ״̬��
#define ARP_STATE_FREE					0x01
#define ARP_STATE_OK					0x02
#define ARP_STATE_RESOLVING				0x04

//ֻ����������ӿڵ��ڴ�ӳ�䡣
#define ARP_T_SHA(p)	((p)->aData)				//������Ӳ����ַ
#define ARP_T_SPA(p)	((p)->aData+(p)->haLen)		//������Э���ַ
#define ARP_T_DHA(p)	((p)->aData+(p)->haLen+(p)->paLen)	//Ŀ��Ӳ����ַ
#define ARP_T_DPA(p)	((p)->aData+(p)->haLen+(p)->paLen+(p)->haLen)	//Ŀ��Э���ַ
typedef struct Arp{
	//Ӳ������
	U16_t	hType;
	//Э������
	U16_t	pType;
	//Ӳ����ַ����
	U8_t	haLen;
	//Э���ַ����
	U8_t	paLen;
	//������
	U16_t	opCode;
//	//������Ӳ����ַ
//	U8_t	*shAddr;
//	//������Э���ַ
//	U8_t	*spAddr;
//	//Ŀ��Ӳ����ַ
//	U8_t	*dhAddr;
//	//Ŀ��Э���ַ
//	U8_t	*dpAddr;
	//��ַ����
	U8_t	aData[1];
	
}ARP_t;

//ARP �������~
typedef struct Arp_entry{
	//Э���ַ
	U8_t	pAddr[PRO_LEN_MAX];
	//Ӳ����ַ
	U8_t	hAddr[HARDWARE_LEN_MAX];
	//ARP����״̬
	U8_t	enState;
	//ARP����ʱ��
	U16_t	tOut;
	//ARP�������
	U8_t	enRetry;
	//ARP�����ѯ����������ARP����ɾ������
	U16_t	enQuery;
}ARP_entry_t;

err_t arp_poll(Netif_t *netif);

err_t arp_init(void);

err_t arp_drag(Netif_t *netif, U16_t opCode, void *data);

err_t arp_query(Netif_t *netif, U8_t *ipdest, U8_t *hwdest);

err_t arp_timeOut(Netif_t *netif);
/*------------------------------------------------------ipv4.c-------------------------------------------------------------*/
typedef struct IPv4{
	//ip �汾(����λ),ָ IP Э��İ汾Ŀǰ�� IP Э��汾��Ϊ 4 (�� IPv4)
	//�ײ�����(����λ),�ɱ�ʾ�������ֵ��15����λ(һ����λΪ 4 �ֽ�)���IP ���ײ����ȵ����ֵ�� 60 �ֽ�,��С��5.
	U8_t	IPver_HEADLen;
	//���ַ���ռ8λ��������ø��÷���,�ھɱ�׼�н�����������,��ʵ����һֱδ��ʹ�ù�.1998 ������ֶθ���Ϊ���ַ���.
	//ֻ����ʹ�����ַ���(DiffServ)ʱ,����ֶβ�������.һ�������¶���ʹ������ֶ�
	U8_t	DiffServ;
	//�ܳ��ȣ�ռ16λ,ָ�ײ�������֮�͵ĳ���,��λΪ�ֽ�,������ݱ�����󳤶�Ϊ 65535 �ֽ�.�ܳ��ȱ��벻�������
	//���͵�Ԫ MTU
	U16_t	TotalLen;
	//��ʶ��ռ16λ������һ��������,�����������ݱ��ı�ʶ
	U16_t	IdentifyCount;
	//��ǣ�ǰ��λ�����λ����������Ϊ0��MF����־�ֶε����λ�� MF (More Fragment)��MF=1 ��ʾ���桰���з�Ƭ����MF=0 ��ʾ���һ����Ƭ��
	//DF����־�ֶ��м��һλ�� DF (Don't Fragment)��ֻ�е� DF=0 ʱ�������Ƭ
	//��Ƭƫ�ƣ���13λ����ͷ��ָʾ�˸÷�Ƭ���������ݱ��е�λ�ã���Ƭƫ����8�ֽ�Ϊ������λ����һ����ƬΪ0.
	U16_t	Flag_FragOffset; 
	//����ʱ�䣬ռ8λ,��ΪTTL (Time To Live) ���ݱ��������п�ͨ����·�����������ֵ,TTL �ֶ����ɷ��Ͷ˳�ʼ����һ�� 8 bit�ֶ�.
	//�Ƽ��ĳ�ʼֵ�ɷ������� RFC ָ��,��ǰֵΪ 64.���� ICMP ����Ӧ��ʱ������ TTL ��Ϊ���ֵ 255
	U8_t	TTL;
	//Э�飬ռ8λ��ָ�������ݱ�Я��������ʹ�ú���Э���Ա�Ŀ��������IP�㽫���ݲ����Ͻ����ĸ��������, 1��ʾΪ ICMP Э��, 2��ʾΪ IGMP Э��, 
	//6��ʾΪ TCP Э��, 17��ʾΪ UDP Э��
	U8_t	ProtoclType;
	//�ײ������,ռ16λ,ֻ�������ݱ����ײ����������ݲ���,��ͷ������16λ�ֵĺͣ�.���ﲻ���� CRC ����������ü򵥵ļ��㷽��
	U16_t	CheckNum;
	//ԴIP��ַ��ռ32λ.
	U8_t	srcAddr[4];
	//Ŀ��IP��ַ��ռ32λ.
	U8_t	dstAddr[4];
	//data
	U8_t	pData[1];
}IPv4_t;

err_t ip_drag(Netif_t *netif);

err_t ip_poll(Netif_t *netif);

/*------------------------------------------------------icmp.c-------------------------------------------------------------*/
//���ڲ�����icmp��������.
#define ICMP_TYPE_DESUNREACH			0x03	//Ŀ�겻�ɴ�
#define ICMP_TYPE_SOURCECONTROL  	0x04	//Դ������
#define ICMP_TYPE_REDIRECTION			0x05  //�ض���
#define ICMP_TYPE_TIMEOUT  				0x0B  //��ʱ
#define ICMP_TYPE_WRONGPARAM  		0x0C  //��������

//����������ģ�icmp��������.
#define ICMP_TYPE_RESPONEREPLY		0x00  //����Ӧ��
#define ICMP_TYPE_REQUESTREPLY	  0x08  //��������
#define ICMP_TYPE_CALLTOROUTE			0x09  //·����ͨ��
#define ICMP_TYPE_QUERYROUTE		  0x0A  //·������ѯ
#define ICMP_TYPE_TIMETIPREQUEST	0x0D  //ʱ�������
#define ICMP_TYPE_TIMETIPRESPONE  0x0E  //ʱ���Ӧ��
#define ICMP_TYPE_MASKREQUEST			0x11  //��ַ���������
#define ICMP_TYPE_MASKRESPONE		  0x12  //��ַ����Ӧ��
#define ICMP_TYPE_TRACEROUTE  		0x1E	//׷��·��

//Ŀ�겻�ɴ� �������
#define ICMP_TYPE_DESUNREACH_NET	0x00	//���粻�ɴ�
#define ICMP_TYPE_DESUNREACH_HOST	0x01	//�������ɴ�
#define ICMP_TYPE_DESUNREACH_PRO	0x02	//Э��Ƿ�
#define ICMP_TYPE_DESUNREACH_PORT	0x03  //�˿ڲ��ɴ�

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
	
	//Դ�˿�
	U16_t srcPort;
	//Ŀ�Ķ˿�
	U16_t destPort;
	//����
	U16_t totalLen;
	//У���
	U16_t chksum;
	//����
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
