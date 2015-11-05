/*
 *	Author:		GalaIO
 *	Date:			2015-9-4 21:39 PM
 *	Description:
 *		build the n2IP's addon tool.
 *
 *	Updates note:
 *			1.code host to network and network to host tools for handle byte order.
 *
 *
**/

#include "n2IP.h"

/*
 *解释大端小端，和如何检测大端小端。
 *对于一个由2个字节组成的16位整数，在内存中存储这两个字节有两种方法：
 *一种是将低序字节存储在起始地址，这称为小端(little-endian)字节序；另一种方
 *法是将高序字节存储在起始地址，这称为大端(big-endian)字节序。

 *对于目前流行的X86架构，他是小端字节序，而ARM呢，可以配置成大端，也可以配置成小端，
 *默认是小端字节序，同时为了保持别的通信协议，不一定是网络，所以尽量不修改ARM中的字节序，
 *在linux中提供htons，htonl，hton表示host to network表示主机箱网络变字节序，s和l分别表示short和long，
 *还有ntohl，ntohs等，值得一提是网络字节序是大端，大家都维护这样一个相同的原则，才不会导致数据传输错误。


 *判断大端小端的方法？
 *typedef union testOrder{
 *   U16_t _2_byte;
 *   U8_t  _1_byte;
 *}testOrder_t;
 *
 *testOrder_t test;
 *test._2_byte=0x0001;
 *if(test._1_byte){
 *   little-endian;小端;
 *}else{
 *   big-endian;大端;
 *}
 *
**/
typedef union testOrder{
   U16_t _2_byte;
   U8_t  _1_byte;
}testOrder_t;

#define TEST_ORDER_HEAD(tmp) testOrder_t test;\
test._2_byte=(U16_t)0x0001;\
if(!test._1_byte){\
   return tmp;\
}else

U16_t htons(U16_t tmp){
	TEST_ORDER_HEAD(tmp)
	return ((((U16_t)tmp&0xFF00)>>8)|(((U16_t)tmp&0x00FF)<<8));
}

U32_t htonl(U32_t tmp){
	TEST_ORDER_HEAD(tmp)
	return (((U32_t)(tmp) & 0xff000000) >> 24) | 
			(((U32_t)(tmp) & 0x00ff0000) >> 8) | 
			(((U32_t)(tmp) & 0x0000ff00) << 8) | 
			(((U32_t)(tmp) & 0x000000ff) << 24) ;
}


U16_t ntohs(U16_t tmp){
	TEST_ORDER_HEAD(tmp)
	return ((((U16_t)tmp&0xFF00)>>8)|(((U16_t)tmp&0x00FF)<<8));
}

U32_t ntohl(U32_t tmp){
	TEST_ORDER_HEAD(tmp)
	return (((U32_t)(tmp) & 0xff000000) >> 24) | 
			(((U32_t)(tmp) & 0x00ff0000) >> 8) | 
			(((U32_t)(tmp) & 0x0000ff00) << 8) | 
			(((U32_t)(tmp) & 0x000000ff) << 24) ;
}

