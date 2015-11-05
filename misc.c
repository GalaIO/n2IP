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
 *���ʹ��С�ˣ�����μ����С�ˡ�
 *����һ����2���ֽ���ɵ�16λ���������ڴ��д洢�������ֽ������ַ�����
 *һ���ǽ������ֽڴ洢����ʼ��ַ�����ΪС��(little-endian)�ֽ�����һ�ַ�
 *���ǽ������ֽڴ洢����ʼ��ַ�����Ϊ���(big-endian)�ֽ���

 *����Ŀǰ���е�X86�ܹ�������С���ֽ��򣬶�ARM�أ��������óɴ�ˣ�Ҳ�������ó�С�ˣ�
 *Ĭ����С���ֽ���ͬʱΪ�˱��ֱ��ͨ��Э�飬��һ�������磬���Ծ������޸�ARM�е��ֽ���
 *��linux���ṩhtons��htonl��hton��ʾhost to network��ʾ������������ֽ���s��l�ֱ��ʾshort��long��
 *����ntohl��ntohs�ȣ�ֵ��һ���������ֽ����Ǵ�ˣ���Ҷ�ά������һ����ͬ��ԭ�򣬲Ų��ᵼ�����ݴ������


 *�жϴ��С�˵ķ�����
 *typedef union testOrder{
 *   U16_t _2_byte;
 *   U8_t  _1_byte;
 *}testOrder_t;
 *
 *testOrder_t test;
 *test._2_byte=0x0001;
 *if(test._1_byte){
 *   little-endian;С��;
 *}else{
 *   big-endian;���;
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

