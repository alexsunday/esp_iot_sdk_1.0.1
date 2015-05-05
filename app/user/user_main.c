/******************************************************************************
 * Copyright 2013-2014 Espressif Systems (Wuxi)
 *
 * FileName: user_main.c
 *
 * Description: entry file of user application
 *
 * Modification history:
 *     2014/1/1, v1.0 create this file.
*******************************************************************************/
#include "ets_sys.h"
#include "osapi.h"
#include "user_interface.h"
#include "ip_addr.h"
#include "driver/uart.h"
#include "eagle_soc.h"
#include "mem.h"
#include "espconn.h"

#include "driver/key.h"
#include "driver/dht.h"


#define FLASH_HEAD_ADDR 0x3C000
#define DEFAULT_SSID "iPLUG"
#define DEFAULT_SSID_PWD "iPLUG123"
#define DEFAULT_GWADDR "192.168.10.253"
#define DHCP_BEGIN_ADDR "192.168.10.100"
#define DHCP_END_ADDR "192.168.10.110"
#define LOCAL_UDP_PORT 8090
#define LOCAL_SERVER_PORT 8091
#define CLOUD_SERVER "211.155.86.145"
#define CLOUD_PORT 10090
#define MAX_PACK_LENGTH 99
#define UDP_FINGERPRINT "I'm HERE, I'm iPLUG."


// 云端连接检查，定时器
static ETSTimer station_chk_timer;
// 开启客户端监听检查。
static ETSTimer server_listen_chk_timer;
struct espconn client_conn;

enum DEV_TYPE {
	DEV_UNKNOWN, DEV_PLUG
};

enum RUN_MODE {
	MODE_UNKNOWN, MODE_SOFTAP, MODE_STATION
};

enum CONNECT_STATUS {
	STATUS_UNKNOWN,
	STATUS_CONNECTING,
	STATUS_CONNECTED,
	STATUS_DISCONNECTED
};

enum CONN_TYPE {
	MODE_CLIENT, MODE_SERVER
};

enum MSG_TYPE {
    DEV_RP_REQ = 0,
    HEART_REQ = 1,
    GSTATUS_REQ = 2,
    SSTATUS_REQ = 3,
    DEV_RP_RSP = 4,
    HEART_RSP = 5,
    GSTATUS_RSP = 6,
    SSTATUS_RSP = 7,
    LEDTEST_REQ = 8,
    LEDTEST_RSP = 9,
    SETSSID_REQ = 10,
    SETSSID_RSP = 11,
    RST_REQ = 12,
    RST_RSP = 13
};

typedef void (* msg_pack_proc_fn)(struct espconn* pconn, char* pdata, unsigned short len);

struct pack_proc {
	enum MSG_TYPE msgtype;
	msg_pack_proc_fn fn;
};
enum RUN_MODE runmode = MODE_UNKNOWN;
enum CONNECT_STATUS client_status = STATUS_UNKNOWN; //为1则代表已连接到服务端


typedef struct _rw_info{
	uint32 server_addr;
	uint16 server_port;
	unsigned char ssid_mine[32];
	unsigned char ssid_pwd_mine[16];
	unsigned char ssid[32];
	unsigned char ssid_pwd[16];
	uint8 run_mode;
	uint8 dev_type;
	uint32 hash;
} rw_info;


typedef struct _conn_info {
	unsigned char* buffer;
	uint32 bufsize;
}conn_context;


typedef struct _led_glint {
	uint32 cur_count; //闪烁次数，当前
	uint32 limit_count; //闪烁次数限制，0则为无限
	uint32 pin; //引脚
	uint16 interval; //闪烁间隔 毫秒单位
	uint16 reverse;
	ETSTimer* ptimer;
}led_glint;


typedef struct _heart_timer {
	enum CONN_TYPE mode;
	struct espconn* conn;
	ETSTimer* timer;
} heart_timer;


void ICACHE_FLASH_ATTR connect_to_cloud();
void ICACHE_FLASH_ATTR _gpio_low(void* time_arg);
void ICACHE_FLASH_ATTR sent_cloud_cb(void* param);
void ICACHE_FLASH_ATTR _gpio_high(void* time_arg);
void ICACHE_FLASH_ATTR connected_cloud_cb(void* param);
void ICACHE_FLASH_ATTR disconnected_cloud_cb(void* param);
void ICACHE_FLASH_ATTR restart_init_station_chk_timer(int interval);
void ICACHE_FLASH_ATTR reconnect_cloud_cb(void* param, sint8 errcode);
void ICACHE_FLASH_ATTR data_received_cb(void* param, char* pdata, unsigned short len);
void ICACHE_FLASH_ATTR server_listen();
void ICACHE_FLASH_ATTR client_reconnect_cb(void* conn, sint8 err);
typedef void (* msg_pack_proc_fn)(struct espconn* pconn, char* pdata, unsigned short len);


void procfn_dev_rp_req(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_heart_req(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_gstatus_req(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_sstatus_req(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_dev_rp_rsp(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_heart_rsp(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_gstatus_rsp(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_sstatus_rsp(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_ledtest_req(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_ledtest_rsp(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_setssid_req(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_setssid_rsp(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_rst_req(struct espconn* pconn, char* pdata, unsigned short len);
void procfn_rst_rsp(struct espconn* pconn, char* pdata, unsigned short len);


static struct pack_proc gl_procs[] = {
		{DEV_RP_REQ, procfn_dev_rp_req},
		{HEART_REQ, procfn_heart_req},
		{GSTATUS_REQ, procfn_gstatus_req},
		{SSTATUS_REQ, procfn_sstatus_req},
		{DEV_RP_RSP, procfn_dev_rp_rsp},
		{HEART_RSP, procfn_heart_rsp},
		{GSTATUS_RSP, procfn_gstatus_rsp},
	    {SSTATUS_RSP, procfn_sstatus_rsp},
	    {LEDTEST_REQ, procfn_ledtest_req},
	    {LEDTEST_RSP, procfn_ledtest_rsp},
	    {SETSSID_REQ, procfn_setssid_req},
	    {SETSSID_RSP, procfn_setssid_rsp},
	    {RST_REQ, procfn_rst_req},
	    {RST_RSP, procfn_rst_rsp}
};


struct keys_param keys;
struct single_key_param *single_key[1];


bool rw_check_hash(rw_info* prw)
{
	uint8 len = sizeof(rw_info);
	uint32 hash = len, i=0;

	os_printf("checking ... :[%p]\n", prw);
	for(; i!=len - 4; ++i) {
		hash += ((uint8*)prw)[i];
	}

	return hash == prw->hash;
}


void write_rw_hash(rw_info* prw)
{
	uint8 len = sizeof(rw_info);
	uint32 hash = len, i = 0;

	for(; i!=len - 4; ++i) {
		hash += ((uint8*)prw)[i];
	}

	prw->hash = hash;
}


void conn_context_release(conn_context* context)
{
	if(context) {
		if(context->buffer) {
			os_free(context->buffer);
		}

		os_free(context);
	}
}


void rwinfo_init(rw_info* prw)
{
	os_memset(prw, 0, sizeof(rw_info));
	prw->server_addr = ipaddr_addr(CLOUD_SERVER);
	prw->server_port = CLOUD_PORT;
	prw->dev_type = DEV_PLUG;
	os_strcpy(prw->ssid_mine, DEFAULT_SSID);
	os_strcpy(prw->ssid_pwd_mine, DEFAULT_SSID_PWD);
}


void ICACHE_FLASH_ATTR raw_show(unsigned char* buf, size_t buflen)
{
	int i = 0;
	os_printf("*************************RAW_INFO*************************\n");
	for (; i != buflen; ++i) {
		if (i % 16 == 0) {
			os_printf("\n");
		}
		os_printf("%02X ", buf[i]);
	}

	os_printf("\n");
	os_printf("*************************RAW_INFO*************************\n");
}

void ICACHE_FLASH_ATTR show_rw(rw_info* rw)
{
	raw_show((unsigned char*) rw, sizeof(rw_info));
	if(rw->run_mode == MODE_UNKNOWN) {
		//printf("error on ")
	}
	os_printf("Serv Addr: [" IPSTR "]\n", IP2STR(rw->server_addr));
	os_printf("Serv Port: [%d]\n", rw->server_port);
	os_printf("Our SSID: [%s]\n", rw->ssid_mine);
	os_printf("Our SSID PWD: [%s]\n", rw->ssid_pwd_mine);
	os_printf("Router SSID: [%d],[%s]\n", os_strlen(rw->ssid), rw->ssid);
	os_printf("Router SSID PWD: [%s]\n", rw->ssid_pwd);
}


void ICACHE_FLASH_ATTR show_sysinfo()
{
	uint32 chipid = system_get_chip_id();
	uint32 heepsize = system_get_free_heap_size();
	uint32 rtctime = system_get_rtc_time();
	uint32 systime = system_get_time();

	os_printf("\n\nSDK version: [%s]\n", system_get_sdk_version());

	os_printf("SYSTEM INIT OVER\n");
	os_printf("==========SYS INFO==========\n");
	system_print_meminfo();
	os_printf("CHIP   ID: [%d]\n", chipid);
	os_printf("HEAP SIZE: [%d]\n", heepsize);
	os_printf("RTC  TIME: [%d]\n", rtctime);
	os_printf("SYS  TIME: [%d]\n", systime);
	os_printf("==========SYS INFO==========\n");
}

uint8 ICACHE_FLASH_ATTR write_cfg_flash(rw_info* prw)
{
	//写入前，需要擦除
	if (spi_flash_erase_sector(FLASH_HEAD_ADDR / (4 * 1024))
			!= SPI_FLASH_RESULT_OK) {
		os_printf("SPI FLASH ERASE ERROR\n");
		return -1;
	}
	os_printf("SPI FLASH ERASE SUCCESS\n");

	//写入
	if (spi_flash_write(FLASH_HEAD_ADDR, (uint32*) prw, sizeof(rw_info))
			!= SPI_FLASH_RESULT_OK) {
		os_printf("SPI FLASH WRITE ERROR\n");
	}
	os_printf("SPI FLASH WRITE SUCCESS\n");

	return 0;
}


bool ICACHE_FLASH_ATTR read_cfg_flash(rw_info* prw)
{
	if (spi_flash_read(FLASH_HEAD_ADDR, (uint32*) prw, sizeof(rw_info))
			!= SPI_FLASH_RESULT_OK) {
		os_printf("FLASH READ ERROR\n");
		return false;
	}
	os_printf("FLASH READ SUCCESS\n");

	return true;
}


void ICACHE_FLASH_ATTR spi_flash_write_test(enum RUN_MODE mode)
{
	rw_info rw;
	os_memset(&rw, 0, sizeof(rw));
	rw.server_addr = ipaddr_addr("192.168.0.241");
	rw.server_port = 10010;
	os_strcpy(rw.ssid, "useease2");
	os_strcpy(rw.ssid_pwd, "1CBE991A14");
	os_strcpy(rw.ssid_mine, "iPLUG");
	os_strcpy(rw.ssid_pwd_mine, "iPLUG123");
	rw.run_mode = mode;
	rw.dev_type = DEV_PLUG;

	show_rw(&rw);

	//写入前，需要擦除
	if (spi_flash_erase_sector(FLASH_HEAD_ADDR / (4 * 1024))
			!= SPI_FLASH_RESULT_OK) {
		os_printf("SPI FLASH ERASE ERROR\n");
	} else {
		os_printf("SPI FLASH ERASE SUCCESS\n");
	}
	//写入
	if (spi_flash_write(FLASH_HEAD_ADDR, (uint32*) &rw, sizeof(rw))
			!= SPI_FLASH_RESULT_OK) {
		os_printf("SPI FLASH WRITE ERROR\n");
	} else {
		os_printf("SPI FLASH WRITE SUCCESS\n");
	}
}


void ICACHE_FLASH_ATTR spi_flash_read_test()
{
	rw_info rw;
	os_memset(&rw, 0, sizeof(rw));

	if (spi_flash_read(FLASH_HEAD_ADDR, (uint32*) &rw, sizeof(rw))
			!= SPI_FLASH_RESULT_OK) {
		os_printf("FLASH READ ERROR\n");
	} else {
		os_printf("FLASH READ SUCCESS\n");
		show_rw(&rw);
	}
}

void ICACHE_FLASH_ATTR _gpio_low(void* time_arg);
void ICACHE_FLASH_ATTR _gpio_high(void* time_arg)
{
	led_glint* led = (led_glint*)time_arg;
	ETSTimer* timer = led->ptimer;

	os_timer_disarm(timer);

	if(led->limit_count && led->cur_count >= led->limit_count) {
		os_free(timer);
		os_free(led);
		os_printf("free timer and led_glint.\n");
		return ;
	}

	//输出高电平
	gpio_output_set(led->pin, 0, led->pin, 0);
	led->cur_count ++;
	os_timer_setfn(timer, _gpio_low, time_arg);
	os_timer_arm(timer, led->interval, 0);
}


void ICACHE_FLASH_ATTR _gpio_low(void* time_arg)
{
	led_glint* led = (led_glint*)time_arg;
	ETSTimer* timer = led->ptimer;

	os_timer_disarm(timer);
	os_timer_setfn(timer, _gpio_high, time_arg);
	os_timer_arm(timer, led->interval, 0);
	//输出低电平
	gpio_output_set(0, led->pin, led->pin, 0);
}


void ICACHE_FLASH_ATTR led_glint_control(led_glint* led)
{
	os_printf("TIMER INIT\n");
	ETSTimer* timer = (ETSTimer*)os_zalloc(sizeof(ETSTimer));
	led->ptimer = timer;
	os_timer_disarm(timer);
	os_timer_setfn(timer, _gpio_high, (void*)led);
	os_timer_arm(timer, led->interval, 0);
}


void ICACHE_FLASH_ATTR startup_ledshow(rw_info* rw)
{
    led_glint* led = (led_glint*)os_zalloc(sizeof(led_glint));

	PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTDI_U, FUNC_GPIO12);
	PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTCK_U, FUNC_GPIO13);
	PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTMS_U,FUNC_GPIO14);

	if(rw->run_mode == MODE_STATION) {
		led->pin = BIT12;
	} else if(rw->run_mode == MODE_SOFTAP) {
		led->pin = BIT13;
	} else {
		led->pin = BIT14;
	}

    led->interval = 100;
    led->limit_count = 10;

    led_glint_control(led);
}


void ICACHE_FLASH_ATTR heart_beat_cbfn(void* param)
{
	heart_timer* pheart = (heart_timer*)param;
	//需要判断网络状态。。。
	struct espconn* pconn = pheart->conn;
	os_printf("conn: [%p], state: [%d]\n", pconn, pconn->state);

	uint8 buf[2];

	buf[0] = 2;
	buf[1] = 1;
	espconn_sent(pconn, buf, 2);
}


void ICACHE_FLASH_ATTR connected_cloud_cb(void* param)
{
	uint8 rcvbuf[16];
	struct espconn* conn = (struct espconn*)param;

	os_printf("connected_cloud_cb, conn: [%p]\n", conn);
	client_status = STATUS_CONNECTED;
	//注册 断开与接收、发送的回调
	espconn_regist_recvcb(conn, data_received_cb);
	espconn_regist_sentcb(conn, sent_cloud_cb);
	espconn_regist_disconcb(conn, disconnected_cloud_cb);
	//注册心跳回调
	heart_timer* pheart = (heart_timer*)os_zalloc(sizeof(heart_timer));
	ETSTimer* timer = (ETSTimer*)os_zalloc(sizeof(ETSTimer));
	pheart->timer = timer;
	pheart->conn = conn;

	conn->reverse = (void*)pheart;
	os_timer_disarm(timer);
	os_timer_setfn(timer, heart_beat_cbfn, pheart);
	os_timer_arm(timer, 120000, 1);//两分钟一个心跳包, 重复

	uint32* pchipid = (uint32*)(rcvbuf + 2);
	rcvbuf[0] = 7;
	rcvbuf[1] = 0;

	*pchipid = system_get_chip_id();
	rcvbuf[6] = 1;

	espconn_sent(conn, rcvbuf, 7);
	os_printf("DEV RP OVER\n");
}

void ICACHE_FLASH_ATTR reconnect_cloud_cb(void* param, sint8 errcode)
{
	os_printf("reconnect_cloud_cb, code: [%d]\n", errcode);
	client_status = STATUS_DISCONNECTED;
	struct espconn* conn = (struct espconn*)param;

	os_printf("conn: [%p] error, close it.\n", conn);
	espconn_disconnect(conn);
	os_free(conn->proto.tcp);
	os_free(conn);
	if(conn->reverse) {
		os_printf("pheart struct not empty, free it.\n");
		heart_timer* pheart = (heart_timer*) conn->reverse;
//		os_timer_disarm(pheart->timer);
//		os_free(pheart->timer);
//		os_free(pheart);
	}
	os_printf("free struct conn && tcp\n");
}


void ICACHE_FLASH_ATTR disconnected_cloud_cb(void* param)
{
	struct espconn* conn = (struct espconn*)param;

	os_printf("[%p] disconnected_cloud_cb\n", conn);
	client_status = STATUS_DISCONNECTED;

	os_free(conn->proto.tcp);
	os_free(conn);
	if(conn->reverse) {
		os_printf("pheart struct not empty, free it.\n");
		heart_timer* pheart = (heart_timer*) conn->reverse;
//		os_timer_disarm(pheart->timer);
//		os_free(pheart->timer);
//		os_free(pheart);
	}
	os_printf("free struct, free ram\n");

	restart_init_station_chk_timer(1000);
}


void ICACHE_FLASH_ATTR sent_cloud_cb(void* param)
{
	os_printf("DATA TRANSPORTED\n");
}


void procfn_dev_rp_req(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);

	uint8 buf[2];
	buf[0] = sizeof(buf);
	buf[1] = DEV_RP_RSP;
	espconn_sent(pconn, buf, 2);
}

void procfn_heart_req(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
	uint8 buf[2];

	buf[0] = sizeof(buf);
	buf[1] = HEART_RSP;
	espconn_sent(pconn, buf, 2);
}

void procfn_gstatus_req(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
	uint8 buf[2];

	buf[0] = sizeof(buf);
	buf[1] = GSTATUS_RSP;

	espconn_sent(pconn, buf, 2);
}

void procfn_sstatus_req(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
	uint8 buf[2];

	buf[0] = sizeof(buf);
	buf[1] = SSTATUS_RSP;

	espconn_sent(pconn, buf, 2);
}
void procfn_dev_rp_rsp(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
}
void procfn_heart_rsp(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
}
void procfn_gstatus_rsp(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
}
void procfn_sstatus_rsp(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
}

void procfn_ledtest_req(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
	uint8 buf[2];
    led_glint* led = (led_glint*)os_zalloc(sizeof(led_glint));

	PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTDI_U, FUNC_GPIO12);
	led->pin = BIT12;
    led->interval = 100;
    led->limit_count = 100;
    led_glint_control(led);

	buf[0] = sizeof(buf);
	buf[1] = LEDTEST_RSP;

	espconn_sent(pconn, buf, 2);
}
void procfn_ledtest_rsp(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
}

void procfn_setssid_req(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
	rw_info rw;
	uint8 buf[2];
	char* ssid = pdata + 2;
	uint8 ssid_size = os_strlen(ssid);

	if(!ssid_size || !ssid || ssid_size > 32) {
		os_printf("ssid size error\n");
	}

	char* pwd = pdata + 2 + ssid_size + 1;
	uint8 pwd_size = strlen(pwd);
	if(!pwd_size || !pwd || pwd_size > 32) {
		os_printf("ssid pwd size error\n");
	}

	if(2 + ssid_size + 1 + pwd_size + 1 > len) {
		os_printf("data error\n");
	}

	os_printf("recv station config: [%s,%s]\n", ssid, pwd);
	if(!read_cfg_flash(&rw)) {
		os_printf("cfg read from flash error\n");
	}

	rwinfo_init(&rw);
	os_strcpy(rw.ssid, ssid);
	os_strcpy(rw.ssid_pwd, pwd);
	rw.run_mode = MODE_STATION;
	write_rw_hash(&rw);
	write_cfg_flash(&rw);

	buf[0] = sizeof(buf);
	buf[1] = SETSSID_RSP;

	espconn_sent(pconn, buf, 2);
}

void procfn_setssid_rsp(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
}


void restart_timer_cb(void* timer)
{
	os_printf("BE WILL RESTARTED\n");
	system_restart();
}


void procfn_rst_req(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
	uint8 buf[2];

	buf[0] = sizeof(buf);
	buf[1] = RST_RSP;

	espconn_sent(pconn, buf, 2);
	espconn_disconnect(pconn);

	//直接调用restart总是故障，改用定时器，100毫秒后重启，顺带也可以把网络数据发出去
	ETSTimer* ptimer = (ETSTimer*)os_zalloc(sizeof(ETSTimer));
	os_timer_disarm(ptimer);
	os_timer_setfn(ptimer, restart_timer_cb, ptimer);
	os_timer_arm(ptimer, 100, 0);
}

void procfn_rst_rsp(struct espconn* pconn, char* pdata, unsigned short len)
{
	os_printf("Enter %s, pconn: [%p], buf: [%p], len:[%d]\n", __func__, pconn, pdata, len);
}

//这里有可能需要加入 数据包的处理，譬如 多包同时到达，单包分次抵达
void ICACHE_FLASH_ATTR data_received_cb(void* param, char* pdata, unsigned short len)
{
	struct espconn* conn = (struct espconn*)param;
	os_printf("datareceived_cloud_cb, conn: [%p]\n", conn);
	uint8 i = 0;
	uint8 pack_len = pdata[0];
	uint8 glfunc_size = sizeof(gl_procs) / sizeof(struct pack_proc);
	msg_pack_proc_fn fn = NULL;
	uint8 msgtype = pdata[1];
	bool matched = false;

	//TODO: 数据包可能分批抵达，亦可能一次抵达多个
	if(len < pack_len) {
		os_printf("network error, or pack error, or protocol error\n");
		espconn_disconnect(conn);
		return ;
	}

	for(; i != glfunc_size; ++i) {
		if(msgtype == gl_procs[i].msgtype) {
			matched = true;
			fn = gl_procs[i].fn;
			fn(conn, pdata, len);
		}
	}

	if(!matched) {
		os_printf("unknown protocol, connection [%p] closed\n", conn);
		espconn_disconnect(conn);
	}
}


void ICACHE_FLASH_ATTR connect_to_cloud()
{
	if(client_status == STATUS_CONNECTING) {
		os_printf("connecting ... abort.\n");
		return ;
	}

	os_printf("connecting to cloud server ... \n");
	const char server_addr[4] = {211, 155, 86, 145};
	struct espconn* conn = (struct espconn*)os_zalloc(sizeof(struct espconn));
	esp_tcp* tcp = (esp_tcp*)os_zalloc(sizeof(esp_tcp));

	os_memcpy(tcp->remote_ip, server_addr, 4);
	tcp->local_port = espconn_port();
	tcp->remote_port = CLOUD_PORT;

	conn->proto.tcp = tcp;
	conn->type = ESPCONN_TCP;
	conn->state = ESPCONN_NONE;
	client_status = STATUS_CONNECTING;

	os_printf("local port: [%d], remote [%d:%d]\n", tcp->local_port, (uint32)tcp->remote_ip, tcp->remote_port);
	espconn_regist_connectcb(conn, connected_cloud_cb);
	espconn_regist_reconcb(conn, reconnect_cloud_cb);
	espconn_connect(conn);
	os_printf("connect cmd over\n");
}


void ICACHE_FLASH_ATTR init_over()
{
	os_printf("SYSTEM INIT COMPLETED\n");
}

void ICACHE_FLASH_ATTR station_connect_status_check_timercb(void* _timer)
{
	ETSTimer* timer = (ETSTimer*)_timer;
	os_printf("wifi_station_dhcpc_status: [%d]\n", wifi_station_dhcpc_status());
    if(wifi_station_dhcpc_status() == DHCP_STOPPED && !wifi_station_dhcpc_start()) {
    	os_printf("wifi_station_dhcpc_start error\n");
    }

    os_printf("wifi station connect status: [%d]\n", wifi_station_get_connect_status());
    if(wifi_station_get_connect_status() == STATION_GOT_IP && client_status != STATUS_CONNECTED) {
    	os_printf("Connected to ROUTER, connecting to cloud\n");
    	connect_to_cloud();
    	client_status = STATUS_CONNECTING;
    }

    //连接成功后停止定时器
    if(client_status == STATUS_CONNECTED) {
    	os_timer_disarm(timer);
    }

    //如果系统模式非station模式，则停止
    if(wifi_get_opmode() != STATION_MODE) {
    	os_timer_disarm(timer);
    }
}

/*
 * 定时检查是否连接到云端，若未连接到云端则定时器开启，若已连接则关闭
 * 从云端断开时，定时器将重新开启。
 * station 模式使用
 */
void ICACHE_FLASH_ATTR restart_init_station_chk_timer(int interval)
{
	os_printf("启动计时器\n");
    os_timer_disarm(&station_chk_timer);
    os_timer_setfn(&station_chk_timer, station_connect_status_check_timercb, &station_chk_timer);
    os_timer_arm(&station_chk_timer, interval, 1);// 重复，每秒检查一次，若连上后取消，连接断开或其他事件重启此 timer
    os_printf("station checker timer start completed\n");
}

void free_connection(struct espconn* pconn)
{
	heart_timer* pheart = (heart_timer*)pconn->reverse;
	os_timer_disarm(pheart->timer);
	os_free(pheart->timer);
	os_free(pheart);
	os_free(pconn->proto.tcp);
	os_free(pconn);
}


void client_disconnected_cb(void* conn)
{
	struct espconn* pconn = (struct espconn*)conn;
	os_printf("client disconnected\n");
	os_printf("debug: [%p], [" IPSTR ":%d], state, [%d]\n",
			pconn, IP2STR(pconn->proto.tcp->remote_ip), pconn->proto.tcp->remote_port, pconn->state);
}


void ICACHE_FLASH_ATTR client_connected_cb(void* conn)
{
	struct espconn* pconn = (struct espconn*)conn;
	os_printf("client connected\n");
	os_printf("debug: [%p], [" IPSTR ":%d], state, [%d]\n",
			pconn, IP2STR(pconn->proto.tcp->remote_ip), pconn->proto.tcp->remote_port, pconn->state);

	espconn_regist_recvcb(pconn, data_received_cb);
	espconn_regist_sentcb(pconn, sent_cloud_cb);
	espconn_regist_disconcb(pconn, client_disconnected_cb);
	espconn_regist_reconcb(pconn, client_reconnect_cb);
}


void ICACHE_FLASH_ATTR client_reconnect_cb(void* conn, sint8 err)
{
	struct espconn* pconn = (struct espconn*)conn;
	os_printf("client connection error: [%d]\n", err);

	free_connection(pconn);
	//server_listen();
}


void ICACHE_FLASH_ATTR server_listen()
{
	os_printf("begin server_listen\n");
	struct espconn* pconn = (struct espconn*)os_zalloc(sizeof(struct espconn));
	esp_tcp* ptcp = (esp_tcp*)os_zalloc(sizeof(esp_tcp));
	heart_timer* pheart = (heart_timer*)os_zalloc(sizeof(heart_timer));
	ETSTimer* ptimer = (ETSTimer*)os_zalloc(sizeof(ETSTimer));

	pconn->state = ESPCONN_NONE;
	pconn->type = ESPCONN_TCP;
	pconn->proto.tcp = ptcp;
	pconn->proto.tcp->local_port = LOCAL_SERVER_PORT;
	pheart->mode = MODE_SERVER;
	pheart->conn = pconn;
	pheart->timer = ptimer;
	pconn->reverse = (void*)pheart;

	espconn_regist_connectcb(pconn, client_connected_cb);

	espconn_accept(pconn);
	espconn_regist_time(pconn, 120, 0);
	os_printf("server_listen ok, conn: [%p]\n", pconn);
}


void ICACHE_FLASH_ATTR listen_chk_timer_cb(void* _timer)
{
	//start tcp listen ...
	os_printf("listen chk timer cb, timer: [%p]\n", _timer);
	ETSTimer* timer = (ETSTimer*)_timer;
	uint8 mode = wifi_get_opmode();
	if(mode == STATION_MODE && wifi_station_get_connect_status() != STATION_GOT_IP) {
		os_printf("station cannot got ip , cannot start server listen.\n");
		return ;
	}

	os_timer_disarm(timer);
	server_listen();
}


void ICACHE_FLASH_ATTR user_btn_long_press()
{
	os_printf("ON LONG PRESS\n");
	rw_info rw;

	read_cfg_flash(&rw);
	rw.run_mode = MODE_SOFTAP;
	write_rw_hash(&rw);
	write_cfg_flash(&rw);
	system_restart();
}


void ICACHE_FLASH_ATTR user_btn_short_press()
{
	os_printf("ON SHORT PRESS\n");
	uint32 iRet = 100;

	iRet = GPIO_INPUT_GET(14);
	os_printf("OUT: [%d]\n", iRet);
}


void ICACHE_FLASH_ATTR set_softap_mode()
{
	os_printf("run in wifi_boardcast mode\n");
	if(!wifi_set_opmode(SOFTAP_MODE)) {
		os_printf("wifi set opmode to softap error\n");
		//可以停机了。。。
	}
	os_printf("wifi set opmode softap ok\n");

	struct softap_config apconfig;
	memset(&apconfig, 0, sizeof(struct softap_config));
	os_strcpy(apconfig.ssid, DEFAULT_SSID);
	os_strcpy(apconfig.password, DEFAULT_SSID_PWD);
	apconfig.ssid_len = 0;
	apconfig.authmode = AUTH_WPA_WPA2_PSK;
	apconfig.ssid_hidden = 0;
	apconfig.max_connection = 5;
	apconfig.beacon_interval = 100;

	if (!wifi_softap_set_config(&apconfig)) {
		os_printf("[%s] [%s] ERROR\n", __func__,
				"wifi_softap_set_config");
	}
	os_printf("wifi_softap_set_config success\n");

	struct ip_info ipinfo;

    ipinfo.gw.addr = ipaddr_addr(DEFAULT_GWADDR);
	ipinfo.ip.addr = ipaddr_addr(DEFAULT_GWADDR);
	ipinfo.netmask.addr = ipaddr_addr("255.255.255.0");

	if(!wifi_set_ip_info(SOFTAP_IF, &ipinfo)) {
		os_printf("wifi_set_ip_info error\n");
		//my god...
	}

	struct dhcps_lease please;
	please.start_ip.addr = ipaddr_addr(DHCP_BEGIN_ADDR);
	please.end_ip.addr = ipaddr_addr(DHCP_END_ADDR);

	if(!wifi_softap_set_dhcps_lease(&please)) {
		os_printf("wifi_softap_set_dhcps_lease error\n");
		//unknown...
	}
	os_printf("wifi_softap_dhcps config lease ok\n");
}

/******************************************************************************
 * FunctionName : user_init
 * Description  : entry of user application, init user function here
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR user_init(void)
{
	uart_init(BIT_RATE_115200, BIT_RATE_115200);
    show_sysinfo();

    rw_info rw;
    os_memset(&rw, 0, sizeof(rw_info));

    if(!read_cfg_flash(&rw)) {
    	rw.run_mode = MODE_SOFTAP;
    }

    if(!rw_check_hash(&rw)) {
    	os_printf("rw check hash error\n");
    	rw.run_mode = MODE_SOFTAP;
    } else {
    	show_rw(&rw);
    }

    //startup_ledshow(&rw);

    single_key[0] = key_init_single(13, PERIPHS_IO_MUX_MTCK_U, FUNC_GPIO13,
    		user_btn_long_press, user_btn_short_press);

    keys.key_num = 1;
    keys.single_key = single_key;

    key_init(&keys);
    //DHTInit(SENSOR_DHT11, 5000);

	PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTMS_U,FUNC_GPIO14);
	gpio_output_set(0, 0, 0, BIT14);


#if 0
    if(rw.run_mode == MODE_STATION) {
    	os_printf("run in client only mode\n");
		wifi_set_opmode(STATION_MODE);
        struct station_config config;
        os_memset(&config, 0, sizeof(struct station_config));
        os_strcpy(config.ssid, rw.ssid);
        os_strcpy(config.password, rw.ssid_pwd);

        /* need to sure that you are in station mode first,
         * otherwise it will be failed. */
        wifi_station_set_config(&config);
        wifi_station_set_auto_connect(1);

        //启动定时器，每秒中检查，若连接到路由器，则连接云端
        //若成功连接到云端，则关闭定时器
        //若从云端断开连接，则重启定时器
        restart_init_station_chk_timer(1000);
    } else if (rw.run_mode == MODE_SOFTAP) {
    	set_softap_mode();
    }

    os_printf("OVER\n");
	os_timer_disarm(&server_listen_chk_timer);
	os_timer_setfn(&server_listen_chk_timer, listen_chk_timer_cb, &server_listen_chk_timer);
	os_timer_arm(&server_listen_chk_timer, 1000, 1);
    system_init_done_cb(init_over);
#endif
}

