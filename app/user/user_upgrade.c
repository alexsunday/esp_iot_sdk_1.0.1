/*
 * user_upgrade.c
 *
 *  Created on: 2015年5月5日
 *      Author: Sunday
 */


#define VERSION_CODE 1
#define VERSION_NAME v0.1.0


/*
 * 自动升级使用，与服务端通讯，获取最新版本号，匹配自身版本号
 * 分为版本号与版本字符串
 * 需要对文件内容进行hash
 */

