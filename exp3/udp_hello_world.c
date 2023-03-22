#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>

#define TARGET_IP_ADDR "127.0.0.1" // 目标服务器IP地址
#define TARGET_PORT 9000           // 目标服务器端口
#define SOURCE_PORT 12345          // 源端口

int main()
{
    libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];

    // 初始化libnet库
    l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    // 构建UDP负载
    char payload[] = "Hello world";
    uint32_t payload_length = strlen(payload);

    // 构建UDP数据包
    libnet_ptag_t udp_tag = libnet_build_udp(
        SOURCE_PORT,                   // 源端口
        TARGET_PORT,                   // 目标端口
        LIBNET_UDP_H + payload_length, // 长度(UDP头部长度+负载长度)
        0,                             // 校验和, 设为0让libnet自动计算
        (uint8_t *)payload,            // 负载内容
        payload_length,                // 负载长度
        l,                             // libnet句柄
        0                              // 0表示新构建一个数据包
    );

    if (udp_tag == -1)
    {
        fprintf(stderr, "libnet_build_udp() failed: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return EXIT_FAILURE;
    }

    // 构建IP数据包
    // 构建IP数据包
    libnet_ptag_t ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_UDP_H + payload_length,             // 长度(IP头部长度+UDP头部长度+负载长度)
        0,                                                         // 服务类型
        0,                                                         // 标识符
        0,                                                         // 片偏移
        64,                                                        // TTL
        IPPROTO_UDP,                                               // 上层协议
        0,                                                         // 校验和, 设为0让libnet自动计算
        libnet_get_ipaddr4(l),                                     // 源IP地址, 使用默认源IP
        libnet_name2addr4(l, TARGET_IP_ADDR, LIBNET_DONT_RESOLVE), // 目标IP地址
        NULL,                                                      // 由于UDP包已经包含了负载，这里设置为NULL
        0,                                                         // 负载长度设置为0
        l,                                                         // libnet句柄
        0                                                          // 0表示新构建一个数据包
    );

    if (ip_tag == -1)
    {
        fprintf(stderr, "libnet_build_ipv4() failed: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        return EXIT_FAILURE;
    }

    // 发送数据包
    int bytes_written = libnet_write(l);
    if (bytes_written == -1)
    {
        fprintf(stderr, "libnet_write() failed: %s\n", libnet_geterror(l));
    }
    libnet_destroy(l);
    return EXIT_FAILURE;

    printf("UDP数据包已发送! (共%d字节)\n", bytes_written);

    // 销毁libnet句柄
    libnet_destroy(l);

    return EXIT_SUCCESS;
}