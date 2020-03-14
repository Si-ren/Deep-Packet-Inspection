#include "dpi.h"
#include <string.h>
int dpi_analyze_tcp_ssh(dpi_pkt *pkt)
{

    //分析报文前面4个字节是不是SSH- ,如果是就表示是SSH报文
    if(pkt->payload_len>=4)
    {
        if(memcmp(pkt->payload,"SSH-",4)==0)
        {
            return 1;
        }
    }


    return 0;
}
