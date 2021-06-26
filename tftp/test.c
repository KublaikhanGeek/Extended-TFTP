#include "tftp_client.h"
#include <pthread.h>

int filesize     = 0;
int transfersize = 0;

void* thread(void* arg)
{
    while (1)
    {
        if (transfersize >= filesize)
        {
            printf("End of transmission. filesize: %d, transfersize: %d \n", filesize, transfersize);
            break;
        }

        printf("filesize: %d, transfersize: %d \n", filesize, transfersize);
        sleep(1);
    }

    return NULL;
}

int main()
{
    void* obj = tftp_create("192.168.20.176", 69, "192.168.18.145", -1);
    if (obj)
    {
        tftp_set_verbose(obj, 1);
        tftp_set_trace(obj, 1);
        tftp_set_blocksize(obj, 1024);
        tftp_set_mode(obj, "octet");
        tftp_cmd_get(obj, "test.txt", "test.txt", &filesize, &transfersize);

        pthread_t th;
        int ret;
        ret = pthread_create(&th, NULL, thread, NULL);
        if (ret != 0)
        {
            printf("Create thread error!\n");
        }

        pthread_join(th, NULL);
    }

    return 0;
}
