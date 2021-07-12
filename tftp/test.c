#include "tftp_client.h"
#include "config.h"
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
    void* obj = tftp_create("192.168.20.11", 69, "192.168.18.145", -1);
    if (obj)
    {
        tftp_set_verbose(obj, 1);
        tftp_set_trace(obj, 1);
#if 1
        //    tftp_set_blocksize(obj, 2048);
        //   tftp_set_mode(obj, "octet");
        tftp_cmd_put(obj, "versions.zip", "hello.txt", &filesize, &transfersize);

        //    tftp_cmd_get(obj, "versions.zip", "server.cap", &filesize, &transfersize);
#endif

#if 0
        tftp_set_blocksize(obj, 1024);
        tftp_set_mode(obj, "netascii");
        tftp_cmd_put(obj, "test.txt", "test.txt", &filesize, &transfersize);

        tftp_cmd_get(obj, "test.txt", "test.txt", &filesize, &transfersize);
#endif

#if 0
        char path[4096];
        int size;

        printf("------------------\n");
        if (TFTP_CWDOK == tftp_cmd_cd(obj, "/home/nvidia/andy"))
        {
            printf("切换路径成功\n");
        }

        printf("+++++++++++++++++++\n");
        if (TFTP_PWDOK == tftp_cmd_pwd(obj, path))
        {
            printf("当前路径：%s\n", path);
        }

        printf("------------------\n");
        if (TFTP_DELEOK == tftp_cmd_delete(obj, "chu"))
        {
            printf("删除文件成功\n");
        }

        // printf("+++++++++++++++++++\n");
        // if (TFTP_RENAMEOK == tftp_cmd_rename(obj, "yu", "yu.bak"))
        //{
        //    printf("重命名文件成功\n");
        //}

        printf("------------------\n");
        if (TFTP_SIZEOK == tftp_cmd_size(obj, "system.tar.gz", &size))
        {
            printf("文件大小：%d\n", size);
        }

        printf("+++++++++++++++++++\n");
        if (TFTP_CHMODOK == tftp_cmd_chmod(obj, "0777", "update.sh"))
        {
            printf("文件权限修改成功\n");
        }

        printf("------------------\n");
        if (TFTP_MKDIROK == tftp_cmd_mkdir(obj, "tftp_cmd"))
        {
            printf("创建文件夹成功\n");
        }

        printf("+++++++++++++++++++\n");
        if (TFTP_RMDIROK == tftp_cmd_rmdir(obj, "test_dir"))
        {
            printf("删除文件夹成功\n");
        }

        printf("------------------\n");
        if (TFTP_CDUPOK == tftp_cmd_cdup(obj))
        {
            printf("切到上级目录成功\n");
        }

        printf("------------------\n");
        if (TFTP_CWDOK == tftp_cmd_cd(obj, "/home/nvidia/upgrade"))
        {
            printf("切换路径成功\n");
        }

        printf("+++++++++++++++++++\n");
        if (TFTP_PWDOK == tftp_cmd_pwd(obj, path))
        {
            printf("当前路径：%s\n", path);
        }

        printf("+++++++++++++++++++\n");
        if (TFTP_LSOK == tftp_cmd_ls(obj, path))
        {
            printf("ls：\r\n%s\n", path);
        }

        printf("------------------\n");
#endif
#if 0
        pthread_t th;
        int ret;
        ret = pthread_create(&th, NULL, thread, NULL);
        if (ret != 0)
        {
            printf("Create thread error!\n");
        }

        pthread_join(th, NULL);
#endif
    }

    return 0;
}
