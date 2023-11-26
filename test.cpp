#include <cstdio>

#include "chpasswd.h"

int main()
{
    char err_msg[CHPASSWD_MESSAGE_LENGTH];
    auto const err = chpasswd(
        "/tmp", "root", "password@123", PASSWD_ENCRYPT_METHOD_YESCRYPT,&err_msg);
    if (err != 0) {
        fprintf(stderr, "chpasswd failed: %s\n", err_msg);
    }
}
