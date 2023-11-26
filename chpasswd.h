#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define CHPASSWD_MESSAGE_LENGTH 1024

enum passwd_encrypt_method {
    PASSWD_ENCRYPT_METHOD_MD5,
    PASSWD_ENCRYPT_METHOD_BCRYPT,
    PASSWD_ENCRYPT_METHOD_YESCRYPT,
    PASSWD_ENCRYPT_METHOD_SHA256,
    PASSWD_ENCRYPT_METHOD_SHA512,
    PASSWD_ENCRYPT_METHOD_DES,
};

/**
 * @brief 修改用户密码
 *
 * @param root_path 根目录，相当于 chroot 的根目录
 * @param username 用户名
 * @param password 密码
 * @param encrypt_method 加密方法
 * @return true 成功
 * @return false 失败
 */
int chpasswd(
    const char * root_path,
    const char * username,
    const char * password,
    passwd_encrypt_method encrypt_method,
    char (*err_msg)[CHPASSWD_MESSAGE_LENGTH]);

#ifdef __cplusplus
}
#endif
