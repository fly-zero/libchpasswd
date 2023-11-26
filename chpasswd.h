#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 修改用户密码
 *
 * @param root_path 根目录，相当于 chroot 的根目录
 * @param username 用户名
 * @param password 密码
 * @return true 成功
 * @return false 失败
 */
bool chpasswd(const char * root_path, const char * username, const char * password);

#ifdef __cplusplus
}
#endif