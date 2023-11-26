#pragma once

#ifdef __cplusplus
extern "C" {
#endif

bool chpasswd(const char * root_path, const char * username, const char * password);

#ifdef __cplusplus
}
#endif