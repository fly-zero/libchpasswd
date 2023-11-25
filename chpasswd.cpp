#include <bits/types/FILE.h>
#include <crypt.h>
#include <pwd.h>
#include <shadow.h>
#include <sys/stat.h>

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#include <memory>
#include <system_error>
#include <utility>
#include <vector>
#include <string>

#include "chpasswd.h"

class my_passwd : public passwd {
public:
    explicit my_passwd(const passwd & pw);

    my_passwd(const my_passwd &) = delete;

    my_passwd & operator=(const my_passwd &) = delete;

    my_passwd(my_passwd && other) noexcept;

    my_passwd & operator=(my_passwd && other) noexcept;

    ~my_passwd();
};

class my_spwd : public spwd {
public:
    explicit my_spwd(const spwd & sp);

    my_spwd(const my_spwd &) = delete;

    my_spwd & operator=(const my_spwd &) = delete;

    my_spwd(my_spwd && other) noexcept;

    my_spwd & operator=(my_spwd && other) noexcept;

    ~my_spwd();
};

class chpasswd_context {
    struct file_deleter {
        void operator()(FILE * file) const noexcept {
            fclose(file);
        }
    };

    using file_ptr = std::unique_ptr<FILE, file_deleter>;

public:
    explicit chpasswd_context(const char * root_path);

    /**
     * @brief 查找 passwd 纪录
     *
     * @param username 用户名
     * @return passwd* passwd 纪录
     */
    passwd * find_passwd(const char * username);

    /**
     * @brief 查找 spwd 纪录
     *
     * @param username 用户名
     * @return passwd* passwd 纪录
     */
    spwd * find_spwd(const char * username);

    /**
     * @brief 创建 passwd 备份文件
     *
     * @param root_path 根目录
     * @return true 创建成功
     * @return false 创建失败
     */
    bool create_passwd_backup(const char * root_path);

    /**
     * @brief 创建 shadow 备份文件
     *
     * @param root_path 根目录
     * @return true 创建成功
     * @return false 创建失败
     */
    bool create_shadow_backup(const char * root_path);

    /**
     * @brief 写 passwd 文件
     *
     * @param root_path 根目录
     * @return true 成功
     * @return false 失败
     */
    bool write_passwd(const char * root_path);

    /**
     * @brief 写 shadow 文件
     * 
     * @param root_path 根目录
     * @return true 成功
     * @return false 失败
     */
    bool write_shadow(const char * root_path);

protected:
    /**
    * @brief 加载 passwd 文件
    *
    * @param fp 文件指针
    * @return std::vector<my_passwd> my_passwd 列表
    */
    static std::vector<my_passwd> load_passwd(FILE * fp);

    /**
    * @brief 加载 shadow 文件
    *
    * @param fp 文件指针
    * @return std::vector<my_spwd> my_spwd 列表
    */
    static std::vector<my_spwd> load_shadow(FILE * fp);

    /**
     * @brief 加载文件的 stat 信息
     *
     * @param path 文件路径
     * @return struct stat 文件的 stat 信息
     */
    static struct stat load_stat(FILE * fp);

    /**
     * @brief 构造系统错误
     *
     * @param format 消息格式
     * @param ... 消息参数
     * @return std::system_error 系统错误
     */
    static std::system_error system_error(
        const char * format, ...) __attribute__((format(printf, 1, 2)));

    /**
     * @brief 打开文件并设置权限
     *
     * @param filename 文件路径
     * @param modes 打开模式
     * @param st 文件的 stat 信息
     * @return file_ptr 文件指针
     */
    static file_ptr open_file_perms(
        const char * filename, const char * modes, const struct stat & st);

    /**
     * @brief 创建备份文件
     *
     * @param root_path 根目录
     * @param dst_name 文件名
     * @param src_fp 源文件指针
     * @param src_st 源文件的 stat 信息
     * @return true 成功
     * @return false 失败
     */
    static bool create_backup(
        const char * root_path, const char * dst_name, FILE * src_fp, const struct stat & src_st);

private:
    std::string passwd_path_;
    std::string shadow_path_;
    file_ptr passwd_fp_;
    file_ptr shadow_fp_;
    std::vector<my_passwd> pwds_;
    std::vector<my_spwd> spwds_;
    struct stat passwd_st_{};
    struct stat shadow_st_{};
};

inline my_passwd::my_passwd(const passwd & pw) {
    pw_name = strdup(pw.pw_name);
    pw_passwd = strdup(pw.pw_passwd);
    pw_uid = pw.pw_uid;
    pw_gid = pw.pw_gid;
    pw_gecos = strdup(pw.pw_gecos);
    pw_dir = strdup(pw.pw_dir);
    pw_shell = strdup(pw.pw_shell);
}

inline my_passwd::my_passwd(my_passwd && other) noexcept {
    pw_name = std::exchange(other.pw_name, nullptr);
    pw_passwd = std::exchange(other.pw_passwd, nullptr);
    pw_uid = other.pw_uid;
    pw_gid = other.pw_gid;
    pw_gecos = std::exchange(other.pw_gecos, nullptr);
    pw_dir = std::exchange(other.pw_dir, nullptr);
    pw_shell = std::exchange(other.pw_shell, nullptr);
}

inline my_passwd & my_passwd::operator=(my_passwd && other) noexcept {
    if (this != &other) {
        free(pw_name);
        free(pw_passwd);
        free(pw_gecos);
        free(pw_dir);
        free(pw_shell);

        pw_name = std::exchange(other.pw_name, nullptr);
        pw_passwd = std::exchange(other.pw_passwd, nullptr);
        pw_uid = other.pw_uid;
        pw_gid = other.pw_gid;
        pw_gecos = std::exchange(other.pw_gecos, nullptr);
        pw_dir = std::exchange(other.pw_dir, nullptr);
        pw_shell = std::exchange(other.pw_shell, nullptr);
    }

    return *this;
}

inline my_passwd::~my_passwd() {
    free(pw_name);
    free(pw_passwd);
    free(pw_gecos);
    free(pw_dir);
    free(pw_shell);
}

inline my_spwd::my_spwd(const spwd & sp) {
    sp_namp = strdup(sp.sp_namp);
    sp_pwdp = strdup(sp.sp_pwdp);
    sp_lstchg = sp.sp_lstchg;
    sp_min = sp.sp_min;
    sp_max = sp.sp_max;
    sp_warn = sp.sp_warn;
    sp_inact = sp.sp_inact;
    sp_expire = sp.sp_expire;
    sp_flag = sp.sp_flag;
}

inline my_spwd::my_spwd(my_spwd && other) noexcept {
    sp_namp = std::exchange(other.sp_namp, nullptr);
    sp_pwdp = std::exchange(other.sp_pwdp, nullptr);
    sp_lstchg = other.sp_lstchg;
    sp_min = other.sp_min;
    sp_max = other.sp_max;
    sp_warn = other.sp_warn;
    sp_inact = other.sp_inact;
    sp_expire = other.sp_expire;
    sp_flag = other.sp_flag;
}

inline my_spwd & my_spwd::operator=(my_spwd && other) noexcept {
    if (this != &other) {
        free(sp_namp);
        free(sp_pwdp);

        sp_namp = std::exchange(other.sp_namp, nullptr);
        sp_pwdp = std::exchange(other.sp_pwdp, nullptr);
        sp_lstchg = other.sp_lstchg;
        sp_min = other.sp_min;
        sp_max = other.sp_max;
        sp_warn = other.sp_warn;
        sp_inact = other.sp_inact;
        sp_expire = other.sp_expire;
        sp_flag = other.sp_flag;
    }

    return *this;
}

inline my_spwd::~my_spwd() {
    free(sp_namp);
    free(sp_pwdp);
}

inline chpasswd_context::chpasswd_context(const char * root_path)
    : passwd_path_(root_path + std::string("/etc/passwd"))
    , shadow_path_(root_path + std::string("/etc/shadow"))
    , passwd_fp_(fopen(passwd_path_.c_str(), "r"))
    , shadow_fp_(fopen(shadow_path_.c_str(), "r"))
    , pwds_(load_passwd(passwd_fp_.get()))
    , spwds_(load_shadow(shadow_fp_.get()))
    , passwd_st_(load_stat(passwd_fp_.get()))
    , shadow_st_(load_stat(shadow_fp_.get())) {
    if (!passwd_fp_) {
        throw system_error("cannot open file %s", passwd_path_.c_str());
    }

    if (pwds_.empty()) {
        throw std::runtime_error("cannot load passwd file");
    }
}

inline passwd * chpasswd_context::find_passwd(const char * username) {
    for (auto & pwd : pwds_) {
        if (strcmp(pwd.pw_name, username) == 0) {
            return &pwd;
        }
    }
    return nullptr;
}


inline spwd * chpasswd_context::find_spwd(const char * username) {
    for (auto & spwd : spwds_) {
        if (strcmp(spwd.sp_namp, username) == 0) {
            return &spwd;
        }
    }
    return nullptr;
}

inline bool chpasswd_context::create_passwd_backup(const char * root_path) {
    return create_backup(root_path, "/etc/passwd-", passwd_fp_.get(), passwd_st_);
}

inline bool chpasswd_context::create_shadow_backup(const char * root_path) {
    return create_backup(root_path, "/etc/shadow-", shadow_fp_.get(), shadow_st_);
}

bool chpasswd_context::write_passwd(const char * root_path) {
    // 创建临时 passwd 文件
    auto const temp_path = root_path + std::string("/etc/passwd+");
    file_ptr fp{open_file_perms(temp_path.c_str(), "w", passwd_st_)};
    if (!fp) {
        return false;
    }

    // 写入临时 passwd 文件
    for (auto & pwd : pwds_) {
        if (putpwent(&pwd, fp.get()) != 0) {
            return false;
        }
    }

    // 刷新 passwd 文件
    fflush(fp.get());
    fsync(fileno(fp.get()));

    // 关闭 passwd 文件
    passwd_fp_.reset();

    // 重命名临时 passwd 文件
    if (rename(temp_path.c_str(), passwd_path_.c_str()) != 0) {
        return false;
    }

    return true;
}

bool chpasswd_context::write_shadow(const char * root_path) {
    // 创建临时 shadow 文件
    auto const temp_path = root_path + std::string("/etc/shadow+");
    file_ptr fp{open_file_perms(temp_path.c_str(), "w", shadow_st_)};
    if (!fp) {
        return false;
    }

    // 写入临时 shadow 文件
    for (auto & spwd : spwds_) {
        if (putspent(&spwd, fp.get()) != 0) {
            return false;
        }
    }

    // 刷新 shadow 文件
    fflush(fp.get());
    fsync(fileno(fp.get()));

    // 关闭 shadow 文件
    shadow_fp_.reset();

    // 重命名临时 shadow 文件
    if (rename(temp_path.c_str(), shadow_path_.c_str()) != 0) {
        return false;
    }

    return true;
}

inline std::vector<my_passwd> chpasswd_context::load_passwd(FILE * fp) {
    std::vector<my_passwd> ret;
    if (fp) for (passwd * pw; (pw= fgetpwent(fp)); ) {
        ret.emplace_back(*pw);
    }
    return ret;
}

inline std::vector<my_spwd> chpasswd_context::load_shadow(FILE * fp) {
    std::vector<my_spwd> ret;
    if (fp) for (spwd * sp; (sp= fgetspent(fp)); ) {
        ret.emplace_back(*sp);
    }
    return ret;
}

inline struct stat chpasswd_context::load_stat(FILE * fp) {
    struct stat st{};
    if (!fp) return st;

    if (fstat(fileno(fp), &st) != 0) {
        throw system_error("cannot stat file");
    }

    return st;
}

std::system_error chpasswd_context::system_error(const char * format, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof buf, format, ap);
    va_end(ap);

    return std::system_error{errno, std::system_category(), buf};
}

inline auto chpasswd_context::open_file_perms(
    const char * filename, const char * modes, const struct stat & st) -> file_ptr {
    // 打开文件
    auto const mask = umask(0777);
    file_ptr fp{fopen(filename, modes)};
    umask(mask);

    // 设置文件的用户
    if (fchown(fileno(fp.get()), st.st_uid, st.st_gid) != 0) {
        return {};
    }

    // 设置文件的权限
    if (fchmod(fileno(fp.get()), st.st_mode & 0664) != 0) {
        return {};
    }

    return fp;
}

bool chpasswd_context::create_backup(
    const char * root_path, const char * dst_name, FILE * src_fp, const struct stat & src_st) {
    // 打开 shadow 备份文件
    const auto backup_path = std::string(root_path) + dst_name;
    file_ptr backup_fp{open_file_perms(backup_path.c_str(), "w", src_st)};
    if (!backup_fp) {
        goto fail;
    }

    // 复制 shadow 文件到 shadow 备份文件
    char buf[4096];
    for (size_t n; (n= fread(buf, 1, sizeof buf, src_fp)) > 0; ) {
        if (fwrite(buf, 1, n, backup_fp.get()) != n) {
            goto fail;
        }
    }

    // 刷新 shadow 备份文件
    fflush(backup_fp.get());
    fsync(fileno(backup_fp.get()));
    return true;

fail:
    unlink(backup_path.c_str());
    return false;
}

bool chpasswd(const char * root_path, const char * username, const char * password) {

    // 构造上下文
    chpasswd_context ctx{root_path};

    // 以用户名查找 pwd
    auto const pwd = ctx.find_passwd(username);
    if (!pwd) {
        return false; // 用户不存在
    }

    // 计算密码的 hash
    char prefix[128]{"$6$"}; // SHA512
    constexpr auto rounds = 5000;
    auto const salt = crypt_gensalt(prefix, rounds, nullptr, 0);
    auto const hash = crypt(password, salt);

    // 以用户名查找 spwd
    auto const sp = ctx.find_spwd(username);

    // 更新 shadow 纪录
    bool update_shadow = false;
    if (sp) {
        // 修改 shadow 文件
        update_shadow = true;
        sp->sp_pwdp = hash;
        sp->sp_lstchg = time(nullptr) / 86400;
        if (sp->sp_lstchg == 0) {
            sp->sp_lstchg = 1;
        }
    }

    // 更新 passwd 纪录
    bool update_passwd = false;
    if (!sp || (strcmp(pwd->pw_passwd, "x") != 0)) {
        update_passwd = true;
        pwd->pw_passwd = hash;
    }

    // 更新 shadow 文件
    if (update_shadow) {
        if (!ctx.create_shadow_backup(root_path)) {
            return false;
        }

        if (!ctx.write_shadow(root_path)) {
            return false;
        }
    }

    // 更新 passwd 文件
    if (update_passwd) {
        if (!ctx.create_passwd_backup(root_path)) {
            return false;
        }

        if (!ctx.write_passwd(root_path)) {
            return false;
        }
    }

    return true;
}