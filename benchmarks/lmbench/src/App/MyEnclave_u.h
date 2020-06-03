#ifndef MYENCLAVE_U_H__
#define MYENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"
#include "sgx_eid.h"
#include "struct/sgx_pthread_struct.h"
#include "sgx_eid.h"
#include "time.h"
#include "struct/sgx_pwd_struct.h"
#include "struct/sgx_grp_struct.h"
#include "struct/sgx_utsname_struct.h"
#include "sgx/sys/types.h"
#include "stdarg.h"
#include "sgx/sys/types.h"
#include "struct/sgx_stdio_struct.h"
#include "struct/sgx_syseventfd_struct.h"
#include "sgx/sys/types.h"
#include "struct/sgx_syssocket_struct.h"
#include "sgx/sys/types.h"
#include "struct/sgx_netdb_struct.h"
#include "struct/sgx_netinetin_struct.h"
#include "sgx/sys/types.h"
#include "sgx/sys/types.h"
#include "struct/sgx_sysuio_struct.h"
#include "sgx/sys/types.h"
#include "struct/sgx_sysmman_struct.h"
#include "struct/sgx_poll_struct.h"
#include "struct/sgx_sysepoll_struct.h"
#include "struct/sgx_sysselect_struct.h"
#include "sgx/sys/types.h"
#include "struct/sgx_syswait_struct.h"
#include "sgx/sys/types.h"
#include "sgx/sys/stat.h"
#include "utime.h"
#include "struct/sgx_dirent_struct.h"
#include "struct/sgx_sysresource_struct.h"
#include "struct/sgx_arpainet_struct.h"
#include "sgx/sys/types.h"
#include "struct/sgx_signal_struct.h"
#include "sgx/sys/types.h"
#include "sgx/rpc/svc.h"
#include "sgx/rpc/xdr.h"
#include "struct/sgx_ifaddrs_struct.h"
#include "struct/sgx_netif_struct.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, do_execve, ());
void SGX_UBRIDGE(SGX_NOCONVENTION, do_execlp, ());
void SGX_UBRIDGE(SGX_NOCONVENTION, printf_string, (char* s));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_create, (pthread_t* new_thread, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, unsigned long int job_id, sgx_enclave_id_t eid));
pthread_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_self, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_join, (pthread_t pt, void** thread_result));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_detach, (pthread_t pt));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_equal, (pthread_t pt1, pthread_t pt2));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_exit, (void* retval));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_cancel, (pthread_t th));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_testcancel, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_attr_init, (SGX_WRAPPER_PTHREAD_ATTRIBUTE* __attr));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_attr_destroy, (SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_attr_getdetachstate, (SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int* __detachstate));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_attr_setdetachstate, (SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int __detachstate));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_attr_getguardsize, (SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t* __guardsize));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_attr_setguardsize, (SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t __guardsize));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_attr_getschedpolicy, (SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int* __policy));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_attr_setschedpolicy, (SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int __policy));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_attr_getstacksize, (SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t* __stacksize));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_attr_setstacksize, (SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t __stacksize));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_setspecific, (pthread_key_t key, const void* value));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_getspecific, (pthread_key_t key));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_key_create, (pthread_key_t* key, void* destructor));
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_time, (time_t* t));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gettimeofday, (void* tv, int tv_size, void* tz, int tz_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gettimeofday2, (void* tv, int tv_size));
clock_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clock, ());
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gmtime_r, (const time_t* timer, struct tm* tp));
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_localtime_r, (const time_t* timer, struct tm* tp));
time_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mktime, (struct tm* tp));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getitimer, (int which, struct itimerval* curr_value));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setitimer, (int which, const struct itimerval* new_value, struct itimerval* old_value));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_nanosleep, (const struct timespec* req, struct timespec* rem));
int SGX_UBRIDGE(SGX_NOCONVENTION, wrapper_getopt, (int argc, char** argv, const char* optstring));
void SGX_UBRIDGE(SGX_NOCONVENTION, set_optind, (int oi));
void SGX_UBRIDGE(SGX_NOCONVENTION, set_opterr, (int oe));
void SGX_UBRIDGE(SGX_NOCONVENTION, set_optopt, (int oo));
void SGX_UBRIDGE(SGX_NOCONVENTION, set_optreset, (int ors));
char* SGX_UBRIDGE(SGX_NOCONVENTION, get_optarg, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_optind, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_opterr, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_optopt, ());
struct passwd* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpwuid, (uid_t uid));
struct passwd* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpwnam, (const char* name));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpwnam_r, (const char* name, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result));
struct group* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getgrgid, (gid_t gid));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_initgroups, (const char* user, gid_t group));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_uname, (struct utsname* name));
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getenv, (const char* name));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_putenv, (char* string));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clearenv, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setenv, (const char* name, const char* value, int replace));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_unsetenv, (const char* name));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mkstemp, (char* temp));
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mkdtemp, (char* temp));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open1, (const char* pathname, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open2, (const char* pathname, int flags, unsigned int mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_creat, (const char* pathname, unsigned int mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_openat1, (int dirfd, const char* pathname, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_openat2, (int dirfd, const char* pathname, int flags, unsigned int mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl1, (int fd, int cmd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl2, (int fd, int cmd, long int arg));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl3, (int fd, int cmd, void* arg, int flock_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gethostname, (char* name, size_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sethostname, (const char* name, size_t len));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lseek, (int fd, off_t offset, int whence));
int SGX_UBRIDGE(SGX_NOCONVENTION, get_buff_addr, (size_t arr[2]));
off_t SGX_UBRIDGE(SGX_FASTCALL, ocall_fast_write, (int fd, size_t count));
off_t SGX_UBRIDGE(SGX_FASTCALL, ocall_fast_read, (int fd, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read, (int fd, void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write, (int fd, const void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read1, (int fd, void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write1, (int fd, const void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read2, (int fd, void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write2, (int fd, const void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read3, (int fd, void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write3, (int fd, const void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read4, (int fd, void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write4, (int fd, const void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read5, (int fd, void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write5, (int fd, const void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read6, (int fd, void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write6, (int fd, const void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read7, (int fd, void* buf, size_t count));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write7, (int fd, const void* buf, size_t count));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int fd));
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpid, ());
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getppid, ());
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pread, (int fd, void* buf, size_t nbytes, off_t offset));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pwrite, (int fd, const void* buf, size_t n, off_t offset));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pipe, (int pipedes[2]));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pipe2, (int pipedes[2], int flag));
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sleep, (unsigned int seconds));
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_usleep, (unsigned int seconds));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_chown, (const char* file, uid_t owner, gid_t group));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fchown, (int fd, uid_t owner, gid_t group));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lchown, (const char* file, uid_t owner, gid_t group));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_chdir, (const char* path));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fchdir, (int fd));
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_current_dir_name, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_dup, (int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_dup2, (int fd, int fd2));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_dup3, (int fd, int fd2, int flags));
uid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getuid, ());
uid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_geteuid, ());
gid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getgid, ());
gid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getegid, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpagesize, ());
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getcwd, (char* buf, size_t size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_unlink, (const char* name));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_rmdir, (const char* name));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall__exit, (int stat, int eid));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_exit, (int stat, int eid));
long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sysconf, (int name));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setgid, (gid_t gid));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setuid, (uid_t uid));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_execvp, (const char* file, const char** argv));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftruncate, (int fd, off_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free, (void* p));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_geterrno, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fsync, (int fd));
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_alarm, (unsigned int seconds));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_copy_arg, (void* buff, int buff_size, char** argv, int index));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mknod, (const char* pathname, mode_t mode, dev_t dev));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_isatty, (int fd));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_malloc, (int n));
SGX_WRAPPER_FILE SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fopen, (const char* filename, const char* mode));
SGX_WRAPPER_FILE SGX_UBRIDGE(SGX_NOCONVENTION, ocall_popen, (const char* command, const char* type));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fclose, (SGX_WRAPPER_FILE FILESTREAM));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pclose, (SGX_WRAPPER_FILE stream));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fputs, (const char* str, SGX_WRAPPER_FILE FILESTREAM));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_feof, (SGX_WRAPPER_FILE FILESTREAM));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_rewind, (SGX_WRAPPER_FILE FILESTREAM));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fflush, (SGX_WRAPPER_FILE FILESTREAM));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fread, (void* ptr, size_t size, size_t nmemb, SGX_WRAPPER_FILE FILESTREAM));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fwrite, (const void* ptr, size_t size, size_t count, SGX_WRAPPER_FILE FILESTREAM));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_vfprintf, (SGX_WRAPPER_FILE FILESTREAM, const char* format, void* val));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_vprintf, (const char* format, void* val));
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fgets, (char* str, int num, SGX_WRAPPER_FILE FILESTREAM));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fgetc, (SGX_WRAPPER_FILE FILESTREAM));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ungetc, (int c, SGX_WRAPPER_FILE FILESTREAM));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getc_unlocked, (SGX_WRAPPER_FILE FILESTREAM));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_flockfile, (SGX_WRAPPER_FILE filehandle));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_funlockfile, (SGX_WRAPPER_FILE filehandle));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_vsprintf, (char* string, const char* format, void* val));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_vasprintf, (char** string, const char* format, void* val));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftello, (SGX_WRAPPER_FILE FILESTREAM));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fseeko, (SGX_WRAPPER_FILE FILESTREAM, off_t offset, int whence));
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftell, (SGX_WRAPPER_FILE FILESTREAM));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fseek, (SGX_WRAPPER_FILE FILESTREAM, off_t offset, int whence));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ferror, (SGX_WRAPPER_FILE FILESTREAM));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_perror, (const char* s));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getc, (SGX_WRAPPER_FILE FILESTREAM));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_vfscanf, (SGX_WRAPPER_FILE s, const char* format, void* val));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_vscanf, (const char* format, void* val));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_vsscanf, (const char* s, const char* format, void* val));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_putchar, (int c));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_putc, (int c, SGX_WRAPPER_FILE stream));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_puts, (const char* s));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fputc, (int c, SGX_WRAPPER_FILE stream));
SGX_WRAPPER_FILE SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fdopen, (int fd, const char* modes));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fileno, (SGX_WRAPPER_FILE stream));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_rename, (const char* _old, const char* _new));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_remove, (const char* pathname));
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_tempnam, (const char* dir, const char* pfx));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* s));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fprint_string, (SGX_WRAPPER_FILE stream, const char* s));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_eventfd, (unsigned int initval, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_socket, (int domain, int type, int protocol));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_accept, (int sockfd, struct sockaddr* addr, socklen_t* addrlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_connect, (int socket, const struct sockaddr* address, socklen_t address_len));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sendto, (int sockfd, const void* buf, size_t len, int flags, const void* dest_addr, unsigned int addrlen));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recv, (int fd, void* buf, size_t len, int flags));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send, (int fd, const void* buf, size_t len, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_socketpair, (int domain, int type, int protocol, int sv[2]));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setsockopt, (int sockfd, int level, int optname, const void* optval, unsigned int optlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getsockopt, (int sockfd, int level, int optname, void* optval, unsigned int* optlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_shutdown, (int fd, int how));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_bind, (int fd, const struct sockaddr* addr, socklen_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_bind_untrusted, (int fd, const struct sockaddr* addr, socklen_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_listen, (int fd, int n));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getsockname, (int fd, struct sockaddr* addr, socklen_t* len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpeername, (int fd, struct sockaddr* addr, socklen_t* len));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recvfrom, (int fd, void* untrusted_buf, size_t n, int flags, struct sockaddr* untrusted_addr, socklen_t* addr_len));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sendmsg, (int fd, const struct msghdr* message, int flags));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recvmsg, (int fd, struct msghdr* message, int flags));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_freeaddrinfo, (void* res));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getaddrinfo, (const char* node, const char* service, const void* hints, void** res));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getaddrinfo1, (const char* node, const char* service, const void* hints, void* res));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sethostent, (int stay_open));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_endhostent, ());
struct hostent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gethostent, ());
struct hostent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gethostbyaddr, (const void* addr, socklen_t len, int type));
struct hostent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gethostbyname, (const char* name));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setnetent, (int stay_open));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_endnetent, ());
struct netent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getnetent, ());
struct netent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getnetbyaddr, (uint32_t net, int type));
struct netent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getnetbyname, (const char* name));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setservent, (int stay_open));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_endservent, ());
struct servent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getservent, ());
struct servent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getservbyname, (const char* name, const char* proto));
struct servent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getservbyport, (int port, const char* proto));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setprotoent, (int stay_open));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_endprotoent, ());
struct protoent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getprotoent, ());
struct protoent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getprotobyname, (const char* name));
struct protoent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getprotobynumber, (int proto));
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_gai_strerror, (int ecode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getnameinfo, (const struct sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags));
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ntohl, (uint32_t netlong));
uint16_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ntohs, (uint16_t netshort));
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_htonl, (uint32_t hostlong));
uint16_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_htons, (uint16_t hostshort));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ioctl, (int fd, unsigned long int request, void* arguments));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readv, (int __fd, const void* __iovec, int iovec_size, int __count));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writev, (int __fd, int iovec_id, int iovec_size, int __count));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_init_multiple_iovec_outside, (const void* __iovec, int iovec_size, int __count));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_copy_base_to_outside, (int iovec_id, int i, const void* base, int len));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_free_iovec_outside, (int iovec_id, int iovec_size, int __count));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_process_vm_readv, (pid_t __pid, const struct iovec* __lvec, unsigned long int __liovcnt, const struct iovec* __rvec, unsigned long int __riovcnt, unsigned long int __flags));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_process_vm_writev, (pid_t __pid, const struct iovec* __lvec, unsigned long int __liovcnt, const struct iovec* __rvec, unsigned long int __riovcnt, unsigned long int __flags));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mmap, (void* __addr, size_t __len, int __prot, int __flags, int __fd, __off_t __offset));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mmap64, (void* __addr, size_t __len, int __prot, int __flags, int __fd, __off64_t __offset));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_munmap, (void* __addr, size_t __len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mprotect, (void* __addr, size_t __len, int __prot));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_msync, (void* __addr, size_t __len, int __flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mlock, (const void* __addr, size_t __len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_munlock, (const void* __addr, size_t __len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mlockall, (int __flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_munlockall, ());
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mincore, (void* __start, size_t __len, unsigned char* __vec));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_shm_open, (const char* __name, int __oflag, mode_t __mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_shm_unlink, (const char* __name));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_poll, (struct pollfd* __fds, nfds_t __nfds, int __timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_create, (int __size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_create1, (int __flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_ctl, (int __epfd, int __op, int __fd, void* __event, int event_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_wait, (int __epfd, void* __events, int event_size, int __maxevents, int __timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_wait1, (int __epfd, void* __events, int event_size, int __maxevents, int __timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_wait2, (int __epfd, void* __events, int event_size, int __maxevents, int __timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_wait3, (int __epfd, void* __events, int event_size, int __maxevents, int __timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_wait4, (int __epfd, void* __events, int event_size, int __maxevents, int __timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_wait5, (int __epfd, void* __events, int event_size, int __maxevents, int __timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_wait6, (int __epfd, void* __events, int event_size, int __maxevents, int __timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_wait7, (int __epfd, void* __events, int event_size, int __maxevents, int __timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_pwait, (int __epfd, void* __events, int event_size, int __maxevents, int __timeout, void* __ss, int sigset_size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_select, (int __nfds, fd_set* __readfds, fd_set* __writefds, fd_set* __exceptfds, void* __timeout, int tvsize));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sendfile, (int out_fd, int in_fd, off_t* offset, size_t count));
__pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_waitpid, (__pid_t __pid, int* __stat_loc, int __options));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_waitid, (idtype_t __idtype, __id_t __id, siginfo_t* __infop, int __options));
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_wait, (int* wstatus));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_stat, (const char* path, struct stat* buf));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fstat, (int fd, struct stat* buf));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lstat, (const char* path, struct stat* buf));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_chmod, (const char* file, mode_t mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fchmod, (int fd, mode_t mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fchmodat, (int fd, const char* file, mode_t mode, int flag));
mode_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_umask, (mode_t mask));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mkdir, (const char* path, mode_t mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mkdirat, (int fd, const char* path, mode_t mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mkfifo, (const char* path, mode_t mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mkfifoat, (int fd, const char* path, mode_t mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_utime, (const char* filename, const struct utimbuf* times));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_opendir, (const char* name));
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fdopendir, (int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closedir, (void* dirp));
struct dirent* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readdir, (void* dirp));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readdir_r, (void* dirp, struct dirent* entry, struct dirent** result));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_rewinddir, (void* dirp));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_seekdir, (void* dirp, long int pos));
long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_telldir, (void* dirp));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_dirfd, (void* dirp));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_alphasort, (const struct dirent** e1, const struct dirent** e2));
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getdirentries, (int fd, char* buf, size_t nbytes, off_t* basep));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_versionsort, (const struct dirent** e1, const struct dirent** e2));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_prlimit, (__pid_t pid, enum __rlimit_resource resource, const struct rlimit* new_limit, struct rlimit* old_limit));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getrlimit, (int resource, struct rlimit* rlim));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setrlimit, (int resource, const struct rlimit* rlim));
in_addr_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inet_addr, (const char* cp));
in_addr_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inet_lnaof, (struct in_addr in));
struct in_addr SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inet_makeaddr, (in_addr_t net, in_addr_t host));
in_addr_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inet_netof, (struct in_addr in));
in_addr_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inet_network, (const char* cp));
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inet_ntoa, (struct in_addr in));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inet_pton, (int af, const char* cp, void* buf));
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_inet_ntop, (int af, const void* cp, char* buf, socklen_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sysctl, (int* name, int nlen, void* oldval, size_t* oldlenp, void* newval, size_t newlen));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sigemptyset, (sigset_t* set));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sigfillset, (sigset_t* set));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sigaddset, (sigset_t* set, int signo));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sigdelset, (sigset_t* set, int signo));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sigismember, (const sigset_t* set, int signo));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sigsuspend, (const sigset_t* set));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sigaction, (int sig, const struct sigaction* act, struct sigaction* oact));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sigpending, (sigset_t* set));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sigwait, (const sigset_t* set, int* sig));
__sighandler_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_signal_generic, (int __sig, __sighandler_t __handler));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sigaction_generic, (int sig, struct sigaction* act, struct sigaction* oact));
__sighandler_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_signal, (int __sig, __sighandler_t __handler));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_raise, (int sig));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_kill, (pid_t pid, int sig));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pmap_set, (unsigned long int prognum, unsigned long int versnum, unsigned int protocol, unsigned short int port));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pmap_unset, (unsigned long int prognum, unsigned long int versnum));
unsigned short int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pmap_getport, (struct sockaddr_in* addr, unsigned long int prognum, unsigned long int versnum, unsigned int protocol));
SVCXPRT* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svcudp_create, (int __sock));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svc_run, ());
SVCXPRT* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svctcp_create, (int __sock, u_int __sendsize, u_int __recvsize));
bool_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svc_register, (SVCXPRT* __xprt, rpcprog_t __prog, rpcvers_t __vers, __dispatch_fn_t __dispatch, rpcprot_t __protocol));
bool_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svc_register_generic, (SVCXPRT* __xprt, rpcprog_t __prog, rpcvers_t __vers, __dispatch_fn_t __dispatch, rpcprot_t __protocol));
CLIENT* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clnt_create, (const char* __host, unsigned long int __prog, unsigned long int __vers, const char* __prot));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clnt_perror, (CLIENT* __clnt, const char* __msg));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clnt_pcreateerror, (const char* __msg));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_callrpc, (const char* __host, unsigned long int __prognum, unsigned long int __versnum, unsigned long int __procnum, xdrproc_t __inproc, const char* __in, xdrproc_t __outproc, char* __out));
bool_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svc_sendreply, (SVCXPRT* __xprt, xdrproc_t __xdr_results, char* __xdr_location));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svcerr_noproc, (SVCXPRT* __xprt));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svcerr_decode, (SVCXPRT* __xprt));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svcerr_systemerr, (SVCXPRT* __xprt));
bool SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clnt_call, (CLIENT* rh, unsigned long int proc, xdrproc_t xargs, caddr_t argsp, xdrproc_t xres, char* resp, struct timeval timeout));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fast_clnt_call, (unsigned long int proc));
bool_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clnt_control, (CLIENT* cl, u_int rq, char* in, int in_size));
bool_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svc_getargs, (SVCXPRT* xprt, xdrproc_t xargs, char* argsp));
bool_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_svc_freeargs, (SVCXPRT* xprt, xdrproc_t xargs, char* argsp));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getifaddrs, (struct ifaddrs** ifap));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_freeifaddrs, (struct ifaddrs* ifa));
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_if_nametoindex, (const char* ifname));
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_if_indextoname, (unsigned int ifindex, char* ifname));
struct if_nameindex* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_if_nameindex, ());
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_if_freenameindex, (struct if_nameindex* ptr));

sgx_status_t MyEnclave_ecall_execute_job(sgx_enclave_id_t eid, pthread_t pthread_self_id, unsigned long int job_id);
sgx_status_t MyEnclave_ecall_set_enclave_id(sgx_enclave_id_t eid, sgx_enclave_id_t self_eid);
sgx_status_t MyEnclave_ecall_bzip2_main(sgx_enclave_id_t eid, int* retval, int argc, char** argv);
sgx_status_t MyEnclave_ecall_generic_signal_handler(sgx_enclave_id_t eid, unsigned long int handler_id);
sgx_status_t MyEnclave_ecall_generic_rpc_dispatch_handler(sgx_enclave_id_t eid, unsigned long int handler_id, struct svc_req* rqstp, SVCXPRT* transp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
