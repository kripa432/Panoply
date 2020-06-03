#ifndef MYENCLAVE_T_H__
#define MYENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

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


void ecall_execute_job(pthread_t pthread_self_id, unsigned long int job_id);
void ecall_set_enclave_id(sgx_enclave_id_t self_eid);
int ecall_bzip2_main(int argc, char** argv);
void ecall_generic_signal_handler(unsigned long int handler_id);
void ecall_generic_rpc_dispatch_handler(unsigned long int handler_id, struct svc_req* rqstp, SVCXPRT* transp);

sgx_status_t SGX_CDECL do_execve();
sgx_status_t SGX_CDECL do_execlp();
sgx_status_t SGX_CDECL printf_string(char* s);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL ocall_pthread_create(int* retval, pthread_t* new_thread, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, unsigned long int job_id, sgx_enclave_id_t eid);
sgx_status_t SGX_CDECL ocall_pthread_self(pthread_t* retval);
sgx_status_t SGX_CDECL ocall_pthread_join(int* retval, pthread_t pt, void** thread_result);
sgx_status_t SGX_CDECL ocall_pthread_detach(int* retval, pthread_t pt);
sgx_status_t SGX_CDECL ocall_pthread_equal(int* retval, pthread_t pt1, pthread_t pt2);
sgx_status_t SGX_CDECL ocall_pthread_exit(void* retval);
sgx_status_t SGX_CDECL ocall_pthread_cancel(int* retval, pthread_t th);
sgx_status_t SGX_CDECL ocall_pthread_testcancel();
sgx_status_t SGX_CDECL ocall_pthread_attr_init(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE* __attr);
sgx_status_t SGX_CDECL ocall_pthread_attr_destroy(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr);
sgx_status_t SGX_CDECL ocall_pthread_attr_getdetachstate(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int* __detachstate);
sgx_status_t SGX_CDECL ocall_pthread_attr_setdetachstate(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int __detachstate);
sgx_status_t SGX_CDECL ocall_pthread_attr_getguardsize(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t* __guardsize);
sgx_status_t SGX_CDECL ocall_pthread_attr_setguardsize(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t __guardsize);
sgx_status_t SGX_CDECL ocall_pthread_attr_getschedpolicy(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int* __policy);
sgx_status_t SGX_CDECL ocall_pthread_attr_setschedpolicy(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int __policy);
sgx_status_t SGX_CDECL ocall_pthread_attr_getstacksize(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t* __stacksize);
sgx_status_t SGX_CDECL ocall_pthread_attr_setstacksize(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t __stacksize);
sgx_status_t SGX_CDECL ocall_pthread_setspecific(int* retval, pthread_key_t key, const void* value);
sgx_status_t SGX_CDECL ocall_pthread_getspecific(void** retval, pthread_key_t key);
sgx_status_t SGX_CDECL ocall_pthread_key_create(int* retval, pthread_key_t* key, void* destructor);
sgx_status_t SGX_CDECL ocall_time(time_t* retval, time_t* t);
sgx_status_t SGX_CDECL ocall_gettimeofday(int* retval, void* tv, int tv_size, void* tz, int tz_size);
sgx_status_t SGX_CDECL ocall_gettimeofday2(int* retval, void* tv, int tv_size);
sgx_status_t SGX_CDECL ocall_clock(clock_t* retval);
sgx_status_t SGX_CDECL ocall_gmtime_r(struct tm** retval, const time_t* timer, struct tm* tp);
sgx_status_t SGX_CDECL ocall_localtime_r(struct tm** retval, const time_t* timer, struct tm* tp);
sgx_status_t SGX_CDECL ocall_mktime(time_t* retval, struct tm* tp);
sgx_status_t SGX_CDECL ocall_getitimer(int* retval, int which, struct itimerval* curr_value);
sgx_status_t SGX_CDECL ocall_setitimer(int* retval, int which, const struct itimerval* new_value, struct itimerval* old_value);
sgx_status_t SGX_CDECL ocall_nanosleep(int* retval, const struct timespec* req, struct timespec* rem);
sgx_status_t SGX_CDECL wrapper_getopt(int* retval, int argc, char** argv, const char* optstring);
sgx_status_t SGX_CDECL set_optind(int oi);
sgx_status_t SGX_CDECL set_opterr(int oe);
sgx_status_t SGX_CDECL set_optopt(int oo);
sgx_status_t SGX_CDECL set_optreset(int ors);
sgx_status_t SGX_CDECL get_optarg(char** retval);
sgx_status_t SGX_CDECL ocall_get_optind(int* retval);
sgx_status_t SGX_CDECL ocall_get_opterr(int* retval);
sgx_status_t SGX_CDECL ocall_get_optopt(int* retval);
sgx_status_t SGX_CDECL ocall_getpwuid(struct passwd** retval, uid_t uid);
sgx_status_t SGX_CDECL ocall_getpwnam(struct passwd** retval, const char* name);
sgx_status_t SGX_CDECL ocall_getpwnam_r(int* retval, const char* name, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result);
sgx_status_t SGX_CDECL ocall_getgrgid(struct group** retval, gid_t gid);
sgx_status_t SGX_CDECL ocall_initgroups(int* retval, const char* user, gid_t group);
sgx_status_t SGX_CDECL ocall_uname(int* retval, struct utsname* name);
sgx_status_t SGX_CDECL ocall_getenv(char** retval, const char* name);
sgx_status_t SGX_CDECL ocall_putenv(int* retval, char* string);
sgx_status_t SGX_CDECL ocall_clearenv(int* retval);
sgx_status_t SGX_CDECL ocall_setenv(int* retval, const char* name, const char* value, int replace);
sgx_status_t SGX_CDECL ocall_unsetenv(int* retval, const char* name);
sgx_status_t SGX_CDECL ocall_mkstemp(int* retval, char* temp);
sgx_status_t SGX_CDECL ocall_mkdtemp(char** retval, char* temp);
sgx_status_t SGX_CDECL ocall_open1(int* retval, const char* pathname, int flags);
sgx_status_t SGX_CDECL ocall_open2(int* retval, const char* pathname, int flags, unsigned int mode);
sgx_status_t SGX_CDECL ocall_creat(int* retval, const char* pathname, unsigned int mode);
sgx_status_t SGX_CDECL ocall_openat1(int* retval, int dirfd, const char* pathname, int flags);
sgx_status_t SGX_CDECL ocall_openat2(int* retval, int dirfd, const char* pathname, int flags, unsigned int mode);
sgx_status_t SGX_CDECL ocall_fcntl1(int* retval, int fd, int cmd);
sgx_status_t SGX_CDECL ocall_fcntl2(int* retval, int fd, int cmd, long int arg);
sgx_status_t SGX_CDECL ocall_fcntl3(int* retval, int fd, int cmd, void* arg, int flock_size);
sgx_status_t SGX_CDECL ocall_gethostname(int* retval, char* name, size_t len);
sgx_status_t SGX_CDECL ocall_sethostname(int* retval, const char* name, size_t len);
sgx_status_t SGX_CDECL ocall_lseek(off_t* retval, int fd, off_t offset, int whence);
sgx_status_t SGX_CDECL get_buff_addr(int* retval, size_t arr[2]);
sgx_status_t SGX_CDECL ocall_fast_write(off_t* retval, int fd, size_t count);
sgx_status_t SGX_CDECL ocall_fast_read(off_t* retval, int fd, size_t count);
sgx_status_t SGX_CDECL ocall_read(off_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write(off_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_read1(off_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write1(off_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_read2(off_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write2(off_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_read3(off_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write3(off_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_read4(off_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write4(off_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_read5(off_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write5(off_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_read6(off_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write6(off_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_read7(off_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_write7(off_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL ocall_close(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_getpid(pid_t* retval);
sgx_status_t SGX_CDECL ocall_getppid(pid_t* retval);
sgx_status_t SGX_CDECL ocall_pread(ssize_t* retval, int fd, void* buf, size_t nbytes, off_t offset);
sgx_status_t SGX_CDECL ocall_pwrite(ssize_t* retval, int fd, const void* buf, size_t n, off_t offset);
sgx_status_t SGX_CDECL ocall_pipe(int* retval, int pipedes[2]);
sgx_status_t SGX_CDECL ocall_pipe2(int* retval, int pipedes[2], int flag);
sgx_status_t SGX_CDECL ocall_sleep(unsigned int* retval, unsigned int seconds);
sgx_status_t SGX_CDECL ocall_usleep(unsigned int* retval, unsigned int seconds);
sgx_status_t SGX_CDECL ocall_chown(int* retval, const char* file, uid_t owner, gid_t group);
sgx_status_t SGX_CDECL ocall_fchown(int* retval, int fd, uid_t owner, gid_t group);
sgx_status_t SGX_CDECL ocall_lchown(int* retval, const char* file, uid_t owner, gid_t group);
sgx_status_t SGX_CDECL ocall_chdir(int* retval, const char* path);
sgx_status_t SGX_CDECL ocall_fchdir(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_get_current_dir_name(char** retval);
sgx_status_t SGX_CDECL ocall_dup(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_dup2(int* retval, int fd, int fd2);
sgx_status_t SGX_CDECL ocall_dup3(int* retval, int fd, int fd2, int flags);
sgx_status_t SGX_CDECL ocall_getuid(uid_t* retval);
sgx_status_t SGX_CDECL ocall_geteuid(uid_t* retval);
sgx_status_t SGX_CDECL ocall_getgid(gid_t* retval);
sgx_status_t SGX_CDECL ocall_getegid(gid_t* retval);
sgx_status_t SGX_CDECL ocall_getpagesize(int* retval);
sgx_status_t SGX_CDECL ocall_getcwd(char** retval, char* buf, size_t size);
sgx_status_t SGX_CDECL ocall_unlink(int* retval, const char* name);
sgx_status_t SGX_CDECL ocall_rmdir(int* retval, const char* name);
sgx_status_t SGX_CDECL ocall__exit(int stat, int eid);
sgx_status_t SGX_CDECL ocall_exit(int stat, int eid);
sgx_status_t SGX_CDECL ocall_sysconf(long int* retval, int name);
sgx_status_t SGX_CDECL ocall_setgid(int* retval, gid_t gid);
sgx_status_t SGX_CDECL ocall_setuid(int* retval, uid_t uid);
sgx_status_t SGX_CDECL ocall_execvp(int* retval, const char* file, const char** argv);
sgx_status_t SGX_CDECL ocall_ftruncate(int* retval, int fd, off_t len);
sgx_status_t SGX_CDECL ocall_free(void* p);
sgx_status_t SGX_CDECL ocall_geterrno(int* retval);
sgx_status_t SGX_CDECL ocall_fsync(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_alarm(unsigned int* retval, unsigned int seconds);
sgx_status_t SGX_CDECL ocall_copy_arg(int* retval, void* buff, int buff_size, char** argv, int index);
sgx_status_t SGX_CDECL ocall_mknod(int* retval, const char* pathname, mode_t mode, dev_t dev);
sgx_status_t SGX_CDECL ocall_isatty(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_malloc(void** retval, int n);
sgx_status_t SGX_CDECL ocall_fopen(SGX_WRAPPER_FILE* retval, const char* filename, const char* mode);
sgx_status_t SGX_CDECL ocall_popen(SGX_WRAPPER_FILE* retval, const char* command, const char* type);
sgx_status_t SGX_CDECL ocall_fclose(int* retval, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_pclose(int* retval, SGX_WRAPPER_FILE stream);
sgx_status_t SGX_CDECL ocall_fputs(int* retval, const char* str, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_feof(int* retval, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_rewind(SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_fflush(int* retval, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_fread(size_t* retval, void* ptr, size_t size, size_t nmemb, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_fwrite(size_t* retval, const void* ptr, size_t size, size_t count, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_vfprintf(int* retval, SGX_WRAPPER_FILE FILESTREAM, const char* format, void* val);
sgx_status_t SGX_CDECL ocall_vprintf(int* retval, const char* format, void* val);
sgx_status_t SGX_CDECL ocall_fgets(char** retval, char* str, int num, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_fgetc(int* retval, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_ungetc(int* retval, int c, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_getc_unlocked(int* retval, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_flockfile(SGX_WRAPPER_FILE filehandle);
sgx_status_t SGX_CDECL ocall_funlockfile(SGX_WRAPPER_FILE filehandle);
sgx_status_t SGX_CDECL ocall_vsprintf(int* retval, char* string, const char* format, void* val);
sgx_status_t SGX_CDECL ocall_vasprintf(int* retval, char** string, const char* format, void* val);
sgx_status_t SGX_CDECL ocall_ftello(off_t* retval, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_fseeko(int* retval, SGX_WRAPPER_FILE FILESTREAM, off_t offset, int whence);
sgx_status_t SGX_CDECL ocall_ftell(off_t* retval, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_fseek(int* retval, SGX_WRAPPER_FILE FILESTREAM, off_t offset, int whence);
sgx_status_t SGX_CDECL ocall_ferror(int* retval, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_perror(const char* s);
sgx_status_t SGX_CDECL ocall_getc(int* retval, SGX_WRAPPER_FILE FILESTREAM);
sgx_status_t SGX_CDECL ocall_vfscanf(int* retval, SGX_WRAPPER_FILE s, const char* format, void* val);
sgx_status_t SGX_CDECL ocall_vscanf(int* retval, const char* format, void* val);
sgx_status_t SGX_CDECL ocall_vsscanf(int* retval, const char* s, const char* format, void* val);
sgx_status_t SGX_CDECL ocall_putchar(int* retval, int c);
sgx_status_t SGX_CDECL ocall_putc(int* retval, int c, SGX_WRAPPER_FILE stream);
sgx_status_t SGX_CDECL ocall_puts(int* retval, const char* s);
sgx_status_t SGX_CDECL ocall_fputc(int* retval, int c, SGX_WRAPPER_FILE stream);
sgx_status_t SGX_CDECL ocall_fdopen(SGX_WRAPPER_FILE* retval, int fd, const char* modes);
sgx_status_t SGX_CDECL ocall_fileno(int* retval, SGX_WRAPPER_FILE stream);
sgx_status_t SGX_CDECL ocall_rename(int* retval, const char* _old, const char* _new);
sgx_status_t SGX_CDECL ocall_remove(int* retval, const char* pathname);
sgx_status_t SGX_CDECL ocall_tempnam(char** retval, const char* dir, const char* pfx);
sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* s);
sgx_status_t SGX_CDECL ocall_fprint_string(int* retval, SGX_WRAPPER_FILE stream, const char* s);
sgx_status_t SGX_CDECL ocall_eventfd(int* retval, unsigned int initval, int flags);
sgx_status_t SGX_CDECL ocall_socket(int* retval, int domain, int type, int protocol);
sgx_status_t SGX_CDECL ocall_accept(int* retval, int sockfd, struct sockaddr* addr, socklen_t* addrlen);
sgx_status_t SGX_CDECL ocall_connect(int* retval, int socket, const struct sockaddr* address, socklen_t address_len);
sgx_status_t SGX_CDECL ocall_sendto(ssize_t* retval, int sockfd, const void* buf, size_t len, int flags, const void* dest_addr, unsigned int addrlen);
sgx_status_t SGX_CDECL ocall_recv(ssize_t* retval, int fd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_send(ssize_t* retval, int fd, const void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_socketpair(int* retval, int domain, int type, int protocol, int sv[2]);
sgx_status_t SGX_CDECL ocall_setsockopt(int* retval, int sockfd, int level, int optname, const void* optval, unsigned int optlen);
sgx_status_t SGX_CDECL ocall_getsockopt(int* retval, int sockfd, int level, int optname, void* optval, unsigned int* optlen);
sgx_status_t SGX_CDECL ocall_shutdown(int* retval, int fd, int how);
sgx_status_t SGX_CDECL ocall_bind(int* retval, int fd, const struct sockaddr* addr, socklen_t len);
sgx_status_t SGX_CDECL ocall_bind_untrusted(int* retval, int fd, const struct sockaddr* addr, socklen_t len);
sgx_status_t SGX_CDECL ocall_listen(int* retval, int fd, int n);
sgx_status_t SGX_CDECL ocall_getsockname(int* retval, int fd, struct sockaddr* addr, socklen_t* len);
sgx_status_t SGX_CDECL ocall_getpeername(int* retval, int fd, struct sockaddr* addr, socklen_t* len);
sgx_status_t SGX_CDECL ocall_recvfrom(ssize_t* retval, int fd, void* untrusted_buf, size_t n, int flags, struct sockaddr* untrusted_addr, socklen_t* addr_len);
sgx_status_t SGX_CDECL ocall_sendmsg(ssize_t* retval, int fd, const struct msghdr* message, int flags);
sgx_status_t SGX_CDECL ocall_recvmsg(ssize_t* retval, int fd, struct msghdr* message, int flags);
sgx_status_t SGX_CDECL ocall_freeaddrinfo(void* res);
sgx_status_t SGX_CDECL ocall_getaddrinfo(int* retval, const char* node, const char* service, const void* hints, void** res);
sgx_status_t SGX_CDECL ocall_getaddrinfo1(int* retval, const char* node, const char* service, const void* hints, void* res);
sgx_status_t SGX_CDECL ocall_sethostent(int stay_open);
sgx_status_t SGX_CDECL ocall_endhostent();
sgx_status_t SGX_CDECL ocall_gethostent(struct hostent** retval);
sgx_status_t SGX_CDECL ocall_gethostbyaddr(struct hostent** retval, const void* addr, socklen_t len, int type);
sgx_status_t SGX_CDECL ocall_gethostbyname(struct hostent** retval, const char* name);
sgx_status_t SGX_CDECL ocall_setnetent(int stay_open);
sgx_status_t SGX_CDECL ocall_endnetent();
sgx_status_t SGX_CDECL ocall_getnetent(struct netent** retval);
sgx_status_t SGX_CDECL ocall_getnetbyaddr(struct netent** retval, uint32_t net, int type);
sgx_status_t SGX_CDECL ocall_getnetbyname(struct netent** retval, const char* name);
sgx_status_t SGX_CDECL ocall_setservent(int stay_open);
sgx_status_t SGX_CDECL ocall_endservent();
sgx_status_t SGX_CDECL ocall_getservent(struct servent** retval);
sgx_status_t SGX_CDECL ocall_getservbyname(struct servent** retval, const char* name, const char* proto);
sgx_status_t SGX_CDECL ocall_getservbyport(struct servent** retval, int port, const char* proto);
sgx_status_t SGX_CDECL ocall_setprotoent(int stay_open);
sgx_status_t SGX_CDECL ocall_endprotoent();
sgx_status_t SGX_CDECL ocall_getprotoent(struct protoent** retval);
sgx_status_t SGX_CDECL ocall_getprotobyname(struct protoent** retval, const char* name);
sgx_status_t SGX_CDECL ocall_getprotobynumber(struct protoent** retval, int proto);
sgx_status_t SGX_CDECL ocall_gai_strerror(char** retval, int ecode);
sgx_status_t SGX_CDECL ocall_getnameinfo(int* retval, const struct sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags);
sgx_status_t SGX_CDECL ocall_ntohl(uint32_t* retval, uint32_t netlong);
sgx_status_t SGX_CDECL ocall_ntohs(uint16_t* retval, uint16_t netshort);
sgx_status_t SGX_CDECL ocall_htonl(uint32_t* retval, uint32_t hostlong);
sgx_status_t SGX_CDECL ocall_htons(uint16_t* retval, uint16_t hostshort);
sgx_status_t SGX_CDECL ocall_ioctl(int* retval, int fd, unsigned long int request, void* arguments);
sgx_status_t SGX_CDECL ocall_readv(ssize_t* retval, int __fd, const void* __iovec, int iovec_size, int __count);
sgx_status_t SGX_CDECL ocall_writev(ssize_t* retval, int __fd, int iovec_id, int iovec_size, int __count);
sgx_status_t SGX_CDECL ocall_init_multiple_iovec_outside(int* retval, const void* __iovec, int iovec_size, int __count);
sgx_status_t SGX_CDECL ocall_copy_base_to_outside(int iovec_id, int i, const void* base, int len);
sgx_status_t SGX_CDECL ocall_free_iovec_outside(int iovec_id, int iovec_size, int __count);
sgx_status_t SGX_CDECL ocall_process_vm_readv(ssize_t* retval, pid_t __pid, const struct iovec* __lvec, unsigned long int __liovcnt, const struct iovec* __rvec, unsigned long int __riovcnt, unsigned long int __flags);
sgx_status_t SGX_CDECL ocall_process_vm_writev(ssize_t* retval, pid_t __pid, const struct iovec* __lvec, unsigned long int __liovcnt, const struct iovec* __rvec, unsigned long int __riovcnt, unsigned long int __flags);
sgx_status_t SGX_CDECL ocall_mmap(void** retval, void* __addr, size_t __len, int __prot, int __flags, int __fd, __off_t __offset);
sgx_status_t SGX_CDECL ocall_mmap64(void** retval, void* __addr, size_t __len, int __prot, int __flags, int __fd, __off64_t __offset);
sgx_status_t SGX_CDECL ocall_munmap(int* retval, void* __addr, size_t __len);
sgx_status_t SGX_CDECL ocall_mprotect(int* retval, void* __addr, size_t __len, int __prot);
sgx_status_t SGX_CDECL ocall_msync(int* retval, void* __addr, size_t __len, int __flags);
sgx_status_t SGX_CDECL ocall_mlock(int* retval, const void* __addr, size_t __len);
sgx_status_t SGX_CDECL ocall_munlock(int* retval, const void* __addr, size_t __len);
sgx_status_t SGX_CDECL ocall_mlockall(int* retval, int __flags);
sgx_status_t SGX_CDECL ocall_munlockall(int* retval);
sgx_status_t SGX_CDECL ocall_mincore(int* retval, void* __start, size_t __len, unsigned char* __vec);
sgx_status_t SGX_CDECL ocall_shm_open(int* retval, const char* __name, int __oflag, mode_t __mode);
sgx_status_t SGX_CDECL ocall_shm_unlink(int* retval, const char* __name);
sgx_status_t SGX_CDECL ocall_poll(int* retval, struct pollfd* __fds, nfds_t __nfds, int __timeout);
sgx_status_t SGX_CDECL ocall_epoll_create(int* retval, int __size);
sgx_status_t SGX_CDECL ocall_epoll_create1(int* retval, int __flags);
sgx_status_t SGX_CDECL ocall_epoll_ctl(int* retval, int __epfd, int __op, int __fd, void* __event, int event_size);
sgx_status_t SGX_CDECL ocall_epoll_wait(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout);
sgx_status_t SGX_CDECL ocall_epoll_wait1(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout);
sgx_status_t SGX_CDECL ocall_epoll_wait2(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout);
sgx_status_t SGX_CDECL ocall_epoll_wait3(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout);
sgx_status_t SGX_CDECL ocall_epoll_wait4(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout);
sgx_status_t SGX_CDECL ocall_epoll_wait5(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout);
sgx_status_t SGX_CDECL ocall_epoll_wait6(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout);
sgx_status_t SGX_CDECL ocall_epoll_wait7(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout);
sgx_status_t SGX_CDECL ocall_epoll_pwait(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout, void* __ss, int sigset_size);
sgx_status_t SGX_CDECL ocall_select(int* retval, int __nfds, fd_set* __readfds, fd_set* __writefds, fd_set* __exceptfds, void* __timeout, int tvsize);
sgx_status_t SGX_CDECL ocall_sendfile(ssize_t* retval, int out_fd, int in_fd, off_t* offset, size_t count);
sgx_status_t SGX_CDECL ocall_waitpid(__pid_t* retval, __pid_t __pid, int* __stat_loc, int __options);
sgx_status_t SGX_CDECL ocall_waitid(int* retval, idtype_t __idtype, __id_t __id, siginfo_t* __infop, int __options);
sgx_status_t SGX_CDECL ocall_wait(pid_t* retval, int* wstatus);
sgx_status_t SGX_CDECL ocall_stat(int* retval, const char* path, struct stat* buf);
sgx_status_t SGX_CDECL ocall_fstat(int* retval, int fd, struct stat* buf);
sgx_status_t SGX_CDECL ocall_lstat(int* retval, const char* path, struct stat* buf);
sgx_status_t SGX_CDECL ocall_chmod(int* retval, const char* file, mode_t mode);
sgx_status_t SGX_CDECL ocall_fchmod(int* retval, int fd, mode_t mode);
sgx_status_t SGX_CDECL ocall_fchmodat(int* retval, int fd, const char* file, mode_t mode, int flag);
sgx_status_t SGX_CDECL ocall_umask(mode_t* retval, mode_t mask);
sgx_status_t SGX_CDECL ocall_mkdir(int* retval, const char* path, mode_t mode);
sgx_status_t SGX_CDECL ocall_mkdirat(int* retval, int fd, const char* path, mode_t mode);
sgx_status_t SGX_CDECL ocall_mkfifo(int* retval, const char* path, mode_t mode);
sgx_status_t SGX_CDECL ocall_mkfifoat(int* retval, int fd, const char* path, mode_t mode);
sgx_status_t SGX_CDECL ocall_utime(int* retval, const char* filename, const struct utimbuf* times);
sgx_status_t SGX_CDECL ocall_opendir(void** retval, const char* name);
sgx_status_t SGX_CDECL ocall_fdopendir(void** retval, int fd);
sgx_status_t SGX_CDECL ocall_closedir(int* retval, void* dirp);
sgx_status_t SGX_CDECL ocall_readdir(struct dirent** retval, void* dirp);
sgx_status_t SGX_CDECL ocall_readdir_r(int* retval, void* dirp, struct dirent* entry, struct dirent** result);
sgx_status_t SGX_CDECL ocall_rewinddir(void* dirp);
sgx_status_t SGX_CDECL ocall_seekdir(void* dirp, long int pos);
sgx_status_t SGX_CDECL ocall_telldir(long int* retval, void* dirp);
sgx_status_t SGX_CDECL ocall_dirfd(int* retval, void* dirp);
sgx_status_t SGX_CDECL ocall_alphasort(int* retval, const struct dirent** e1, const struct dirent** e2);
sgx_status_t SGX_CDECL ocall_getdirentries(ssize_t* retval, int fd, char* buf, size_t nbytes, off_t* basep);
sgx_status_t SGX_CDECL ocall_versionsort(int* retval, const struct dirent** e1, const struct dirent** e2);
sgx_status_t SGX_CDECL ocall_prlimit(int* retval, __pid_t pid, enum __rlimit_resource resource, const struct rlimit* new_limit, struct rlimit* old_limit);
sgx_status_t SGX_CDECL ocall_getrlimit(int* retval, int resource, struct rlimit* rlim);
sgx_status_t SGX_CDECL ocall_setrlimit(int* retval, int resource, const struct rlimit* rlim);
sgx_status_t SGX_CDECL ocall_inet_addr(in_addr_t* retval, const char* cp);
sgx_status_t SGX_CDECL ocall_inet_lnaof(in_addr_t* retval, struct in_addr in);
sgx_status_t SGX_CDECL ocall_inet_makeaddr(struct in_addr* retval, in_addr_t net, in_addr_t host);
sgx_status_t SGX_CDECL ocall_inet_netof(in_addr_t* retval, struct in_addr in);
sgx_status_t SGX_CDECL ocall_inet_network(in_addr_t* retval, const char* cp);
sgx_status_t SGX_CDECL ocall_inet_ntoa(char** retval, struct in_addr in);
sgx_status_t SGX_CDECL ocall_inet_pton(int* retval, int af, const char* cp, void* buf);
sgx_status_t SGX_CDECL ocall_inet_ntop(char** retval, int af, const void* cp, char* buf, socklen_t len);
sgx_status_t SGX_CDECL ocall_sysctl(int* retval, int* name, int nlen, void* oldval, size_t* oldlenp, void* newval, size_t newlen);
sgx_status_t SGX_CDECL ocall_sigemptyset(int* retval, sigset_t* set);
sgx_status_t SGX_CDECL ocall_sigfillset(int* retval, sigset_t* set);
sgx_status_t SGX_CDECL ocall_sigaddset(int* retval, sigset_t* set, int signo);
sgx_status_t SGX_CDECL ocall_sigdelset(int* retval, sigset_t* set, int signo);
sgx_status_t SGX_CDECL ocall_sigismember(int* retval, const sigset_t* set, int signo);
sgx_status_t SGX_CDECL ocall_sigsuspend(int* retval, const sigset_t* set);
sgx_status_t SGX_CDECL ocall_sigaction(int* retval, int sig, const struct sigaction* act, struct sigaction* oact);
sgx_status_t SGX_CDECL ocall_sigpending(int* retval, sigset_t* set);
sgx_status_t SGX_CDECL ocall_sigwait(int* retval, const sigset_t* set, int* sig);
sgx_status_t SGX_CDECL ocall_signal_generic(__sighandler_t* retval, int __sig, __sighandler_t __handler);
sgx_status_t SGX_CDECL ocall_sigaction_generic(int* retval, int sig, struct sigaction* act, struct sigaction* oact);
sgx_status_t SGX_CDECL ocall_signal(__sighandler_t* retval, int __sig, __sighandler_t __handler);
sgx_status_t SGX_CDECL ocall_raise(int* retval, int sig);
sgx_status_t SGX_CDECL ocall_kill(int* retval, pid_t pid, int sig);
sgx_status_t SGX_CDECL ocall_pmap_set(int* retval, unsigned long int prognum, unsigned long int versnum, unsigned int protocol, unsigned short int port);
sgx_status_t SGX_CDECL ocall_pmap_unset(int* retval, unsigned long int prognum, unsigned long int versnum);
sgx_status_t SGX_CDECL ocall_pmap_getport(unsigned short int* retval, struct sockaddr_in* addr, unsigned long int prognum, unsigned long int versnum, unsigned int protocol);
sgx_status_t SGX_CDECL ocall_svcudp_create(SVCXPRT** retval, int __sock);
sgx_status_t SGX_CDECL ocall_svc_run();
sgx_status_t SGX_CDECL ocall_svctcp_create(SVCXPRT** retval, int __sock, u_int __sendsize, u_int __recvsize);
sgx_status_t SGX_CDECL ocall_svc_register(bool_t* retval, SVCXPRT* __xprt, rpcprog_t __prog, rpcvers_t __vers, __dispatch_fn_t __dispatch, rpcprot_t __protocol);
sgx_status_t SGX_CDECL ocall_svc_register_generic(bool_t* retval, SVCXPRT* __xprt, rpcprog_t __prog, rpcvers_t __vers, __dispatch_fn_t __dispatch, rpcprot_t __protocol);
sgx_status_t SGX_CDECL ocall_clnt_create(CLIENT** retval, const char* __host, unsigned long int __prog, unsigned long int __vers, const char* __prot);
sgx_status_t SGX_CDECL ocall_clnt_perror(CLIENT* __clnt, const char* __msg);
sgx_status_t SGX_CDECL ocall_clnt_pcreateerror(const char* __msg);
sgx_status_t SGX_CDECL ocall_callrpc(int* retval, const char* __host, unsigned long int __prognum, unsigned long int __versnum, unsigned long int __procnum, xdrproc_t __inproc, const char* __in, xdrproc_t __outproc, char* __out);
sgx_status_t SGX_CDECL ocall_svc_sendreply(bool_t* retval, SVCXPRT* __xprt, xdrproc_t __xdr_results, char* __xdr_location);
sgx_status_t SGX_CDECL ocall_svcerr_noproc(SVCXPRT* __xprt);
sgx_status_t SGX_CDECL ocall_svcerr_decode(SVCXPRT* __xprt);
sgx_status_t SGX_CDECL ocall_svcerr_systemerr(SVCXPRT* __xprt);
sgx_status_t SGX_CDECL ocall_clnt_call(bool* retval, CLIENT* rh, unsigned long int proc, xdrproc_t xargs, caddr_t argsp, xdrproc_t xres, char* resp, struct timeval timeout);
sgx_status_t SGX_CDECL ocall_fast_clnt_call(unsigned long int proc);
sgx_status_t SGX_CDECL ocall_clnt_control(bool_t* retval, CLIENT* cl, u_int rq, char* in, int in_size);
sgx_status_t SGX_CDECL ocall_svc_getargs(bool_t* retval, SVCXPRT* xprt, xdrproc_t xargs, char* argsp);
sgx_status_t SGX_CDECL ocall_svc_freeargs(bool_t* retval, SVCXPRT* xprt, xdrproc_t xargs, char* argsp);
sgx_status_t SGX_CDECL ocall_getifaddrs(int* retval, struct ifaddrs** ifap);
sgx_status_t SGX_CDECL ocall_freeifaddrs(struct ifaddrs* ifa);
sgx_status_t SGX_CDECL ocall_if_nametoindex(unsigned int* retval, const char* ifname);
sgx_status_t SGX_CDECL ocall_if_indextoname(char** retval, unsigned int ifindex, char* ifname);
sgx_status_t SGX_CDECL ocall_if_nameindex(struct if_nameindex** retval);
sgx_status_t SGX_CDECL ocall_if_freenameindex(struct if_nameindex* ptr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
