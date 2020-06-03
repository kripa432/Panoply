#include "MyEnclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_execute_job_t {
	pthread_t ms_pthread_self_id;
	unsigned long int ms_job_id;
} ms_ecall_execute_job_t;

typedef struct ms_ecall_set_enclave_id_t {
	sgx_enclave_id_t ms_self_eid;
} ms_ecall_set_enclave_id_t;

typedef struct ms_ecall_bzip2_main_t {
	int ms_retval;
	int ms_argc;
	char** ms_argv;
} ms_ecall_bzip2_main_t;

typedef struct ms_ecall_generic_signal_handler_t {
	unsigned long int ms_handler_id;
} ms_ecall_generic_signal_handler_t;

typedef struct ms_ecall_generic_rpc_dispatch_handler_t {
	unsigned long int ms_handler_id;
	struct svc_req* ms_rqstp;
	SVCXPRT* ms_transp;
} ms_ecall_generic_rpc_dispatch_handler_t;



typedef struct ms_printf_string_t {
	char* ms_s;
} ms_printf_string_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_ocall_pthread_create_t {
	int ms_retval;
	pthread_t* ms_new_thread;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE ms___attr;
	unsigned long int ms_job_id;
	sgx_enclave_id_t ms_eid;
} ms_ocall_pthread_create_t;

typedef struct ms_ocall_pthread_self_t {
	pthread_t ms_retval;
} ms_ocall_pthread_self_t;

typedef struct ms_ocall_pthread_join_t {
	int ms_retval;
	pthread_t ms_pt;
	void** ms_thread_result;
} ms_ocall_pthread_join_t;

typedef struct ms_ocall_pthread_detach_t {
	int ms_retval;
	pthread_t ms_pt;
} ms_ocall_pthread_detach_t;

typedef struct ms_ocall_pthread_equal_t {
	int ms_retval;
	pthread_t ms_pt1;
	pthread_t ms_pt2;
} ms_ocall_pthread_equal_t;

typedef struct ms_ocall_pthread_exit_t {
	void* ms_retval;
} ms_ocall_pthread_exit_t;

typedef struct ms_ocall_pthread_cancel_t {
	int ms_retval;
	pthread_t ms_th;
} ms_ocall_pthread_cancel_t;


typedef struct ms_ocall_pthread_attr_init_t {
	int ms_retval;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE* ms___attr;
} ms_ocall_pthread_attr_init_t;

typedef struct ms_ocall_pthread_attr_destroy_t {
	int ms_retval;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE ms___attr;
} ms_ocall_pthread_attr_destroy_t;

typedef struct ms_ocall_pthread_attr_getdetachstate_t {
	int ms_retval;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE ms___attr;
	int* ms___detachstate;
} ms_ocall_pthread_attr_getdetachstate_t;

typedef struct ms_ocall_pthread_attr_setdetachstate_t {
	int ms_retval;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE ms___attr;
	int ms___detachstate;
} ms_ocall_pthread_attr_setdetachstate_t;

typedef struct ms_ocall_pthread_attr_getguardsize_t {
	int ms_retval;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE ms___attr;
	size_t* ms___guardsize;
} ms_ocall_pthread_attr_getguardsize_t;

typedef struct ms_ocall_pthread_attr_setguardsize_t {
	int ms_retval;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE ms___attr;
	size_t ms___guardsize;
} ms_ocall_pthread_attr_setguardsize_t;

typedef struct ms_ocall_pthread_attr_getschedpolicy_t {
	int ms_retval;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE ms___attr;
	int* ms___policy;
} ms_ocall_pthread_attr_getschedpolicy_t;

typedef struct ms_ocall_pthread_attr_setschedpolicy_t {
	int ms_retval;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE ms___attr;
	int ms___policy;
} ms_ocall_pthread_attr_setschedpolicy_t;

typedef struct ms_ocall_pthread_attr_getstacksize_t {
	int ms_retval;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE ms___attr;
	size_t* ms___stacksize;
} ms_ocall_pthread_attr_getstacksize_t;

typedef struct ms_ocall_pthread_attr_setstacksize_t {
	int ms_retval;
	SGX_WRAPPER_PTHREAD_ATTRIBUTE ms___attr;
	size_t ms___stacksize;
} ms_ocall_pthread_attr_setstacksize_t;

typedef struct ms_ocall_pthread_setspecific_t {
	int ms_retval;
	pthread_key_t ms_key;
	void* ms_value;
} ms_ocall_pthread_setspecific_t;

typedef struct ms_ocall_pthread_getspecific_t {
	void* ms_retval;
	pthread_key_t ms_key;
} ms_ocall_pthread_getspecific_t;

typedef struct ms_ocall_pthread_key_create_t {
	int ms_retval;
	pthread_key_t* ms_key;
	void* ms_destructor;
} ms_ocall_pthread_key_create_t;

typedef struct ms_ocall_time_t {
	time_t ms_retval;
	time_t* ms_t;
} ms_ocall_time_t;

typedef struct ms_ocall_gettimeofday_t {
	int ms_retval;
	void* ms_tv;
	int ms_tv_size;
	void* ms_tz;
	int ms_tz_size;
} ms_ocall_gettimeofday_t;

typedef struct ms_ocall_gettimeofday2_t {
	int ms_retval;
	void* ms_tv;
	int ms_tv_size;
} ms_ocall_gettimeofday2_t;

typedef struct ms_ocall_clock_t {
	clock_t ms_retval;
} ms_ocall_clock_t;

typedef struct ms_ocall_gmtime_r_t {
	struct tm* ms_retval;
	time_t* ms_timer;
	struct tm* ms_tp;
} ms_ocall_gmtime_r_t;

typedef struct ms_ocall_localtime_r_t {
	struct tm* ms_retval;
	time_t* ms_timer;
	struct tm* ms_tp;
} ms_ocall_localtime_r_t;

typedef struct ms_ocall_mktime_t {
	time_t ms_retval;
	struct tm* ms_tp;
} ms_ocall_mktime_t;

typedef struct ms_ocall_getitimer_t {
	int ms_retval;
	int ms_which;
	struct itimerval* ms_curr_value;
} ms_ocall_getitimer_t;

typedef struct ms_ocall_setitimer_t {
	int ms_retval;
	int ms_which;
	struct itimerval* ms_new_value;
	struct itimerval* ms_old_value;
} ms_ocall_setitimer_t;

typedef struct ms_ocall_nanosleep_t {
	int ms_retval;
	struct timespec* ms_req;
	struct timespec* ms_rem;
} ms_ocall_nanosleep_t;

typedef struct ms_wrapper_getopt_t {
	int ms_retval;
	int ms_argc;
	char** ms_argv;
	char* ms_optstring;
} ms_wrapper_getopt_t;

typedef struct ms_set_optind_t {
	int ms_oi;
} ms_set_optind_t;

typedef struct ms_set_opterr_t {
	int ms_oe;
} ms_set_opterr_t;

typedef struct ms_set_optopt_t {
	int ms_oo;
} ms_set_optopt_t;

typedef struct ms_set_optreset_t {
	int ms_ors;
} ms_set_optreset_t;

typedef struct ms_get_optarg_t {
	char* ms_retval;
} ms_get_optarg_t;

typedef struct ms_ocall_get_optind_t {
	int ms_retval;
} ms_ocall_get_optind_t;

typedef struct ms_ocall_get_opterr_t {
	int ms_retval;
} ms_ocall_get_opterr_t;

typedef struct ms_ocall_get_optopt_t {
	int ms_retval;
} ms_ocall_get_optopt_t;

typedef struct ms_ocall_getpwuid_t {
	struct passwd* ms_retval;
	uid_t ms_uid;
} ms_ocall_getpwuid_t;

typedef struct ms_ocall_getpwnam_t {
	struct passwd* ms_retval;
	char* ms_name;
} ms_ocall_getpwnam_t;

typedef struct ms_ocall_getpwnam_r_t {
	int ms_retval;
	char* ms_name;
	struct passwd* ms_pwd;
	char* ms_buf;
	size_t ms_buflen;
	struct passwd** ms_result;
} ms_ocall_getpwnam_r_t;

typedef struct ms_ocall_getgrgid_t {
	struct group* ms_retval;
	gid_t ms_gid;
} ms_ocall_getgrgid_t;

typedef struct ms_ocall_initgroups_t {
	int ms_retval;
	char* ms_user;
	gid_t ms_group;
} ms_ocall_initgroups_t;

typedef struct ms_ocall_uname_t {
	int ms_retval;
	struct utsname* ms_name;
} ms_ocall_uname_t;

typedef struct ms_ocall_getenv_t {
	char* ms_retval;
	char* ms_name;
} ms_ocall_getenv_t;

typedef struct ms_ocall_putenv_t {
	int ms_retval;
	char* ms_string;
} ms_ocall_putenv_t;

typedef struct ms_ocall_clearenv_t {
	int ms_retval;
} ms_ocall_clearenv_t;

typedef struct ms_ocall_setenv_t {
	int ms_retval;
	char* ms_name;
	char* ms_value;
	int ms_replace;
} ms_ocall_setenv_t;

typedef struct ms_ocall_unsetenv_t {
	int ms_retval;
	char* ms_name;
} ms_ocall_unsetenv_t;

typedef struct ms_ocall_mkstemp_t {
	int ms_retval;
	char* ms_temp;
} ms_ocall_mkstemp_t;

typedef struct ms_ocall_mkdtemp_t {
	char* ms_retval;
	char* ms_temp;
} ms_ocall_mkdtemp_t;

typedef struct ms_ocall_open1_t {
	int ms_retval;
	char* ms_pathname;
	int ms_flags;
} ms_ocall_open1_t;

typedef struct ms_ocall_open2_t {
	int ms_retval;
	char* ms_pathname;
	int ms_flags;
	unsigned int ms_mode;
} ms_ocall_open2_t;

typedef struct ms_ocall_creat_t {
	int ms_retval;
	char* ms_pathname;
	unsigned int ms_mode;
} ms_ocall_creat_t;

typedef struct ms_ocall_openat1_t {
	int ms_retval;
	int ms_dirfd;
	char* ms_pathname;
	int ms_flags;
} ms_ocall_openat1_t;

typedef struct ms_ocall_openat2_t {
	int ms_retval;
	int ms_dirfd;
	char* ms_pathname;
	int ms_flags;
	unsigned int ms_mode;
} ms_ocall_openat2_t;

typedef struct ms_ocall_fcntl1_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
} ms_ocall_fcntl1_t;

typedef struct ms_ocall_fcntl2_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
	long int ms_arg;
} ms_ocall_fcntl2_t;

typedef struct ms_ocall_fcntl3_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
	void* ms_arg;
	int ms_flock_size;
} ms_ocall_fcntl3_t;

typedef struct ms_ocall_gethostname_t {
	int ms_retval;
	char* ms_name;
	size_t ms_len;
} ms_ocall_gethostname_t;

typedef struct ms_ocall_sethostname_t {
	int ms_retval;
	char* ms_name;
	size_t ms_len;
} ms_ocall_sethostname_t;

typedef struct ms_ocall_lseek_t {
	off_t ms_retval;
	int ms_fd;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_lseek_t;

typedef struct ms_get_buff_addr_t {
	int ms_retval;
	size_t* ms_arr;
} ms_get_buff_addr_t;

typedef struct ms_ocall_fast_write_t {
	off_t ms_retval;
	int ms_fd;
	size_t ms_count;
} ms_ocall_fast_write_t;

typedef struct ms_ocall_fast_read_t {
	off_t ms_retval;
	int ms_fd;
	size_t ms_count;
} ms_ocall_fast_read_t;

typedef struct ms_ocall_read_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read_t;

typedef struct ms_ocall_write_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_write_t;

typedef struct ms_ocall_read1_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read1_t;

typedef struct ms_ocall_write1_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_write1_t;

typedef struct ms_ocall_read2_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read2_t;

typedef struct ms_ocall_write2_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_write2_t;

typedef struct ms_ocall_read3_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read3_t;

typedef struct ms_ocall_write3_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_write3_t;

typedef struct ms_ocall_read4_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read4_t;

typedef struct ms_ocall_write4_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_write4_t;

typedef struct ms_ocall_read5_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read5_t;

typedef struct ms_ocall_write5_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_write5_t;

typedef struct ms_ocall_read6_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read6_t;

typedef struct ms_ocall_write6_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_write6_t;

typedef struct ms_ocall_read7_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_read7_t;

typedef struct ms_ocall_write7_t {
	off_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_ocall_write7_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_getpid_t {
	pid_t ms_retval;
} ms_ocall_getpid_t;

typedef struct ms_ocall_getppid_t {
	pid_t ms_retval;
} ms_ocall_getppid_t;

typedef struct ms_ocall_pread_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_nbytes;
	off_t ms_offset;
} ms_ocall_pread_t;

typedef struct ms_ocall_pwrite_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_n;
	off_t ms_offset;
} ms_ocall_pwrite_t;

typedef struct ms_ocall_pipe_t {
	int ms_retval;
	int* ms_pipedes;
} ms_ocall_pipe_t;

typedef struct ms_ocall_pipe2_t {
	int ms_retval;
	int* ms_pipedes;
	int ms_flag;
} ms_ocall_pipe2_t;

typedef struct ms_ocall_sleep_t {
	unsigned int ms_retval;
	unsigned int ms_seconds;
} ms_ocall_sleep_t;

typedef struct ms_ocall_usleep_t {
	unsigned int ms_retval;
	unsigned int ms_seconds;
} ms_ocall_usleep_t;

typedef struct ms_ocall_chown_t {
	int ms_retval;
	char* ms_file;
	uid_t ms_owner;
	gid_t ms_group;
} ms_ocall_chown_t;

typedef struct ms_ocall_fchown_t {
	int ms_retval;
	int ms_fd;
	uid_t ms_owner;
	gid_t ms_group;
} ms_ocall_fchown_t;

typedef struct ms_ocall_lchown_t {
	int ms_retval;
	char* ms_file;
	uid_t ms_owner;
	gid_t ms_group;
} ms_ocall_lchown_t;

typedef struct ms_ocall_chdir_t {
	int ms_retval;
	char* ms_path;
} ms_ocall_chdir_t;

typedef struct ms_ocall_fchdir_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fchdir_t;

typedef struct ms_ocall_get_current_dir_name_t {
	char* ms_retval;
} ms_ocall_get_current_dir_name_t;

typedef struct ms_ocall_dup_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_dup_t;

typedef struct ms_ocall_dup2_t {
	int ms_retval;
	int ms_fd;
	int ms_fd2;
} ms_ocall_dup2_t;

typedef struct ms_ocall_dup3_t {
	int ms_retval;
	int ms_fd;
	int ms_fd2;
	int ms_flags;
} ms_ocall_dup3_t;

typedef struct ms_ocall_getuid_t {
	uid_t ms_retval;
} ms_ocall_getuid_t;

typedef struct ms_ocall_geteuid_t {
	uid_t ms_retval;
} ms_ocall_geteuid_t;

typedef struct ms_ocall_getgid_t {
	gid_t ms_retval;
} ms_ocall_getgid_t;

typedef struct ms_ocall_getegid_t {
	gid_t ms_retval;
} ms_ocall_getegid_t;

typedef struct ms_ocall_getpagesize_t {
	int ms_retval;
} ms_ocall_getpagesize_t;

typedef struct ms_ocall_getcwd_t {
	char* ms_retval;
	char* ms_buf;
	size_t ms_size;
} ms_ocall_getcwd_t;

typedef struct ms_ocall_unlink_t {
	int ms_retval;
	char* ms_name;
} ms_ocall_unlink_t;

typedef struct ms_ocall_rmdir_t {
	int ms_retval;
	char* ms_name;
} ms_ocall_rmdir_t;

typedef struct ms_ocall__exit_t {
	int ms_stat;
	int ms_eid;
} ms_ocall__exit_t;

typedef struct ms_ocall_exit_t {
	int ms_stat;
	int ms_eid;
} ms_ocall_exit_t;

typedef struct ms_ocall_sysconf_t {
	long int ms_retval;
	int ms_name;
} ms_ocall_sysconf_t;

typedef struct ms_ocall_setgid_t {
	int ms_retval;
	gid_t ms_gid;
} ms_ocall_setgid_t;

typedef struct ms_ocall_setuid_t {
	int ms_retval;
	uid_t ms_uid;
} ms_ocall_setuid_t;

typedef struct ms_ocall_execvp_t {
	int ms_retval;
	char* ms_file;
	char** ms_argv;
} ms_ocall_execvp_t;

typedef struct ms_ocall_ftruncate_t {
	int ms_retval;
	int ms_fd;
	off_t ms_len;
} ms_ocall_ftruncate_t;

typedef struct ms_ocall_free_t {
	void* ms_p;
} ms_ocall_free_t;

typedef struct ms_ocall_geterrno_t {
	int ms_retval;
} ms_ocall_geterrno_t;

typedef struct ms_ocall_fsync_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fsync_t;

typedef struct ms_ocall_alarm_t {
	unsigned int ms_retval;
	unsigned int ms_seconds;
} ms_ocall_alarm_t;

typedef struct ms_ocall_copy_arg_t {
	int ms_retval;
	void* ms_buff;
	int ms_buff_size;
	char** ms_argv;
	int ms_index;
} ms_ocall_copy_arg_t;

typedef struct ms_ocall_mknod_t {
	int ms_retval;
	char* ms_pathname;
	mode_t ms_mode;
	dev_t ms_dev;
} ms_ocall_mknod_t;

typedef struct ms_ocall_isatty_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_isatty_t;

typedef struct ms_ocall_malloc_t {
	void* ms_retval;
	int ms_n;
} ms_ocall_malloc_t;

typedef struct ms_ocall_fopen_t {
	SGX_WRAPPER_FILE ms_retval;
	char* ms_filename;
	char* ms_mode;
} ms_ocall_fopen_t;

typedef struct ms_ocall_popen_t {
	SGX_WRAPPER_FILE ms_retval;
	char* ms_command;
	char* ms_type;
} ms_ocall_popen_t;

typedef struct ms_ocall_fclose_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_fclose_t;

typedef struct ms_ocall_pclose_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_stream;
} ms_ocall_pclose_t;

typedef struct ms_ocall_fputs_t {
	int ms_retval;
	char* ms_str;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_fputs_t;

typedef struct ms_ocall_feof_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_feof_t;

typedef struct ms_ocall_rewind_t {
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_rewind_t;

typedef struct ms_ocall_fflush_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_fflush_t;

typedef struct ms_ocall_fread_t {
	size_t ms_retval;
	void* ms_ptr;
	size_t ms_size;
	size_t ms_nmemb;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_fread_t;

typedef struct ms_ocall_fwrite_t {
	size_t ms_retval;
	void* ms_ptr;
	size_t ms_size;
	size_t ms_count;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_fwrite_t;

typedef struct ms_ocall_vfprintf_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
	char* ms_format;
	void* ms_val;
} ms_ocall_vfprintf_t;

typedef struct ms_ocall_vprintf_t {
	int ms_retval;
	char* ms_format;
	void* ms_val;
} ms_ocall_vprintf_t;

typedef struct ms_ocall_fgets_t {
	char* ms_retval;
	char* ms_str;
	int ms_num;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_fgets_t;

typedef struct ms_ocall_fgetc_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_fgetc_t;

typedef struct ms_ocall_ungetc_t {
	int ms_retval;
	int ms_c;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_ungetc_t;

typedef struct ms_ocall_getc_unlocked_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_getc_unlocked_t;

typedef struct ms_ocall_flockfile_t {
	SGX_WRAPPER_FILE ms_filehandle;
} ms_ocall_flockfile_t;

typedef struct ms_ocall_funlockfile_t {
	SGX_WRAPPER_FILE ms_filehandle;
} ms_ocall_funlockfile_t;

typedef struct ms_ocall_vsprintf_t {
	int ms_retval;
	char* ms_string;
	char* ms_format;
	void* ms_val;
} ms_ocall_vsprintf_t;

typedef struct ms_ocall_vasprintf_t {
	int ms_retval;
	char** ms_string;
	char* ms_format;
	void* ms_val;
} ms_ocall_vasprintf_t;

typedef struct ms_ocall_ftello_t {
	off_t ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_ftello_t;

typedef struct ms_ocall_fseeko_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_fseeko_t;

typedef struct ms_ocall_ftell_t {
	off_t ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_ftell_t;

typedef struct ms_ocall_fseek_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_fseek_t;

typedef struct ms_ocall_ferror_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_ferror_t;

typedef struct ms_ocall_perror_t {
	char* ms_s;
} ms_ocall_perror_t;

typedef struct ms_ocall_getc_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_FILESTREAM;
} ms_ocall_getc_t;

typedef struct ms_ocall_vfscanf_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_s;
	char* ms_format;
	void* ms_val;
} ms_ocall_vfscanf_t;

typedef struct ms_ocall_vscanf_t {
	int ms_retval;
	char* ms_format;
	void* ms_val;
} ms_ocall_vscanf_t;

typedef struct ms_ocall_vsscanf_t {
	int ms_retval;
	char* ms_s;
	char* ms_format;
	void* ms_val;
} ms_ocall_vsscanf_t;

typedef struct ms_ocall_putchar_t {
	int ms_retval;
	int ms_c;
} ms_ocall_putchar_t;

typedef struct ms_ocall_putc_t {
	int ms_retval;
	int ms_c;
	SGX_WRAPPER_FILE ms_stream;
} ms_ocall_putc_t;

typedef struct ms_ocall_puts_t {
	int ms_retval;
	char* ms_s;
} ms_ocall_puts_t;

typedef struct ms_ocall_fputc_t {
	int ms_retval;
	int ms_c;
	SGX_WRAPPER_FILE ms_stream;
} ms_ocall_fputc_t;

typedef struct ms_ocall_fdopen_t {
	SGX_WRAPPER_FILE ms_retval;
	int ms_fd;
	char* ms_modes;
} ms_ocall_fdopen_t;

typedef struct ms_ocall_fileno_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_stream;
} ms_ocall_fileno_t;

typedef struct ms_ocall_rename_t {
	int ms_retval;
	char* ms__old;
	char* ms__new;
} ms_ocall_rename_t;

typedef struct ms_ocall_remove_t {
	int ms_retval;
	char* ms_pathname;
} ms_ocall_remove_t;

typedef struct ms_ocall_tempnam_t {
	char* ms_retval;
	char* ms_dir;
	char* ms_pfx;
} ms_ocall_tempnam_t;

typedef struct ms_ocall_print_string_t {
	int ms_retval;
	char* ms_s;
} ms_ocall_print_string_t;

typedef struct ms_ocall_fprint_string_t {
	int ms_retval;
	SGX_WRAPPER_FILE ms_stream;
	char* ms_s;
} ms_ocall_fprint_string_t;

typedef struct ms_ocall_eventfd_t {
	int ms_retval;
	unsigned int ms_initval;
	int ms_flags;
} ms_ocall_eventfd_t;

typedef struct ms_ocall_socket_t {
	int ms_retval;
	int ms_domain;
	int ms_type;
	int ms_protocol;
} ms_ocall_socket_t;

typedef struct ms_ocall_accept_t {
	int ms_retval;
	int ms_sockfd;
	struct sockaddr* ms_addr;
	socklen_t* ms_addrlen;
} ms_ocall_accept_t;

typedef struct ms_ocall_connect_t {
	int ms_retval;
	int ms_socket;
	struct sockaddr* ms_address;
	socklen_t ms_address_len;
} ms_ocall_connect_t;

typedef struct ms_ocall_sendto_t {
	ssize_t ms_retval;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
	void* ms_dest_addr;
	unsigned int ms_addrlen;
} ms_ocall_sendto_t;

typedef struct ms_ocall_recv_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_send_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

typedef struct ms_ocall_socketpair_t {
	int ms_retval;
	int ms_domain;
	int ms_type;
	int ms_protocol;
	int* ms_sv;
} ms_ocall_socketpair_t;

typedef struct ms_ocall_setsockopt_t {
	int ms_retval;
	int ms_sockfd;
	int ms_level;
	int ms_optname;
	void* ms_optval;
	unsigned int ms_optlen;
} ms_ocall_setsockopt_t;

typedef struct ms_ocall_getsockopt_t {
	int ms_retval;
	int ms_sockfd;
	int ms_level;
	int ms_optname;
	void* ms_optval;
	unsigned int* ms_optlen;
} ms_ocall_getsockopt_t;

typedef struct ms_ocall_shutdown_t {
	int ms_retval;
	int ms_fd;
	int ms_how;
} ms_ocall_shutdown_t;

typedef struct ms_ocall_bind_t {
	int ms_retval;
	int ms_fd;
	struct sockaddr* ms_addr;
	socklen_t ms_len;
} ms_ocall_bind_t;

typedef struct ms_ocall_bind_untrusted_t {
	int ms_retval;
	int ms_fd;
	struct sockaddr* ms_addr;
	socklen_t ms_len;
} ms_ocall_bind_untrusted_t;

typedef struct ms_ocall_listen_t {
	int ms_retval;
	int ms_fd;
	int ms_n;
} ms_ocall_listen_t;

typedef struct ms_ocall_getsockname_t {
	int ms_retval;
	int ms_fd;
	struct sockaddr* ms_addr;
	socklen_t* ms_len;
} ms_ocall_getsockname_t;

typedef struct ms_ocall_getpeername_t {
	int ms_retval;
	int ms_fd;
	struct sockaddr* ms_addr;
	socklen_t* ms_len;
} ms_ocall_getpeername_t;

typedef struct ms_ocall_recvfrom_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_untrusted_buf;
	size_t ms_n;
	int ms_flags;
	struct sockaddr* ms_untrusted_addr;
	socklen_t* ms_addr_len;
} ms_ocall_recvfrom_t;

typedef struct ms_ocall_sendmsg_t {
	ssize_t ms_retval;
	int ms_fd;
	struct msghdr* ms_message;
	int ms_flags;
} ms_ocall_sendmsg_t;

typedef struct ms_ocall_recvmsg_t {
	ssize_t ms_retval;
	int ms_fd;
	struct msghdr* ms_message;
	int ms_flags;
} ms_ocall_recvmsg_t;

typedef struct ms_ocall_freeaddrinfo_t {
	void* ms_res;
} ms_ocall_freeaddrinfo_t;

typedef struct ms_ocall_getaddrinfo_t {
	int ms_retval;
	char* ms_node;
	char* ms_service;
	void* ms_hints;
	void** ms_res;
} ms_ocall_getaddrinfo_t;

typedef struct ms_ocall_getaddrinfo1_t {
	int ms_retval;
	char* ms_node;
	char* ms_service;
	void* ms_hints;
	void* ms_res;
} ms_ocall_getaddrinfo1_t;

typedef struct ms_ocall_sethostent_t {
	int ms_stay_open;
} ms_ocall_sethostent_t;


typedef struct ms_ocall_gethostent_t {
	struct hostent* ms_retval;
} ms_ocall_gethostent_t;

typedef struct ms_ocall_gethostbyaddr_t {
	struct hostent* ms_retval;
	void* ms_addr;
	socklen_t ms_len;
	int ms_type;
} ms_ocall_gethostbyaddr_t;

typedef struct ms_ocall_gethostbyname_t {
	struct hostent* ms_retval;
	char* ms_name;
} ms_ocall_gethostbyname_t;

typedef struct ms_ocall_setnetent_t {
	int ms_stay_open;
} ms_ocall_setnetent_t;


typedef struct ms_ocall_getnetent_t {
	struct netent* ms_retval;
} ms_ocall_getnetent_t;

typedef struct ms_ocall_getnetbyaddr_t {
	struct netent* ms_retval;
	uint32_t ms_net;
	int ms_type;
} ms_ocall_getnetbyaddr_t;

typedef struct ms_ocall_getnetbyname_t {
	struct netent* ms_retval;
	char* ms_name;
} ms_ocall_getnetbyname_t;

typedef struct ms_ocall_setservent_t {
	int ms_stay_open;
} ms_ocall_setservent_t;


typedef struct ms_ocall_getservent_t {
	struct servent* ms_retval;
} ms_ocall_getservent_t;

typedef struct ms_ocall_getservbyname_t {
	struct servent* ms_retval;
	char* ms_name;
	char* ms_proto;
} ms_ocall_getservbyname_t;

typedef struct ms_ocall_getservbyport_t {
	struct servent* ms_retval;
	int ms_port;
	char* ms_proto;
} ms_ocall_getservbyport_t;

typedef struct ms_ocall_setprotoent_t {
	int ms_stay_open;
} ms_ocall_setprotoent_t;


typedef struct ms_ocall_getprotoent_t {
	struct protoent* ms_retval;
} ms_ocall_getprotoent_t;

typedef struct ms_ocall_getprotobyname_t {
	struct protoent* ms_retval;
	char* ms_name;
} ms_ocall_getprotobyname_t;

typedef struct ms_ocall_getprotobynumber_t {
	struct protoent* ms_retval;
	int ms_proto;
} ms_ocall_getprotobynumber_t;

typedef struct ms_ocall_gai_strerror_t {
	char* ms_retval;
	int ms_ecode;
} ms_ocall_gai_strerror_t;

typedef struct ms_ocall_getnameinfo_t {
	int ms_retval;
	struct sockaddr* ms_sa;
	socklen_t ms_salen;
	char* ms_host;
	socklen_t ms_hostlen;
	char* ms_serv;
	socklen_t ms_servlen;
	int ms_flags;
} ms_ocall_getnameinfo_t;

typedef struct ms_ocall_ntohl_t {
	uint32_t ms_retval;
	uint32_t ms_netlong;
} ms_ocall_ntohl_t;

typedef struct ms_ocall_ntohs_t {
	uint16_t ms_retval;
	uint16_t ms_netshort;
} ms_ocall_ntohs_t;

typedef struct ms_ocall_htonl_t {
	uint32_t ms_retval;
	uint32_t ms_hostlong;
} ms_ocall_htonl_t;

typedef struct ms_ocall_htons_t {
	uint16_t ms_retval;
	uint16_t ms_hostshort;
} ms_ocall_htons_t;

typedef struct ms_ocall_ioctl_t {
	int ms_retval;
	int ms_fd;
	unsigned long int ms_request;
	void* ms_arguments;
} ms_ocall_ioctl_t;

typedef struct ms_ocall_readv_t {
	ssize_t ms_retval;
	int ms___fd;
	void* ms___iovec;
	int ms_iovec_size;
	int ms___count;
} ms_ocall_readv_t;

typedef struct ms_ocall_writev_t {
	ssize_t ms_retval;
	int ms___fd;
	int ms_iovec_id;
	int ms_iovec_size;
	int ms___count;
} ms_ocall_writev_t;

typedef struct ms_ocall_init_multiple_iovec_outside_t {
	int ms_retval;
	void* ms___iovec;
	int ms_iovec_size;
	int ms___count;
} ms_ocall_init_multiple_iovec_outside_t;

typedef struct ms_ocall_copy_base_to_outside_t {
	int ms_iovec_id;
	int ms_i;
	void* ms_base;
	int ms_len;
} ms_ocall_copy_base_to_outside_t;

typedef struct ms_ocall_free_iovec_outside_t {
	int ms_iovec_id;
	int ms_iovec_size;
	int ms___count;
} ms_ocall_free_iovec_outside_t;

typedef struct ms_ocall_process_vm_readv_t {
	ssize_t ms_retval;
	pid_t ms___pid;
	struct iovec* ms___lvec;
	unsigned long int ms___liovcnt;
	struct iovec* ms___rvec;
	unsigned long int ms___riovcnt;
	unsigned long int ms___flags;
} ms_ocall_process_vm_readv_t;

typedef struct ms_ocall_process_vm_writev_t {
	ssize_t ms_retval;
	pid_t ms___pid;
	struct iovec* ms___lvec;
	unsigned long int ms___liovcnt;
	struct iovec* ms___rvec;
	unsigned long int ms___riovcnt;
	unsigned long int ms___flags;
} ms_ocall_process_vm_writev_t;

typedef struct ms_ocall_mmap_t {
	void* ms_retval;
	void* ms___addr;
	size_t ms___len;
	int ms___prot;
	int ms___flags;
	int ms___fd;
	__off_t ms___offset;
} ms_ocall_mmap_t;

typedef struct ms_ocall_mmap64_t {
	void* ms_retval;
	void* ms___addr;
	size_t ms___len;
	int ms___prot;
	int ms___flags;
	int ms___fd;
	__off64_t ms___offset;
} ms_ocall_mmap64_t;

typedef struct ms_ocall_munmap_t {
	int ms_retval;
	void* ms___addr;
	size_t ms___len;
} ms_ocall_munmap_t;

typedef struct ms_ocall_mprotect_t {
	int ms_retval;
	void* ms___addr;
	size_t ms___len;
	int ms___prot;
} ms_ocall_mprotect_t;

typedef struct ms_ocall_msync_t {
	int ms_retval;
	void* ms___addr;
	size_t ms___len;
	int ms___flags;
} ms_ocall_msync_t;

typedef struct ms_ocall_mlock_t {
	int ms_retval;
	void* ms___addr;
	size_t ms___len;
} ms_ocall_mlock_t;

typedef struct ms_ocall_munlock_t {
	int ms_retval;
	void* ms___addr;
	size_t ms___len;
} ms_ocall_munlock_t;

typedef struct ms_ocall_mlockall_t {
	int ms_retval;
	int ms___flags;
} ms_ocall_mlockall_t;

typedef struct ms_ocall_munlockall_t {
	int ms_retval;
} ms_ocall_munlockall_t;

typedef struct ms_ocall_mincore_t {
	int ms_retval;
	void* ms___start;
	size_t ms___len;
	unsigned char* ms___vec;
} ms_ocall_mincore_t;

typedef struct ms_ocall_shm_open_t {
	int ms_retval;
	char* ms___name;
	int ms___oflag;
	mode_t ms___mode;
} ms_ocall_shm_open_t;

typedef struct ms_ocall_shm_unlink_t {
	int ms_retval;
	char* ms___name;
} ms_ocall_shm_unlink_t;

typedef struct ms_ocall_poll_t {
	int ms_retval;
	struct pollfd* ms___fds;
	nfds_t ms___nfds;
	int ms___timeout;
} ms_ocall_poll_t;

typedef struct ms_ocall_epoll_create_t {
	int ms_retval;
	int ms___size;
} ms_ocall_epoll_create_t;

typedef struct ms_ocall_epoll_create1_t {
	int ms_retval;
	int ms___flags;
} ms_ocall_epoll_create1_t;

typedef struct ms_ocall_epoll_ctl_t {
	int ms_retval;
	int ms___epfd;
	int ms___op;
	int ms___fd;
	void* ms___event;
	int ms_event_size;
} ms_ocall_epoll_ctl_t;

typedef struct ms_ocall_epoll_wait_t {
	int ms_retval;
	int ms___epfd;
	void* ms___events;
	int ms_event_size;
	int ms___maxevents;
	int ms___timeout;
} ms_ocall_epoll_wait_t;

typedef struct ms_ocall_epoll_wait1_t {
	int ms_retval;
	int ms___epfd;
	void* ms___events;
	int ms_event_size;
	int ms___maxevents;
	int ms___timeout;
} ms_ocall_epoll_wait1_t;

typedef struct ms_ocall_epoll_wait2_t {
	int ms_retval;
	int ms___epfd;
	void* ms___events;
	int ms_event_size;
	int ms___maxevents;
	int ms___timeout;
} ms_ocall_epoll_wait2_t;

typedef struct ms_ocall_epoll_wait3_t {
	int ms_retval;
	int ms___epfd;
	void* ms___events;
	int ms_event_size;
	int ms___maxevents;
	int ms___timeout;
} ms_ocall_epoll_wait3_t;

typedef struct ms_ocall_epoll_wait4_t {
	int ms_retval;
	int ms___epfd;
	void* ms___events;
	int ms_event_size;
	int ms___maxevents;
	int ms___timeout;
} ms_ocall_epoll_wait4_t;

typedef struct ms_ocall_epoll_wait5_t {
	int ms_retval;
	int ms___epfd;
	void* ms___events;
	int ms_event_size;
	int ms___maxevents;
	int ms___timeout;
} ms_ocall_epoll_wait5_t;

typedef struct ms_ocall_epoll_wait6_t {
	int ms_retval;
	int ms___epfd;
	void* ms___events;
	int ms_event_size;
	int ms___maxevents;
	int ms___timeout;
} ms_ocall_epoll_wait6_t;

typedef struct ms_ocall_epoll_wait7_t {
	int ms_retval;
	int ms___epfd;
	void* ms___events;
	int ms_event_size;
	int ms___maxevents;
	int ms___timeout;
} ms_ocall_epoll_wait7_t;

typedef struct ms_ocall_epoll_pwait_t {
	int ms_retval;
	int ms___epfd;
	void* ms___events;
	int ms_event_size;
	int ms___maxevents;
	int ms___timeout;
	void* ms___ss;
	int ms_sigset_size;
} ms_ocall_epoll_pwait_t;

typedef struct ms_ocall_select_t {
	int ms_retval;
	int ms___nfds;
	fd_set* ms___readfds;
	fd_set* ms___writefds;
	fd_set* ms___exceptfds;
	void* ms___timeout;
	int ms_tvsize;
} ms_ocall_select_t;

typedef struct ms_ocall_sendfile_t {
	ssize_t ms_retval;
	int ms_out_fd;
	int ms_in_fd;
	off_t* ms_offset;
	size_t ms_count;
} ms_ocall_sendfile_t;

typedef struct ms_ocall_waitpid_t {
	__pid_t ms_retval;
	__pid_t ms___pid;
	int* ms___stat_loc;
	int ms___options;
} ms_ocall_waitpid_t;

typedef struct ms_ocall_waitid_t {
	int ms_retval;
	idtype_t ms___idtype;
	__id_t ms___id;
	siginfo_t* ms___infop;
	int ms___options;
} ms_ocall_waitid_t;

typedef struct ms_ocall_wait_t {
	pid_t ms_retval;
	int* ms_wstatus;
} ms_ocall_wait_t;

typedef struct ms_ocall_stat_t {
	int ms_retval;
	char* ms_path;
	struct stat* ms_buf;
} ms_ocall_stat_t;

typedef struct ms_ocall_fstat_t {
	int ms_retval;
	int ms_fd;
	struct stat* ms_buf;
} ms_ocall_fstat_t;

typedef struct ms_ocall_lstat_t {
	int ms_retval;
	char* ms_path;
	struct stat* ms_buf;
} ms_ocall_lstat_t;

typedef struct ms_ocall_chmod_t {
	int ms_retval;
	char* ms_file;
	mode_t ms_mode;
} ms_ocall_chmod_t;

typedef struct ms_ocall_fchmod_t {
	int ms_retval;
	int ms_fd;
	mode_t ms_mode;
} ms_ocall_fchmod_t;

typedef struct ms_ocall_fchmodat_t {
	int ms_retval;
	int ms_fd;
	char* ms_file;
	mode_t ms_mode;
	int ms_flag;
} ms_ocall_fchmodat_t;

typedef struct ms_ocall_umask_t {
	mode_t ms_retval;
	mode_t ms_mask;
} ms_ocall_umask_t;

typedef struct ms_ocall_mkdir_t {
	int ms_retval;
	char* ms_path;
	mode_t ms_mode;
} ms_ocall_mkdir_t;

typedef struct ms_ocall_mkdirat_t {
	int ms_retval;
	int ms_fd;
	char* ms_path;
	mode_t ms_mode;
} ms_ocall_mkdirat_t;

typedef struct ms_ocall_mkfifo_t {
	int ms_retval;
	char* ms_path;
	mode_t ms_mode;
} ms_ocall_mkfifo_t;

typedef struct ms_ocall_mkfifoat_t {
	int ms_retval;
	int ms_fd;
	char* ms_path;
	mode_t ms_mode;
} ms_ocall_mkfifoat_t;

typedef struct ms_ocall_utime_t {
	int ms_retval;
	char* ms_filename;
	struct utimbuf* ms_times;
} ms_ocall_utime_t;

typedef struct ms_ocall_opendir_t {
	void* ms_retval;
	char* ms_name;
} ms_ocall_opendir_t;

typedef struct ms_ocall_fdopendir_t {
	void* ms_retval;
	int ms_fd;
} ms_ocall_fdopendir_t;

typedef struct ms_ocall_closedir_t {
	int ms_retval;
	void* ms_dirp;
} ms_ocall_closedir_t;

typedef struct ms_ocall_readdir_t {
	struct dirent* ms_retval;
	void* ms_dirp;
} ms_ocall_readdir_t;

typedef struct ms_ocall_readdir_r_t {
	int ms_retval;
	void* ms_dirp;
	struct dirent* ms_entry;
	struct dirent** ms_result;
} ms_ocall_readdir_r_t;

typedef struct ms_ocall_rewinddir_t {
	void* ms_dirp;
} ms_ocall_rewinddir_t;

typedef struct ms_ocall_seekdir_t {
	void* ms_dirp;
	long int ms_pos;
} ms_ocall_seekdir_t;

typedef struct ms_ocall_telldir_t {
	long int ms_retval;
	void* ms_dirp;
} ms_ocall_telldir_t;

typedef struct ms_ocall_dirfd_t {
	int ms_retval;
	void* ms_dirp;
} ms_ocall_dirfd_t;

typedef struct ms_ocall_alphasort_t {
	int ms_retval;
	struct dirent** ms_e1;
	struct dirent** ms_e2;
} ms_ocall_alphasort_t;

typedef struct ms_ocall_getdirentries_t {
	ssize_t ms_retval;
	int ms_fd;
	char* ms_buf;
	size_t ms_nbytes;
	off_t* ms_basep;
} ms_ocall_getdirentries_t;

typedef struct ms_ocall_versionsort_t {
	int ms_retval;
	struct dirent** ms_e1;
	struct dirent** ms_e2;
} ms_ocall_versionsort_t;

typedef struct ms_ocall_prlimit_t {
	int ms_retval;
	__pid_t ms_pid;
	enum __rlimit_resource ms_resource;
	struct rlimit* ms_new_limit;
	struct rlimit* ms_old_limit;
} ms_ocall_prlimit_t;

typedef struct ms_ocall_getrlimit_t {
	int ms_retval;
	int ms_resource;
	struct rlimit* ms_rlim;
} ms_ocall_getrlimit_t;

typedef struct ms_ocall_setrlimit_t {
	int ms_retval;
	int ms_resource;
	struct rlimit* ms_rlim;
} ms_ocall_setrlimit_t;

typedef struct ms_ocall_inet_addr_t {
	in_addr_t ms_retval;
	char* ms_cp;
} ms_ocall_inet_addr_t;

typedef struct ms_ocall_inet_lnaof_t {
	in_addr_t ms_retval;
	struct in_addr ms_in;
} ms_ocall_inet_lnaof_t;

typedef struct ms_ocall_inet_makeaddr_t {
	struct in_addr ms_retval;
	in_addr_t ms_net;
	in_addr_t ms_host;
} ms_ocall_inet_makeaddr_t;

typedef struct ms_ocall_inet_netof_t {
	in_addr_t ms_retval;
	struct in_addr ms_in;
} ms_ocall_inet_netof_t;

typedef struct ms_ocall_inet_network_t {
	in_addr_t ms_retval;
	char* ms_cp;
} ms_ocall_inet_network_t;

typedef struct ms_ocall_inet_ntoa_t {
	char* ms_retval;
	struct in_addr ms_in;
} ms_ocall_inet_ntoa_t;

typedef struct ms_ocall_inet_pton_t {
	int ms_retval;
	int ms_af;
	char* ms_cp;
	void* ms_buf;
} ms_ocall_inet_pton_t;

typedef struct ms_ocall_inet_ntop_t {
	char* ms_retval;
	int ms_af;
	void* ms_cp;
	char* ms_buf;
	socklen_t ms_len;
} ms_ocall_inet_ntop_t;

typedef struct ms_ocall_sysctl_t {
	int ms_retval;
	int* ms_name;
	int ms_nlen;
	void* ms_oldval;
	size_t* ms_oldlenp;
	void* ms_newval;
	size_t ms_newlen;
} ms_ocall_sysctl_t;

typedef struct ms_ocall_sigemptyset_t {
	int ms_retval;
	sigset_t* ms_set;
} ms_ocall_sigemptyset_t;

typedef struct ms_ocall_sigfillset_t {
	int ms_retval;
	sigset_t* ms_set;
} ms_ocall_sigfillset_t;

typedef struct ms_ocall_sigaddset_t {
	int ms_retval;
	sigset_t* ms_set;
	int ms_signo;
} ms_ocall_sigaddset_t;

typedef struct ms_ocall_sigdelset_t {
	int ms_retval;
	sigset_t* ms_set;
	int ms_signo;
} ms_ocall_sigdelset_t;

typedef struct ms_ocall_sigismember_t {
	int ms_retval;
	sigset_t* ms_set;
	int ms_signo;
} ms_ocall_sigismember_t;

typedef struct ms_ocall_sigsuspend_t {
	int ms_retval;
	sigset_t* ms_set;
} ms_ocall_sigsuspend_t;

typedef struct ms_ocall_sigaction_t {
	int ms_retval;
	int ms_sig;
	struct sigaction* ms_act;
	struct sigaction* ms_oact;
} ms_ocall_sigaction_t;

typedef struct ms_ocall_sigpending_t {
	int ms_retval;
	sigset_t* ms_set;
} ms_ocall_sigpending_t;

typedef struct ms_ocall_sigwait_t {
	int ms_retval;
	sigset_t* ms_set;
	int* ms_sig;
} ms_ocall_sigwait_t;

typedef struct ms_ocall_signal_generic_t {
	__sighandler_t ms_retval;
	int ms___sig;
	__sighandler_t ms___handler;
} ms_ocall_signal_generic_t;

typedef struct ms_ocall_sigaction_generic_t {
	int ms_retval;
	int ms_sig;
	struct sigaction* ms_act;
	struct sigaction* ms_oact;
} ms_ocall_sigaction_generic_t;

typedef struct ms_ocall_signal_t {
	__sighandler_t ms_retval;
	int ms___sig;
	__sighandler_t ms___handler;
} ms_ocall_signal_t;

typedef struct ms_ocall_raise_t {
	int ms_retval;
	int ms_sig;
} ms_ocall_raise_t;

typedef struct ms_ocall_kill_t {
	int ms_retval;
	pid_t ms_pid;
	int ms_sig;
} ms_ocall_kill_t;

typedef struct ms_ocall_pmap_set_t {
	int ms_retval;
	unsigned long int ms_prognum;
	unsigned long int ms_versnum;
	unsigned int ms_protocol;
	unsigned short int ms_port;
} ms_ocall_pmap_set_t;

typedef struct ms_ocall_pmap_unset_t {
	int ms_retval;
	unsigned long int ms_prognum;
	unsigned long int ms_versnum;
} ms_ocall_pmap_unset_t;

typedef struct ms_ocall_pmap_getport_t {
	unsigned short int ms_retval;
	struct sockaddr_in* ms_addr;
	unsigned long int ms_prognum;
	unsigned long int ms_versnum;
	unsigned int ms_protocol;
} ms_ocall_pmap_getport_t;

typedef struct ms_ocall_svcudp_create_t {
	SVCXPRT* ms_retval;
	int ms___sock;
} ms_ocall_svcudp_create_t;


typedef struct ms_ocall_svctcp_create_t {
	SVCXPRT* ms_retval;
	int ms___sock;
	u_int ms___sendsize;
	u_int ms___recvsize;
} ms_ocall_svctcp_create_t;

typedef struct ms_ocall_svc_register_t {
	bool_t ms_retval;
	SVCXPRT* ms___xprt;
	rpcprog_t ms___prog;
	rpcvers_t ms___vers;
	__dispatch_fn_t ms___dispatch;
	rpcprot_t ms___protocol;
} ms_ocall_svc_register_t;

typedef struct ms_ocall_svc_register_generic_t {
	bool_t ms_retval;
	SVCXPRT* ms___xprt;
	rpcprog_t ms___prog;
	rpcvers_t ms___vers;
	__dispatch_fn_t ms___dispatch;
	rpcprot_t ms___protocol;
} ms_ocall_svc_register_generic_t;

typedef struct ms_ocall_clnt_create_t {
	CLIENT* ms_retval;
	char* ms___host;
	unsigned long int ms___prog;
	unsigned long int ms___vers;
	char* ms___prot;
} ms_ocall_clnt_create_t;

typedef struct ms_ocall_clnt_perror_t {
	CLIENT* ms___clnt;
	char* ms___msg;
} ms_ocall_clnt_perror_t;

typedef struct ms_ocall_clnt_pcreateerror_t {
	char* ms___msg;
} ms_ocall_clnt_pcreateerror_t;

typedef struct ms_ocall_callrpc_t {
	int ms_retval;
	char* ms___host;
	unsigned long int ms___prognum;
	unsigned long int ms___versnum;
	unsigned long int ms___procnum;
	xdrproc_t ms___inproc;
	char* ms___in;
	xdrproc_t ms___outproc;
	char* ms___out;
} ms_ocall_callrpc_t;

typedef struct ms_ocall_svc_sendreply_t {
	bool_t ms_retval;
	SVCXPRT* ms___xprt;
	xdrproc_t ms___xdr_results;
	char* ms___xdr_location;
} ms_ocall_svc_sendreply_t;

typedef struct ms_ocall_svcerr_noproc_t {
	SVCXPRT* ms___xprt;
} ms_ocall_svcerr_noproc_t;

typedef struct ms_ocall_svcerr_decode_t {
	SVCXPRT* ms___xprt;
} ms_ocall_svcerr_decode_t;

typedef struct ms_ocall_svcerr_systemerr_t {
	SVCXPRT* ms___xprt;
} ms_ocall_svcerr_systemerr_t;

typedef struct ms_ocall_clnt_call_t {
	bool ms_retval;
	CLIENT* ms_rh;
	unsigned long int ms_proc;
	xdrproc_t ms_xargs;
	caddr_t ms_argsp;
	xdrproc_t ms_xres;
	char* ms_resp;
	struct timeval ms_timeout;
} ms_ocall_clnt_call_t;

typedef struct ms_ocall_fast_clnt_call_t {
	unsigned long int ms_proc;
} ms_ocall_fast_clnt_call_t;

typedef struct ms_ocall_clnt_control_t {
	bool_t ms_retval;
	CLIENT* ms_cl;
	u_int ms_rq;
	char* ms_in;
	int ms_in_size;
} ms_ocall_clnt_control_t;

typedef struct ms_ocall_svc_getargs_t {
	bool_t ms_retval;
	SVCXPRT* ms_xprt;
	xdrproc_t ms_xargs;
	char* ms_argsp;
} ms_ocall_svc_getargs_t;

typedef struct ms_ocall_svc_freeargs_t {
	bool_t ms_retval;
	SVCXPRT* ms_xprt;
	xdrproc_t ms_xargs;
	char* ms_argsp;
} ms_ocall_svc_freeargs_t;

typedef struct ms_ocall_getifaddrs_t {
	int ms_retval;
	struct ifaddrs** ms_ifap;
} ms_ocall_getifaddrs_t;

typedef struct ms_ocall_freeifaddrs_t {
	struct ifaddrs* ms_ifa;
} ms_ocall_freeifaddrs_t;

typedef struct ms_ocall_if_nametoindex_t {
	unsigned int ms_retval;
	char* ms_ifname;
} ms_ocall_if_nametoindex_t;

typedef struct ms_ocall_if_indextoname_t {
	char* ms_retval;
	unsigned int ms_ifindex;
	char* ms_ifname;
} ms_ocall_if_indextoname_t;

typedef struct ms_ocall_if_nameindex_t {
	struct if_nameindex* ms_retval;
} ms_ocall_if_nameindex_t;

typedef struct ms_ocall_if_freenameindex_t {
	struct if_nameindex* ms_ptr;
} ms_ocall_if_freenameindex_t;

static sgx_status_t SGX_CDECL sgx_ecall_execute_job(void* pms)
{
	ms_ecall_execute_job_t* ms = SGX_CAST(ms_ecall_execute_job_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_execute_job_t));

	ecall_execute_job(ms->ms_pthread_self_id, ms->ms_job_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_set_enclave_id(void* pms)
{
	ms_ecall_set_enclave_id_t* ms = SGX_CAST(ms_ecall_set_enclave_id_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_set_enclave_id_t));

	ecall_set_enclave_id(ms->ms_self_eid);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_bzip2_main(void* pms)
{
	ms_ecall_bzip2_main_t* ms = SGX_CAST(ms_ecall_bzip2_main_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_argv = ms->ms_argv;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_bzip2_main_t));

	ms->ms_retval = ecall_bzip2_main(ms->ms_argc, _tmp_argv);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_generic_signal_handler(void* pms)
{
	ms_ecall_generic_signal_handler_t* ms = SGX_CAST(ms_ecall_generic_signal_handler_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generic_signal_handler_t));

	ecall_generic_signal_handler(ms->ms_handler_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_generic_rpc_dispatch_handler(void* pms)
{
	ms_ecall_generic_rpc_dispatch_handler_t* ms = SGX_CAST(ms_ecall_generic_rpc_dispatch_handler_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct svc_req* _tmp_rqstp = ms->ms_rqstp;
	SVCXPRT* _tmp_transp = ms->ms_transp;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generic_rpc_dispatch_handler_t));

	ecall_generic_rpc_dispatch_handler(ms->ms_handler_id, _tmp_rqstp, _tmp_transp);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_ecall_execute_job, 0},
		{(void*)(uintptr_t)sgx_ecall_set_enclave_id, 0},
		{(void*)(uintptr_t)sgx_ecall_bzip2_main, 0},
		{(void*)(uintptr_t)sgx_ecall_generic_signal_handler, 0},
		{(void*)(uintptr_t)sgx_ecall_generic_rpc_dispatch_handler, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[335][5];
} g_dyn_entry_table = {
	335,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{1, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL do_execve()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(0, NULL);

	return status;
}

sgx_status_t SGX_CDECL do_execlp()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(1, NULL);

	return status;
}

sgx_status_t SGX_CDECL printf_string(char* s)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_printf_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_printf_string_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_printf_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_printf_string_t));

	ms->ms_s = SGX_CAST(char*, s);
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_create(int* retval, pthread_t* new_thread, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, unsigned long int job_id, sgx_enclave_id_t eid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_create_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_create_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_create_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_create_t));

	ms->ms_new_thread = SGX_CAST(pthread_t*, new_thread);
	ms->ms___attr = __attr;
	ms->ms_job_id = job_id;
	ms->ms_eid = eid;
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_self(pthread_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_self_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_self_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_self_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_self_t));

	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_join(int* retval, pthread_t pt, void** thread_result)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_join_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_join_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_join_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_join_t));

	ms->ms_pt = pt;
	ms->ms_thread_result = SGX_CAST(void**, thread_result);
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_detach(int* retval, pthread_t pt)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_detach_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_detach_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_detach_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_detach_t));

	ms->ms_pt = pt;
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_equal(int* retval, pthread_t pt1, pthread_t pt2)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_equal_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_equal_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_equal_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_equal_t));

	ms->ms_pt1 = pt1;
	ms->ms_pt2 = pt2;
	status = sgx_ocall(11, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_exit(void* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_exit_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_exit_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_exit_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_exit_t));

	ms->ms_retval = SGX_CAST(void*, retval);
	status = sgx_ocall(12, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_cancel(int* retval, pthread_t th)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_cancel_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_cancel_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_cancel_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_cancel_t));

	ms->ms_th = th;
	status = sgx_ocall(13, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_testcancel()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(14, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_attr_init(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE* __attr)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___attr = 1;

	ms_ocall_pthread_attr_init_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_attr_init_t);
	void *__tmp = NULL;

	ocalloc_size += (__attr != NULL && sgx_is_within_enclave(__attr, _len___attr)) ? _len___attr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_attr_init_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_attr_init_t));

	if (__attr != NULL && sgx_is_within_enclave(__attr, _len___attr)) {
		ms->ms___attr = (SGX_WRAPPER_PTHREAD_ATTRIBUTE*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___attr);
		memset(ms->ms___attr, 0, _len___attr);
	} else if (__attr == NULL) {
		ms->ms___attr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(15, ms);

	if (retval) *retval = ms->ms_retval;
	if (__attr) memcpy((void*)__attr, ms->ms___attr, _len___attr);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_attr_destroy(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_attr_destroy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_attr_destroy_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_attr_destroy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_attr_destroy_t));

	ms->ms___attr = __attr;
	status = sgx_ocall(16, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_attr_getdetachstate(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int* __detachstate)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___detachstate = 1;

	ms_ocall_pthread_attr_getdetachstate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_attr_getdetachstate_t);
	void *__tmp = NULL;

	ocalloc_size += (__detachstate != NULL && sgx_is_within_enclave(__detachstate, _len___detachstate)) ? _len___detachstate : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_attr_getdetachstate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_attr_getdetachstate_t));

	ms->ms___attr = __attr;
	if (__detachstate != NULL && sgx_is_within_enclave(__detachstate, _len___detachstate)) {
		ms->ms___detachstate = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___detachstate);
		memset(ms->ms___detachstate, 0, _len___detachstate);
	} else if (__detachstate == NULL) {
		ms->ms___detachstate = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(17, ms);

	if (retval) *retval = ms->ms_retval;
	if (__detachstate) memcpy((void*)__detachstate, ms->ms___detachstate, _len___detachstate);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_attr_setdetachstate(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int __detachstate)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_attr_setdetachstate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_attr_setdetachstate_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_attr_setdetachstate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_attr_setdetachstate_t));

	ms->ms___attr = __attr;
	ms->ms___detachstate = __detachstate;
	status = sgx_ocall(18, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_attr_getguardsize(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t* __guardsize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___guardsize = 1;

	ms_ocall_pthread_attr_getguardsize_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_attr_getguardsize_t);
	void *__tmp = NULL;

	ocalloc_size += (__guardsize != NULL && sgx_is_within_enclave(__guardsize, _len___guardsize)) ? _len___guardsize : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_attr_getguardsize_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_attr_getguardsize_t));

	ms->ms___attr = __attr;
	if (__guardsize != NULL && sgx_is_within_enclave(__guardsize, _len___guardsize)) {
		ms->ms___guardsize = (size_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___guardsize);
		memcpy(ms->ms___guardsize, __guardsize, _len___guardsize);
	} else if (__guardsize == NULL) {
		ms->ms___guardsize = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(19, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_attr_setguardsize(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t __guardsize)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_attr_setguardsize_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_attr_setguardsize_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_attr_setguardsize_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_attr_setguardsize_t));

	ms->ms___attr = __attr;
	ms->ms___guardsize = __guardsize;
	status = sgx_ocall(20, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_attr_getschedpolicy(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int* __policy)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___policy = 1;

	ms_ocall_pthread_attr_getschedpolicy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_attr_getschedpolicy_t);
	void *__tmp = NULL;

	ocalloc_size += (__policy != NULL && sgx_is_within_enclave(__policy, _len___policy)) ? _len___policy : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_attr_getschedpolicy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_attr_getschedpolicy_t));

	ms->ms___attr = __attr;
	if (__policy != NULL && sgx_is_within_enclave(__policy, _len___policy)) {
		ms->ms___policy = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___policy);
		memcpy(ms->ms___policy, __policy, _len___policy);
	} else if (__policy == NULL) {
		ms->ms___policy = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(21, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_attr_setschedpolicy(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, int __policy)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_attr_setschedpolicy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_attr_setschedpolicy_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_attr_setschedpolicy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_attr_setschedpolicy_t));

	ms->ms___attr = __attr;
	ms->ms___policy = __policy;
	status = sgx_ocall(22, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_attr_getstacksize(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t* __stacksize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___stacksize = 1;

	ms_ocall_pthread_attr_getstacksize_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_attr_getstacksize_t);
	void *__tmp = NULL;

	ocalloc_size += (__stacksize != NULL && sgx_is_within_enclave(__stacksize, _len___stacksize)) ? _len___stacksize : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_attr_getstacksize_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_attr_getstacksize_t));

	ms->ms___attr = __attr;
	if (__stacksize != NULL && sgx_is_within_enclave(__stacksize, _len___stacksize)) {
		ms->ms___stacksize = (size_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___stacksize);
		memcpy(ms->ms___stacksize, __stacksize, _len___stacksize);
	} else if (__stacksize == NULL) {
		ms->ms___stacksize = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(23, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_attr_setstacksize(int* retval, SGX_WRAPPER_PTHREAD_ATTRIBUTE __attr, size_t __stacksize)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_attr_setstacksize_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_attr_setstacksize_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_attr_setstacksize_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_attr_setstacksize_t));

	ms->ms___attr = __attr;
	ms->ms___stacksize = __stacksize;
	status = sgx_ocall(24, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_setspecific(int* retval, pthread_key_t key, const void* value)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_setspecific_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_setspecific_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_setspecific_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_setspecific_t));

	ms->ms_key = key;
	ms->ms_value = SGX_CAST(void*, value);
	status = sgx_ocall(25, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_getspecific(void** retval, pthread_key_t key)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pthread_getspecific_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_getspecific_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_getspecific_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_getspecific_t));

	ms->ms_key = key;
	status = sgx_ocall(26, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pthread_key_create(int* retval, pthread_key_t* key, void* destructor)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_key = sizeof(*key);

	ms_ocall_pthread_key_create_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pthread_key_create_t);
	void *__tmp = NULL;

	ocalloc_size += (key != NULL && sgx_is_within_enclave(key, _len_key)) ? _len_key : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pthread_key_create_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pthread_key_create_t));

	if (key != NULL && sgx_is_within_enclave(key, _len_key)) {
		ms->ms_key = (pthread_key_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_key);
		memcpy(ms->ms_key, key, _len_key);
	} else if (key == NULL) {
		ms->ms_key = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_destructor = SGX_CAST(void*, destructor);
	status = sgx_ocall(27, ms);

	if (retval) *retval = ms->ms_retval;
	if (key) memcpy((void*)key, ms->ms_key, _len_key);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_time(time_t* retval, time_t* t)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_t = sizeof(*t);

	ms_ocall_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_time_t);
	void *__tmp = NULL;

	ocalloc_size += (t != NULL && sgx_is_within_enclave(t, _len_t)) ? _len_t : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_time_t));

	if (t != NULL && sgx_is_within_enclave(t, _len_t)) {
		ms->ms_t = (time_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_t);
		memset(ms->ms_t, 0, _len_t);
	} else if (t == NULL) {
		ms->ms_t = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(28, ms);

	if (retval) *retval = ms->ms_retval;
	if (t) memcpy((void*)t, ms->ms_t, _len_t);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_gettimeofday(int* retval, void* tv, int tv_size, void* tz, int tz_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tv = tv_size;
	size_t _len_tz = tz_size;

	ms_ocall_gettimeofday_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gettimeofday_t);
	void *__tmp = NULL;

	ocalloc_size += (tv != NULL && sgx_is_within_enclave(tv, _len_tv)) ? _len_tv : 0;
	ocalloc_size += (tz != NULL && sgx_is_within_enclave(tz, _len_tz)) ? _len_tz : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gettimeofday_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gettimeofday_t));

	if (tv != NULL && sgx_is_within_enclave(tv, _len_tv)) {
		ms->ms_tv = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_tv);
		memset(ms->ms_tv, 0, _len_tv);
	} else if (tv == NULL) {
		ms->ms_tv = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tv_size = tv_size;
	if (tz != NULL && sgx_is_within_enclave(tz, _len_tz)) {
		ms->ms_tz = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_tz);
		memcpy(ms->ms_tz, tz, _len_tz);
	} else if (tz == NULL) {
		ms->ms_tz = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tz_size = tz_size;
	status = sgx_ocall(29, ms);

	if (retval) *retval = ms->ms_retval;
	if (tv) memcpy((void*)tv, ms->ms_tv, _len_tv);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_gettimeofday2(int* retval, void* tv, int tv_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tv = tv_size;

	ms_ocall_gettimeofday2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gettimeofday2_t);
	void *__tmp = NULL;

	ocalloc_size += (tv != NULL && sgx_is_within_enclave(tv, _len_tv)) ? _len_tv : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gettimeofday2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gettimeofday2_t));

	if (tv != NULL && sgx_is_within_enclave(tv, _len_tv)) {
		ms->ms_tv = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_tv);
		memset(ms->ms_tv, 0, _len_tv);
	} else if (tv == NULL) {
		ms->ms_tv = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tv_size = tv_size;
	status = sgx_ocall(30, ms);

	if (retval) *retval = ms->ms_retval;
	if (tv) memcpy((void*)tv, ms->ms_tv, _len_tv);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_clock(clock_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_clock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_clock_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_clock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_clock_t));

	status = sgx_ocall(31, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_gmtime_r(struct tm** retval, const time_t* timer, struct tm* tp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timer = sizeof(*timer);
	size_t _len_tp = sizeof(*tp);

	ms_ocall_gmtime_r_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gmtime_r_t);
	void *__tmp = NULL;

	ocalloc_size += (timer != NULL && sgx_is_within_enclave(timer, _len_timer)) ? _len_timer : 0;
	ocalloc_size += (tp != NULL && sgx_is_within_enclave(tp, _len_tp)) ? _len_tp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gmtime_r_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gmtime_r_t));

	if (timer != NULL && sgx_is_within_enclave(timer, _len_timer)) {
		ms->ms_timer = (time_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_timer);
		memcpy((void*)ms->ms_timer, timer, _len_timer);
	} else if (timer == NULL) {
		ms->ms_timer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (tp != NULL && sgx_is_within_enclave(tp, _len_tp)) {
		ms->ms_tp = (struct tm*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_tp);
		memset(ms->ms_tp, 0, _len_tp);
	} else if (tp == NULL) {
		ms->ms_tp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(32, ms);

	if (retval) *retval = ms->ms_retval;
	if (tp) memcpy((void*)tp, ms->ms_tp, _len_tp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_localtime_r(struct tm** retval, const time_t* timer, struct tm* tp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timer = sizeof(*timer);
	size_t _len_tp = sizeof(*tp);

	ms_ocall_localtime_r_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_localtime_r_t);
	void *__tmp = NULL;

	ocalloc_size += (timer != NULL && sgx_is_within_enclave(timer, _len_timer)) ? _len_timer : 0;
	ocalloc_size += (tp != NULL && sgx_is_within_enclave(tp, _len_tp)) ? _len_tp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_localtime_r_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_localtime_r_t));

	if (timer != NULL && sgx_is_within_enclave(timer, _len_timer)) {
		ms->ms_timer = (time_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_timer);
		memcpy((void*)ms->ms_timer, timer, _len_timer);
	} else if (timer == NULL) {
		ms->ms_timer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (tp != NULL && sgx_is_within_enclave(tp, _len_tp)) {
		ms->ms_tp = (struct tm*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_tp);
		memset(ms->ms_tp, 0, _len_tp);
	} else if (tp == NULL) {
		ms->ms_tp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(33, ms);

	if (retval) *retval = ms->ms_retval;
	if (tp) memcpy((void*)tp, ms->ms_tp, _len_tp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mktime(time_t* retval, struct tm* tp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tp = sizeof(*tp);

	ms_ocall_mktime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mktime_t);
	void *__tmp = NULL;

	ocalloc_size += (tp != NULL && sgx_is_within_enclave(tp, _len_tp)) ? _len_tp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mktime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mktime_t));

	if (tp != NULL && sgx_is_within_enclave(tp, _len_tp)) {
		ms->ms_tp = (struct tm*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_tp);
		memset(ms->ms_tp, 0, _len_tp);
	} else if (tp == NULL) {
		ms->ms_tp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(34, ms);

	if (retval) *retval = ms->ms_retval;
	if (tp) memcpy((void*)tp, ms->ms_tp, _len_tp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getitimer(int* retval, int which, struct itimerval* curr_value)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_curr_value = sizeof(*curr_value);

	ms_ocall_getitimer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getitimer_t);
	void *__tmp = NULL;

	ocalloc_size += (curr_value != NULL && sgx_is_within_enclave(curr_value, _len_curr_value)) ? _len_curr_value : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getitimer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getitimer_t));

	ms->ms_which = which;
	if (curr_value != NULL && sgx_is_within_enclave(curr_value, _len_curr_value)) {
		ms->ms_curr_value = (struct itimerval*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_curr_value);
		memset(ms->ms_curr_value, 0, _len_curr_value);
	} else if (curr_value == NULL) {
		ms->ms_curr_value = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(35, ms);

	if (retval) *retval = ms->ms_retval;
	if (curr_value) memcpy((void*)curr_value, ms->ms_curr_value, _len_curr_value);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_setitimer(int* retval, int which, const struct itimerval* new_value, struct itimerval* old_value)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_new_value = sizeof(*new_value);
	size_t _len_old_value = sizeof(*old_value);

	ms_ocall_setitimer_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_setitimer_t);
	void *__tmp = NULL;

	ocalloc_size += (new_value != NULL && sgx_is_within_enclave(new_value, _len_new_value)) ? _len_new_value : 0;
	ocalloc_size += (old_value != NULL && sgx_is_within_enclave(old_value, _len_old_value)) ? _len_old_value : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_setitimer_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_setitimer_t));

	ms->ms_which = which;
	if (new_value != NULL && sgx_is_within_enclave(new_value, _len_new_value)) {
		ms->ms_new_value = (struct itimerval*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_new_value);
		memcpy((void*)ms->ms_new_value, new_value, _len_new_value);
	} else if (new_value == NULL) {
		ms->ms_new_value = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (old_value != NULL && sgx_is_within_enclave(old_value, _len_old_value)) {
		ms->ms_old_value = (struct itimerval*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_old_value);
		memset(ms->ms_old_value, 0, _len_old_value);
	} else if (old_value == NULL) {
		ms->ms_old_value = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(36, ms);

	if (retval) *retval = ms->ms_retval;
	if (old_value) memcpy((void*)old_value, ms->ms_old_value, _len_old_value);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_nanosleep(int* retval, const struct timespec* req, struct timespec* rem)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_req = sizeof(*req);
	size_t _len_rem = sizeof(*rem);

	ms_ocall_nanosleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_nanosleep_t);
	void *__tmp = NULL;

	ocalloc_size += (req != NULL && sgx_is_within_enclave(req, _len_req)) ? _len_req : 0;
	ocalloc_size += (rem != NULL && sgx_is_within_enclave(rem, _len_rem)) ? _len_rem : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_nanosleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_nanosleep_t));

	if (req != NULL && sgx_is_within_enclave(req, _len_req)) {
		ms->ms_req = (struct timespec*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_req);
		memcpy((void*)ms->ms_req, req, _len_req);
	} else if (req == NULL) {
		ms->ms_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (rem != NULL && sgx_is_within_enclave(rem, _len_rem)) {
		ms->ms_rem = (struct timespec*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_rem);
		memcpy(ms->ms_rem, rem, _len_rem);
	} else if (rem == NULL) {
		ms->ms_rem = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(37, ms);

	if (retval) *retval = ms->ms_retval;
	if (rem) memcpy((void*)rem, ms->ms_rem, _len_rem);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrapper_getopt(int* retval, int argc, char** argv, const char* optstring)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_optstring = optstring ? strlen(optstring) + 1 : 0;

	ms_wrapper_getopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrapper_getopt_t);
	void *__tmp = NULL;

	ocalloc_size += (optstring != NULL && sgx_is_within_enclave(optstring, _len_optstring)) ? _len_optstring : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrapper_getopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrapper_getopt_t));

	ms->ms_argc = argc;
	ms->ms_argv = SGX_CAST(char**, argv);
	if (optstring != NULL && sgx_is_within_enclave(optstring, _len_optstring)) {
		ms->ms_optstring = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_optstring);
		memcpy((void*)ms->ms_optstring, optstring, _len_optstring);
	} else if (optstring == NULL) {
		ms->ms_optstring = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(38, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL set_optind(int oi)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_set_optind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_set_optind_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_set_optind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_set_optind_t));

	ms->ms_oi = oi;
	status = sgx_ocall(39, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL set_opterr(int oe)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_set_opterr_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_set_opterr_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_set_opterr_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_set_opterr_t));

	ms->ms_oe = oe;
	status = sgx_ocall(40, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL set_optopt(int oo)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_set_optopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_set_optopt_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_set_optopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_set_optopt_t));

	ms->ms_oo = oo;
	status = sgx_ocall(41, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL set_optreset(int ors)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_set_optreset_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_set_optreset_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_set_optreset_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_set_optreset_t));

	ms->ms_ors = ors;
	status = sgx_ocall(42, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL get_optarg(char** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_get_optarg_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_get_optarg_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_get_optarg_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_get_optarg_t));

	status = sgx_ocall(43, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_optind(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_get_optind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_optind_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_optind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_optind_t));

	status = sgx_ocall(44, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_opterr(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_get_opterr_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_opterr_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_opterr_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_opterr_t));

	status = sgx_ocall(45, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_optopt(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_get_optopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_optopt_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_optopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_optopt_t));

	status = sgx_ocall(46, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getpwuid(struct passwd** retval, uid_t uid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getpwuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getpwuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getpwuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getpwuid_t));

	ms->ms_uid = uid;
	status = sgx_ocall(47, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getpwnam(struct passwd** retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_getpwnam_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getpwnam_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getpwnam_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getpwnam_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(48, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getpwnam_r(int* retval, const char* name, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;
	size_t _len_pwd = sizeof(*pwd);
	size_t _len_buf = buflen;
	size_t _len_result = sizeof(*result);

	ms_ocall_getpwnam_r_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getpwnam_r_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;
	ocalloc_size += (pwd != NULL && sgx_is_within_enclave(pwd, _len_pwd)) ? _len_pwd : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;
	ocalloc_size += (result != NULL && sgx_is_within_enclave(result, _len_result)) ? _len_result : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getpwnam_r_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getpwnam_r_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (pwd != NULL && sgx_is_within_enclave(pwd, _len_pwd)) {
		ms->ms_pwd = (struct passwd*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pwd);
		memcpy(ms->ms_pwd, pwd, _len_pwd);
	} else if (pwd == NULL) {
		ms->ms_pwd = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy(ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_buflen = buflen;
	if (result != NULL && sgx_is_within_enclave(result, _len_result)) {
		ms->ms_result = (struct passwd**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_result);
		memcpy(ms->ms_result, result, _len_result);
	} else if (result == NULL) {
		ms->ms_result = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(49, ms);

	if (retval) *retval = ms->ms_retval;
	if (result) memcpy((void*)result, ms->ms_result, _len_result);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getgrgid(struct group** retval, gid_t gid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getgrgid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getgrgid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getgrgid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getgrgid_t));

	ms->ms_gid = gid;
	status = sgx_ocall(50, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_initgroups(int* retval, const char* user, gid_t group)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_user = user ? strlen(user) + 1 : 0;

	ms_ocall_initgroups_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_initgroups_t);
	void *__tmp = NULL;

	ocalloc_size += (user != NULL && sgx_is_within_enclave(user, _len_user)) ? _len_user : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_initgroups_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_initgroups_t));

	if (user != NULL && sgx_is_within_enclave(user, _len_user)) {
		ms->ms_user = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_user);
		memcpy((void*)ms->ms_user, user, _len_user);
	} else if (user == NULL) {
		ms->ms_user = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_group = group;
	status = sgx_ocall(51, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_uname(int* retval, struct utsname* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = sizeof(*name);

	ms_ocall_uname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_uname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_uname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_uname_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (struct utsname*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memset(ms->ms_name, 0, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(52, ms);

	if (retval) *retval = ms->ms_retval;
	if (name) memcpy((void*)name, ms->ms_name, _len_name);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getenv(char** retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_getenv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getenv_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getenv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getenv_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(53, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_putenv(int* retval, char* string)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_string = string ? strlen(string) + 1 : 0;

	ms_ocall_putenv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_putenv_t);
	void *__tmp = NULL;

	ocalloc_size += (string != NULL && sgx_is_within_enclave(string, _len_string)) ? _len_string : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_putenv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_putenv_t));

	if (string != NULL && sgx_is_within_enclave(string, _len_string)) {
		ms->ms_string = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_string);
		memcpy(ms->ms_string, string, _len_string);
	} else if (string == NULL) {
		ms->ms_string = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(54, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_clearenv(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_clearenv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_clearenv_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_clearenv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_clearenv_t));

	status = sgx_ocall(55, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_setenv(int* retval, const char* name, const char* value, int replace)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;
	size_t _len_value = value ? strlen(value) + 1 : 0;

	ms_ocall_setenv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_setenv_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;
	ocalloc_size += (value != NULL && sgx_is_within_enclave(value, _len_value)) ? _len_value : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_setenv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_setenv_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (value != NULL && sgx_is_within_enclave(value, _len_value)) {
		ms->ms_value = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_value);
		memcpy((void*)ms->ms_value, value, _len_value);
	} else if (value == NULL) {
		ms->ms_value = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_replace = replace;
	status = sgx_ocall(56, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_unsetenv(int* retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_unsetenv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_unsetenv_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_unsetenv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_unsetenv_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(57, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mkstemp(int* retval, char* temp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_temp = temp ? strlen(temp) + 1 : 0;

	ms_ocall_mkstemp_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mkstemp_t);
	void *__tmp = NULL;

	ocalloc_size += (temp != NULL && sgx_is_within_enclave(temp, _len_temp)) ? _len_temp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mkstemp_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mkstemp_t));

	if (temp != NULL && sgx_is_within_enclave(temp, _len_temp)) {
		ms->ms_temp = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_temp);
		memcpy(ms->ms_temp, temp, _len_temp);
	} else if (temp == NULL) {
		ms->ms_temp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(58, ms);

	if (retval) *retval = ms->ms_retval;
	if (temp) memcpy((void*)temp, ms->ms_temp, _len_temp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mkdtemp(char** retval, char* temp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_temp = temp ? strlen(temp) + 1 : 0;

	ms_ocall_mkdtemp_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mkdtemp_t);
	void *__tmp = NULL;

	ocalloc_size += (temp != NULL && sgx_is_within_enclave(temp, _len_temp)) ? _len_temp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mkdtemp_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mkdtemp_t));

	if (temp != NULL && sgx_is_within_enclave(temp, _len_temp)) {
		ms->ms_temp = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_temp);
		memcpy(ms->ms_temp, temp, _len_temp);
	} else if (temp == NULL) {
		ms->ms_temp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(59, ms);

	if (retval) *retval = ms->ms_retval;
	if (temp) memcpy((void*)temp, ms->ms_temp, _len_temp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_open1(int* retval, const char* pathname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_open1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_open1_t);
	void *__tmp = NULL;

	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_open1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_open1_t));

	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		memcpy((void*)ms->ms_pathname, pathname, _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(60, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_open2(int* retval, const char* pathname, int flags, unsigned int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_open2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_open2_t);
	void *__tmp = NULL;

	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_open2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_open2_t));

	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		memcpy((void*)ms->ms_pathname, pathname, _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flags = flags;
	ms->ms_mode = mode;
	status = sgx_ocall(61, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_creat(int* retval, const char* pathname, unsigned int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_creat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_creat_t);
	void *__tmp = NULL;

	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_creat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_creat_t));

	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		memcpy((void*)ms->ms_pathname, pathname, _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(62, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_openat1(int* retval, int dirfd, const char* pathname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_openat1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_openat1_t);
	void *__tmp = NULL;

	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_openat1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_openat1_t));

	ms->ms_dirfd = dirfd;
	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		memcpy((void*)ms->ms_pathname, pathname, _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(63, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_openat2(int* retval, int dirfd, const char* pathname, int flags, unsigned int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_openat2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_openat2_t);
	void *__tmp = NULL;

	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_openat2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_openat2_t));

	ms->ms_dirfd = dirfd;
	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		memcpy((void*)ms->ms_pathname, pathname, _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flags = flags;
	ms->ms_mode = mode;
	status = sgx_ocall(64, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fcntl1(int* retval, int fd, int cmd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fcntl1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fcntl1_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fcntl1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fcntl1_t));

	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	status = sgx_ocall(65, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fcntl2(int* retval, int fd, int cmd, long int arg)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fcntl2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fcntl2_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fcntl2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fcntl2_t));

	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	ms->ms_arg = arg;
	status = sgx_ocall(66, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fcntl3(int* retval, int fd, int cmd, void* arg, int flock_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_arg = flock_size;

	ms_ocall_fcntl3_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fcntl3_t);
	void *__tmp = NULL;

	ocalloc_size += (arg != NULL && sgx_is_within_enclave(arg, _len_arg)) ? _len_arg : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fcntl3_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fcntl3_t));

	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	if (arg != NULL && sgx_is_within_enclave(arg, _len_arg)) {
		ms->ms_arg = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_arg);
		memcpy(ms->ms_arg, arg, _len_arg);
	} else if (arg == NULL) {
		ms->ms_arg = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flock_size = flock_size;
	status = sgx_ocall(67, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_gethostname(int* retval, char* name, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = len;

	ms_ocall_gethostname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gethostname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gethostname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gethostname_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memset(ms->ms_name, 0, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(68, ms);

	if (retval) *retval = ms->ms_retval;
	if (name) memcpy((void*)name, ms->ms_name, _len_name);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sethostname(int* retval, const char* name, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = len;

	ms_ocall_sethostname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sethostname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sethostname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sethostname_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(69, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_lseek(off_t* retval, int fd, off_t offset, int whence)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_lseek_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_lseek_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_lseek_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_lseek_t));

	ms->ms_fd = fd;
	ms->ms_offset = offset;
	ms->ms_whence = whence;
	status = sgx_ocall(70, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL get_buff_addr(int* retval, size_t arr[2])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_arr = 2 * sizeof(*arr);

	ms_get_buff_addr_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_get_buff_addr_t);
	void *__tmp = NULL;

	ocalloc_size += (arr != NULL && sgx_is_within_enclave(arr, _len_arr)) ? _len_arr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_get_buff_addr_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_get_buff_addr_t));

	if (arr != NULL && sgx_is_within_enclave(arr, _len_arr)) {
		ms->ms_arr = (size_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_arr);
		memset(ms->ms_arr, 0, _len_arr);
	} else if (arr == NULL) {
		ms->ms_arr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(71, ms);

	if (retval) *retval = ms->ms_retval;
	if (arr) memcpy((void*)arr, ms->ms_arr, _len_arr);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fast_write(off_t* retval, int fd, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fast_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fast_write_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fast_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fast_write_t));

	ms->ms_fd = fd;
	ms->ms_count = count;
	status = sgx_ocall(72, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fast_read(off_t* retval, int fd, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fast_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fast_read_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fast_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fast_read_t));

	ms->ms_fd = fd;
	ms->ms_count = count;
	status = sgx_ocall(73, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read(off_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(74, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write(off_t* retval, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(75, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read1(off_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_read1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read1_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read1_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(76, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write1(off_t* retval, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_write1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write1_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write1_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(77, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read2(off_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_read2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read2_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read2_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(78, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write2(off_t* retval, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_write2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write2_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write2_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(79, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read3(off_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_read3_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read3_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read3_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read3_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(80, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write3(off_t* retval, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_write3_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write3_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write3_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write3_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(81, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read4(off_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_read4_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read4_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read4_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read4_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(82, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write4(off_t* retval, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_write4_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write4_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write4_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write4_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(83, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read5(off_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_read5_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read5_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read5_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read5_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(84, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write5(off_t* retval, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_write5_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write5_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write5_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write5_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(85, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read6(off_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_read6_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read6_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read6_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read6_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(86, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write6(off_t* retval, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_write6_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write6_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write6_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write6_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(87, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read7(off_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_read7_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read7_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read7_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read7_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(88, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write7(off_t* retval, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_ocall_write7_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write7_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write7_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write7_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(89, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_close_t));

	ms->ms_fd = fd;
	status = sgx_ocall(90, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getpid(pid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getpid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getpid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getpid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getpid_t));

	status = sgx_ocall(91, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getppid(pid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getppid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getppid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getppid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getppid_t));

	status = sgx_ocall(92, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pread(ssize_t* retval, int fd, void* buf, size_t nbytes, off_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_ocall_pread_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pread_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pread_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pread_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	ms->ms_offset = offset;
	status = sgx_ocall(93, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pwrite(ssize_t* retval, int fd, const void* buf, size_t n, off_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_ocall_pwrite_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pwrite_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pwrite_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pwrite_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_n = n;
	ms->ms_offset = offset;
	status = sgx_ocall(94, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pipe(int* retval, int pipedes[2])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pipedes = 2 * sizeof(*pipedes);

	ms_ocall_pipe_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pipe_t);
	void *__tmp = NULL;

	ocalloc_size += (pipedes != NULL && sgx_is_within_enclave(pipedes, _len_pipedes)) ? _len_pipedes : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pipe_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pipe_t));

	if (pipedes != NULL && sgx_is_within_enclave(pipedes, _len_pipedes)) {
		ms->ms_pipedes = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pipedes);
		memset(ms->ms_pipedes, 0, _len_pipedes);
	} else if (pipedes == NULL) {
		ms->ms_pipedes = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(95, ms);

	if (retval) *retval = ms->ms_retval;
	if (pipedes) memcpy((void*)pipedes, ms->ms_pipedes, _len_pipedes);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pipe2(int* retval, int pipedes[2], int flag)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pipedes = 2 * sizeof(*pipedes);

	ms_ocall_pipe2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pipe2_t);
	void *__tmp = NULL;

	ocalloc_size += (pipedes != NULL && sgx_is_within_enclave(pipedes, _len_pipedes)) ? _len_pipedes : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pipe2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pipe2_t));

	if (pipedes != NULL && sgx_is_within_enclave(pipedes, _len_pipedes)) {
		ms->ms_pipedes = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pipedes);
		memset(ms->ms_pipedes, 0, _len_pipedes);
	} else if (pipedes == NULL) {
		ms->ms_pipedes = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flag = flag;
	status = sgx_ocall(96, ms);

	if (retval) *retval = ms->ms_retval;
	if (pipedes) memcpy((void*)pipedes, ms->ms_pipedes, _len_pipedes);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sleep(unsigned int* retval, unsigned int seconds)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sleep_t));

	ms->ms_seconds = seconds;
	status = sgx_ocall(97, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_usleep(unsigned int* retval, unsigned int seconds)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_usleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_usleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_usleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_usleep_t));

	ms->ms_seconds = seconds;
	status = sgx_ocall(98, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_chown(int* retval, const char* file, uid_t owner, gid_t group)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file = file ? strlen(file) + 1 : 0;

	ms_ocall_chown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_chown_t);
	void *__tmp = NULL;

	ocalloc_size += (file != NULL && sgx_is_within_enclave(file, _len_file)) ? _len_file : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_chown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_chown_t));

	if (file != NULL && sgx_is_within_enclave(file, _len_file)) {
		ms->ms_file = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_file);
		memcpy((void*)ms->ms_file, file, _len_file);
	} else if (file == NULL) {
		ms->ms_file = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_owner = owner;
	ms->ms_group = group;
	status = sgx_ocall(99, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fchown(int* retval, int fd, uid_t owner, gid_t group)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fchown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fchown_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fchown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fchown_t));

	ms->ms_fd = fd;
	ms->ms_owner = owner;
	ms->ms_group = group;
	status = sgx_ocall(100, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_lchown(int* retval, const char* file, uid_t owner, gid_t group)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file = file ? strlen(file) + 1 : 0;

	ms_ocall_lchown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_lchown_t);
	void *__tmp = NULL;

	ocalloc_size += (file != NULL && sgx_is_within_enclave(file, _len_file)) ? _len_file : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_lchown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_lchown_t));

	if (file != NULL && sgx_is_within_enclave(file, _len_file)) {
		ms->ms_file = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_file);
		memcpy((void*)ms->ms_file, file, _len_file);
	} else if (file == NULL) {
		ms->ms_file = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_owner = owner;
	ms->ms_group = group;
	status = sgx_ocall(101, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_chdir(int* retval, const char* path)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_chdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_chdir_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_chdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_chdir_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(102, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fchdir(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fchdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fchdir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fchdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fchdir_t));

	ms->ms_fd = fd;
	status = sgx_ocall(103, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_current_dir_name(char** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_get_current_dir_name_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_current_dir_name_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_current_dir_name_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_current_dir_name_t));

	status = sgx_ocall(104, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_dup(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_dup_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_dup_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_dup_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_dup_t));

	ms->ms_fd = fd;
	status = sgx_ocall(105, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_dup2(int* retval, int fd, int fd2)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_dup2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_dup2_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_dup2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_dup2_t));

	ms->ms_fd = fd;
	ms->ms_fd2 = fd2;
	status = sgx_ocall(106, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_dup3(int* retval, int fd, int fd2, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_dup3_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_dup3_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_dup3_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_dup3_t));

	ms->ms_fd = fd;
	ms->ms_fd2 = fd2;
	ms->ms_flags = flags;
	status = sgx_ocall(107, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getuid(uid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getuid_t));

	status = sgx_ocall(108, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_geteuid(uid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_geteuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_geteuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_geteuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_geteuid_t));

	status = sgx_ocall(109, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getgid(gid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getgid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getgid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getgid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getgid_t));

	status = sgx_ocall(110, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getegid(gid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getegid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getegid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getegid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getegid_t));

	status = sgx_ocall(111, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getpagesize(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getpagesize_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getpagesize_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getpagesize_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getpagesize_t));

	status = sgx_ocall(112, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getcwd(char** retval, char* buf, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = size;

	ms_ocall_getcwd_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getcwd_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getcwd_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getcwd_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	status = sgx_ocall(113, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_unlink(int* retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_unlink_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_unlink_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_unlink_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_unlink_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(114, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_rmdir(int* retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_rmdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_rmdir_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_rmdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_rmdir_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(115, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall__exit(int stat, int eid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall__exit_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall__exit_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall__exit_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall__exit_t));

	ms->ms_stat = stat;
	ms->ms_eid = eid;
	status = sgx_ocall(116, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_exit(int stat, int eid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_exit_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_exit_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_exit_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_exit_t));

	ms->ms_stat = stat;
	ms->ms_eid = eid;
	status = sgx_ocall(117, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sysconf(long int* retval, int name)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sysconf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sysconf_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sysconf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sysconf_t));

	ms->ms_name = name;
	status = sgx_ocall(118, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_setgid(int* retval, gid_t gid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_setgid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_setgid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_setgid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_setgid_t));

	ms->ms_gid = gid;
	status = sgx_ocall(119, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_setuid(int* retval, uid_t uid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_setuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_setuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_setuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_setuid_t));

	ms->ms_uid = uid;
	status = sgx_ocall(120, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_execvp(int* retval, const char* file, const char** argv)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_execvp_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_execvp_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_execvp_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_execvp_t));

	ms->ms_file = SGX_CAST(char*, file);
	ms->ms_argv = SGX_CAST(char**, argv);
	status = sgx_ocall(121, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ftruncate(int* retval, int fd, off_t len)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_ftruncate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ftruncate_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ftruncate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ftruncate_t));

	ms->ms_fd = fd;
	ms->ms_len = len;
	status = sgx_ocall(122, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_free(void* p)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_free_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_free_t));

	ms->ms_p = SGX_CAST(void*, p);
	status = sgx_ocall(123, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_geterrno(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_geterrno_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_geterrno_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_geterrno_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_geterrno_t));

	status = sgx_ocall(124, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fsync(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fsync_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fsync_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fsync_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fsync_t));

	ms->ms_fd = fd;
	status = sgx_ocall(125, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_alarm(unsigned int* retval, unsigned int seconds)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_alarm_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_alarm_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_alarm_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_alarm_t));

	ms->ms_seconds = seconds;
	status = sgx_ocall(126, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_copy_arg(int* retval, void* buff, int buff_size, char** argv, int index)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buff = buff_size;

	ms_ocall_copy_arg_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_copy_arg_t);
	void *__tmp = NULL;

	ocalloc_size += (buff != NULL && sgx_is_within_enclave(buff, _len_buff)) ? _len_buff : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_copy_arg_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_copy_arg_t));

	if (buff != NULL && sgx_is_within_enclave(buff, _len_buff)) {
		ms->ms_buff = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buff);
		memcpy(ms->ms_buff, buff, _len_buff);
	} else if (buff == NULL) {
		ms->ms_buff = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_buff_size = buff_size;
	ms->ms_argv = SGX_CAST(char**, argv);
	ms->ms_index = index;
	status = sgx_ocall(127, ms);

	if (retval) *retval = ms->ms_retval;
	if (buff) memcpy((void*)buff, ms->ms_buff, _len_buff);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mknod(int* retval, const char* pathname, mode_t mode, dev_t dev)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_ocall_mknod_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mknod_t);
	void *__tmp = NULL;

	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mknod_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mknod_t));

	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		memcpy((void*)ms->ms_pathname, pathname, _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	ms->ms_dev = dev;
	status = sgx_ocall(128, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_isatty(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_isatty_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_isatty_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_isatty_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_isatty_t));

	ms->ms_fd = fd;
	status = sgx_ocall(129, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_malloc(void** retval, int n)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_malloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_malloc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_malloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_malloc_t));

	ms->ms_n = n;
	status = sgx_ocall(130, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fopen(SGX_WRAPPER_FILE* retval, const char* filename, const char* mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_mode = mode ? strlen(mode) + 1 : 0;

	ms_ocall_fopen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fopen_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;
	ocalloc_size += (mode != NULL && sgx_is_within_enclave(mode, _len_mode)) ? _len_mode : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fopen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fopen_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_filename);
		memcpy((void*)ms->ms_filename, filename, _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (mode != NULL && sgx_is_within_enclave(mode, _len_mode)) {
		ms->ms_mode = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_mode);
		memcpy((void*)ms->ms_mode, mode, _len_mode);
	} else if (mode == NULL) {
		ms->ms_mode = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(131, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_popen(SGX_WRAPPER_FILE* retval, const char* command, const char* type)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_command = command ? strlen(command) + 1 : 0;
	size_t _len_type = type ? strlen(type) + 1 : 0;

	ms_ocall_popen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_popen_t);
	void *__tmp = NULL;

	ocalloc_size += (command != NULL && sgx_is_within_enclave(command, _len_command)) ? _len_command : 0;
	ocalloc_size += (type != NULL && sgx_is_within_enclave(type, _len_type)) ? _len_type : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_popen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_popen_t));

	if (command != NULL && sgx_is_within_enclave(command, _len_command)) {
		ms->ms_command = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_command);
		memcpy((void*)ms->ms_command, command, _len_command);
	} else if (command == NULL) {
		ms->ms_command = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (type != NULL && sgx_is_within_enclave(type, _len_type)) {
		ms->ms_type = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_type);
		memcpy((void*)ms->ms_type, type, _len_type);
	} else if (type == NULL) {
		ms->ms_type = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(132, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fclose(int* retval, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fclose_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fclose_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fclose_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fclose_t));

	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(133, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pclose(int* retval, SGX_WRAPPER_FILE stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pclose_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pclose_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pclose_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pclose_t));

	ms->ms_stream = stream;
	status = sgx_ocall(134, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fputs(int* retval, const char* str, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_fputs_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fputs_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fputs_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fputs_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(135, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_feof(int* retval, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_feof_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_feof_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_feof_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_feof_t));

	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(136, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_rewind(SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_rewind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_rewind_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_rewind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_rewind_t));

	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(137, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fflush(int* retval, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fflush_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fflush_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fflush_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fflush_t));

	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(138, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fread(size_t* retval, void* ptr, size_t size, size_t nmemb, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ptr = nmemb * size;

	ms_ocall_fread_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fread_t);
	void *__tmp = NULL;

	ocalloc_size += (ptr != NULL && sgx_is_within_enclave(ptr, _len_ptr)) ? _len_ptr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fread_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fread_t));

	if (ptr != NULL && sgx_is_within_enclave(ptr, _len_ptr)) {
		ms->ms_ptr = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_ptr);
		memset(ms->ms_ptr, 0, _len_ptr);
	} else if (ptr == NULL) {
		ms->ms_ptr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	ms->ms_nmemb = nmemb;
	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(139, ms);

	if (retval) *retval = ms->ms_retval;
	if (ptr) memcpy((void*)ptr, ms->ms_ptr, _len_ptr);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fwrite(size_t* retval, const void* ptr, size_t size, size_t count, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ptr = count * size;

	ms_ocall_fwrite_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fwrite_t);
	void *__tmp = NULL;

	ocalloc_size += (ptr != NULL && sgx_is_within_enclave(ptr, _len_ptr)) ? _len_ptr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fwrite_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fwrite_t));

	if (ptr != NULL && sgx_is_within_enclave(ptr, _len_ptr)) {
		ms->ms_ptr = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_ptr);
		memcpy((void*)ms->ms_ptr, ptr, _len_ptr);
	} else if (ptr == NULL) {
		ms->ms_ptr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_size = size;
	ms->ms_count = count;
	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(140, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_vfprintf(int* retval, SGX_WRAPPER_FILE FILESTREAM, const char* format, void* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_format = format ? strlen(format) + 1 : 0;

	ms_ocall_vfprintf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_vfprintf_t);
	void *__tmp = NULL;

	ocalloc_size += (format != NULL && sgx_is_within_enclave(format, _len_format)) ? _len_format : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_vfprintf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_vfprintf_t));

	ms->ms_FILESTREAM = FILESTREAM;
	if (format != NULL && sgx_is_within_enclave(format, _len_format)) {
		ms->ms_format = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_format);
		memcpy((void*)ms->ms_format, format, _len_format);
	} else if (format == NULL) {
		ms->ms_format = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = SGX_CAST(void*, val);
	status = sgx_ocall(141, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_vprintf(int* retval, const char* format, void* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_format = format ? strlen(format) + 1 : 0;

	ms_ocall_vprintf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_vprintf_t);
	void *__tmp = NULL;

	ocalloc_size += (format != NULL && sgx_is_within_enclave(format, _len_format)) ? _len_format : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_vprintf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_vprintf_t));

	if (format != NULL && sgx_is_within_enclave(format, _len_format)) {
		ms->ms_format = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_format);
		memcpy((void*)ms->ms_format, format, _len_format);
	} else if (format == NULL) {
		ms->ms_format = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = SGX_CAST(void*, val);
	status = sgx_ocall(142, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fgets(char** retval, char* str, int num, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = num;

	ms_ocall_fgets_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fgets_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fgets_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fgets_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memset(ms->ms_str, 0, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_num = num;
	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(143, ms);

	if (retval) *retval = ms->ms_retval;
	if (str) memcpy((void*)str, ms->ms_str, _len_str);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fgetc(int* retval, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fgetc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fgetc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fgetc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fgetc_t));

	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(144, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ungetc(int* retval, int c, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_ungetc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ungetc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ungetc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ungetc_t));

	ms->ms_c = c;
	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(145, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getc_unlocked(int* retval, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getc_unlocked_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getc_unlocked_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getc_unlocked_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getc_unlocked_t));

	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(146, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_flockfile(SGX_WRAPPER_FILE filehandle)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_flockfile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_flockfile_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_flockfile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_flockfile_t));

	ms->ms_filehandle = filehandle;
	status = sgx_ocall(147, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_funlockfile(SGX_WRAPPER_FILE filehandle)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_funlockfile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_funlockfile_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_funlockfile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_funlockfile_t));

	ms->ms_filehandle = filehandle;
	status = sgx_ocall(148, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_vsprintf(int* retval, char* string, const char* format, void* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_format = format ? strlen(format) + 1 : 0;

	ms_ocall_vsprintf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_vsprintf_t);
	void *__tmp = NULL;

	ocalloc_size += (format != NULL && sgx_is_within_enclave(format, _len_format)) ? _len_format : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_vsprintf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_vsprintf_t));

	ms->ms_string = SGX_CAST(char*, string);
	if (format != NULL && sgx_is_within_enclave(format, _len_format)) {
		ms->ms_format = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_format);
		memcpy((void*)ms->ms_format, format, _len_format);
	} else if (format == NULL) {
		ms->ms_format = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = SGX_CAST(void*, val);
	status = sgx_ocall(149, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_vasprintf(int* retval, char** string, const char* format, void* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_format = format ? strlen(format) + 1 : 0;

	ms_ocall_vasprintf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_vasprintf_t);
	void *__tmp = NULL;

	ocalloc_size += (format != NULL && sgx_is_within_enclave(format, _len_format)) ? _len_format : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_vasprintf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_vasprintf_t));

	ms->ms_string = SGX_CAST(char**, string);
	if (format != NULL && sgx_is_within_enclave(format, _len_format)) {
		ms->ms_format = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_format);
		memcpy((void*)ms->ms_format, format, _len_format);
	} else if (format == NULL) {
		ms->ms_format = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = SGX_CAST(void*, val);
	status = sgx_ocall(150, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ftello(off_t* retval, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_ftello_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ftello_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ftello_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ftello_t));

	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(151, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fseeko(int* retval, SGX_WRAPPER_FILE FILESTREAM, off_t offset, int whence)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fseeko_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fseeko_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fseeko_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fseeko_t));

	ms->ms_FILESTREAM = FILESTREAM;
	ms->ms_offset = offset;
	ms->ms_whence = whence;
	status = sgx_ocall(152, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ftell(off_t* retval, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_ftell_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ftell_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ftell_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ftell_t));

	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(153, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fseek(int* retval, SGX_WRAPPER_FILE FILESTREAM, off_t offset, int whence)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fseek_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fseek_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fseek_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fseek_t));

	ms->ms_FILESTREAM = FILESTREAM;
	ms->ms_offset = offset;
	ms->ms_whence = whence;
	status = sgx_ocall(154, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ferror(int* retval, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_ferror_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ferror_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ferror_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ferror_t));

	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(155, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_perror(const char* s)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_s = s ? strlen(s) + 1 : 0;

	ms_ocall_perror_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_perror_t);
	void *__tmp = NULL;

	ocalloc_size += (s != NULL && sgx_is_within_enclave(s, _len_s)) ? _len_s : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_perror_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_perror_t));

	if (s != NULL && sgx_is_within_enclave(s, _len_s)) {
		ms->ms_s = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_s);
		memcpy((void*)ms->ms_s, s, _len_s);
	} else if (s == NULL) {
		ms->ms_s = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(156, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getc(int* retval, SGX_WRAPPER_FILE FILESTREAM)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getc_t));

	ms->ms_FILESTREAM = FILESTREAM;
	status = sgx_ocall(157, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_vfscanf(int* retval, SGX_WRAPPER_FILE s, const char* format, void* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_format = format ? strlen(format) + 1 : 0;

	ms_ocall_vfscanf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_vfscanf_t);
	void *__tmp = NULL;

	ocalloc_size += (format != NULL && sgx_is_within_enclave(format, _len_format)) ? _len_format : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_vfscanf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_vfscanf_t));

	ms->ms_s = s;
	if (format != NULL && sgx_is_within_enclave(format, _len_format)) {
		ms->ms_format = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_format);
		memcpy((void*)ms->ms_format, format, _len_format);
	} else if (format == NULL) {
		ms->ms_format = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = SGX_CAST(void*, val);
	status = sgx_ocall(158, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_vscanf(int* retval, const char* format, void* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_format = format ? strlen(format) + 1 : 0;

	ms_ocall_vscanf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_vscanf_t);
	void *__tmp = NULL;

	ocalloc_size += (format != NULL && sgx_is_within_enclave(format, _len_format)) ? _len_format : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_vscanf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_vscanf_t));

	if (format != NULL && sgx_is_within_enclave(format, _len_format)) {
		ms->ms_format = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_format);
		memcpy((void*)ms->ms_format, format, _len_format);
	} else if (format == NULL) {
		ms->ms_format = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = SGX_CAST(void*, val);
	status = sgx_ocall(159, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_vsscanf(int* retval, const char* s, const char* format, void* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_s = s ? strlen(s) + 1 : 0;
	size_t _len_format = format ? strlen(format) + 1 : 0;

	ms_ocall_vsscanf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_vsscanf_t);
	void *__tmp = NULL;

	ocalloc_size += (s != NULL && sgx_is_within_enclave(s, _len_s)) ? _len_s : 0;
	ocalloc_size += (format != NULL && sgx_is_within_enclave(format, _len_format)) ? _len_format : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_vsscanf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_vsscanf_t));

	if (s != NULL && sgx_is_within_enclave(s, _len_s)) {
		ms->ms_s = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_s);
		memcpy((void*)ms->ms_s, s, _len_s);
	} else if (s == NULL) {
		ms->ms_s = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (format != NULL && sgx_is_within_enclave(format, _len_format)) {
		ms->ms_format = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_format);
		memcpy((void*)ms->ms_format, format, _len_format);
	} else if (format == NULL) {
		ms->ms_format = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = SGX_CAST(void*, val);
	status = sgx_ocall(160, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_putchar(int* retval, int c)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_putchar_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_putchar_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_putchar_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_putchar_t));

	ms->ms_c = c;
	status = sgx_ocall(161, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_putc(int* retval, int c, SGX_WRAPPER_FILE stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_putc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_putc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_putc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_putc_t));

	ms->ms_c = c;
	ms->ms_stream = stream;
	status = sgx_ocall(162, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_puts(int* retval, const char* s)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_s = s ? strlen(s) + 1 : 0;

	ms_ocall_puts_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_puts_t);
	void *__tmp = NULL;

	ocalloc_size += (s != NULL && sgx_is_within_enclave(s, _len_s)) ? _len_s : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_puts_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_puts_t));

	if (s != NULL && sgx_is_within_enclave(s, _len_s)) {
		ms->ms_s = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_s);
		memcpy((void*)ms->ms_s, s, _len_s);
	} else if (s == NULL) {
		ms->ms_s = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(163, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fputc(int* retval, int c, SGX_WRAPPER_FILE stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fputc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fputc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fputc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fputc_t));

	ms->ms_c = c;
	ms->ms_stream = stream;
	status = sgx_ocall(164, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fdopen(SGX_WRAPPER_FILE* retval, int fd, const char* modes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_modes = modes ? strlen(modes) + 1 : 0;

	ms_ocall_fdopen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fdopen_t);
	void *__tmp = NULL;

	ocalloc_size += (modes != NULL && sgx_is_within_enclave(modes, _len_modes)) ? _len_modes : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fdopen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fdopen_t));

	ms->ms_fd = fd;
	if (modes != NULL && sgx_is_within_enclave(modes, _len_modes)) {
		ms->ms_modes = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_modes);
		memcpy((void*)ms->ms_modes, modes, _len_modes);
	} else if (modes == NULL) {
		ms->ms_modes = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(165, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fileno(int* retval, SGX_WRAPPER_FILE stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fileno_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fileno_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fileno_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fileno_t));

	ms->ms_stream = stream;
	status = sgx_ocall(166, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_rename(int* retval, const char* _old, const char* _new)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len__old = _old ? strlen(_old) + 1 : 0;
	size_t _len__new = _new ? strlen(_new) + 1 : 0;

	ms_ocall_rename_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_rename_t);
	void *__tmp = NULL;

	ocalloc_size += (_old != NULL && sgx_is_within_enclave(_old, _len__old)) ? _len__old : 0;
	ocalloc_size += (_new != NULL && sgx_is_within_enclave(_new, _len__new)) ? _len__new : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_rename_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_rename_t));

	if (_old != NULL && sgx_is_within_enclave(_old, _len__old)) {
		ms->ms__old = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len__old);
		memcpy((void*)ms->ms__old, _old, _len__old);
	} else if (_old == NULL) {
		ms->ms__old = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (_new != NULL && sgx_is_within_enclave(_new, _len__new)) {
		ms->ms__new = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len__new);
		memcpy((void*)ms->ms__new, _new, _len__new);
	} else if (_new == NULL) {
		ms->ms__new = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(167, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_remove(int* retval, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = sizeof(*pathname);

	ms_ocall_remove_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_remove_t);
	void *__tmp = NULL;

	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_remove_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_remove_t));

	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		memcpy((void*)ms->ms_pathname, pathname, _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(168, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_tempnam(char** retval, const char* dir, const char* pfx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dir = dir ? strlen(dir) + 1 : 0;
	size_t _len_pfx = pfx ? strlen(pfx) + 1 : 0;

	ms_ocall_tempnam_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_tempnam_t);
	void *__tmp = NULL;

	ocalloc_size += (dir != NULL && sgx_is_within_enclave(dir, _len_dir)) ? _len_dir : 0;
	ocalloc_size += (pfx != NULL && sgx_is_within_enclave(pfx, _len_pfx)) ? _len_pfx : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_tempnam_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_tempnam_t));

	if (dir != NULL && sgx_is_within_enclave(dir, _len_dir)) {
		ms->ms_dir = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dir);
		memcpy((void*)ms->ms_dir, dir, _len_dir);
	} else if (dir == NULL) {
		ms->ms_dir = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (pfx != NULL && sgx_is_within_enclave(pfx, _len_pfx)) {
		ms->ms_pfx = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pfx);
		memcpy((void*)ms->ms_pfx, pfx, _len_pfx);
	} else if (pfx == NULL) {
		ms->ms_pfx = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(169, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* s)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_s = s ? strlen(s) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (s != NULL && sgx_is_within_enclave(s, _len_s)) ? _len_s : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (s != NULL && sgx_is_within_enclave(s, _len_s)) {
		ms->ms_s = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_s);
		memcpy((void*)ms->ms_s, s, _len_s);
	} else if (s == NULL) {
		ms->ms_s = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(170, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fprint_string(int* retval, SGX_WRAPPER_FILE stream, const char* s)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_s = s ? strlen(s) + 1 : 0;

	ms_ocall_fprint_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fprint_string_t);
	void *__tmp = NULL;

	ocalloc_size += (s != NULL && sgx_is_within_enclave(s, _len_s)) ? _len_s : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fprint_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fprint_string_t));

	ms->ms_stream = stream;
	if (s != NULL && sgx_is_within_enclave(s, _len_s)) {
		ms->ms_s = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_s);
		memcpy((void*)ms->ms_s, s, _len_s);
	} else if (s == NULL) {
		ms->ms_s = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(171, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_eventfd(int* retval, unsigned int initval, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_eventfd_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_eventfd_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_eventfd_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_eventfd_t));

	ms->ms_initval = initval;
	ms->ms_flags = flags;
	status = sgx_ocall(172, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_socket(int* retval, int domain, int type, int protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_socket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_socket_t));

	ms->ms_domain = domain;
	ms->ms_type = type;
	ms->ms_protocol = protocol;
	status = sgx_ocall(173, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_accept(int* retval, int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = sizeof(*addr);
	size_t _len_addrlen = sizeof(*addrlen);

	ms_ocall_accept_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_accept_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;
	ocalloc_size += (addrlen != NULL && sgx_is_within_enclave(addrlen, _len_addrlen)) ? _len_addrlen : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_accept_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_accept_t));

	ms->ms_sockfd = sockfd;
	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addr);
		memset(ms->ms_addr, 0, _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (addrlen != NULL && sgx_is_within_enclave(addrlen, _len_addrlen)) {
		ms->ms_addrlen = (socklen_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addrlen);
		memcpy(ms->ms_addrlen, addrlen, _len_addrlen);
	} else if (addrlen == NULL) {
		ms->ms_addrlen = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(174, ms);

	if (retval) *retval = ms->ms_retval;
	if (addr) memcpy((void*)addr, ms->ms_addr, _len_addr);
	if (addrlen) memcpy((void*)addrlen, ms->ms_addrlen, _len_addrlen);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_connect(int* retval, int socket, const struct sockaddr* address, socklen_t address_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_address = sizeof(*address);

	ms_ocall_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_connect_t);
	void *__tmp = NULL;

	ocalloc_size += (address != NULL && sgx_is_within_enclave(address, _len_address)) ? _len_address : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_connect_t));

	ms->ms_socket = socket;
	if (address != NULL && sgx_is_within_enclave(address, _len_address)) {
		ms->ms_address = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_address);
		memcpy((void*)ms->ms_address, address, _len_address);
	} else if (address == NULL) {
		ms->ms_address = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_address_len = address_len;
	status = sgx_ocall(175, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sendto(ssize_t* retval, int sockfd, const void* buf, size_t len, int flags, const void* dest_addr, unsigned int addrlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;
	size_t _len_dest_addr = addrlen;

	ms_ocall_sendto_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sendto_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;
	ocalloc_size += (dest_addr != NULL && sgx_is_within_enclave(dest_addr, _len_dest_addr)) ? _len_dest_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sendto_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sendto_t));

	ms->ms_sockfd = sockfd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	if (dest_addr != NULL && sgx_is_within_enclave(dest_addr, _len_dest_addr)) {
		ms->ms_dest_addr = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dest_addr);
		memcpy((void*)ms->ms_dest_addr, dest_addr, _len_dest_addr);
	} else if (dest_addr == NULL) {
		ms->ms_dest_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_addrlen = addrlen;
	status = sgx_ocall(176, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_recv(ssize_t* retval, int fd, void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_recv_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_recv_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(177, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send(ssize_t* retval, int fd, const void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(178, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_socketpair(int* retval, int domain, int type, int protocol, int sv[2])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sv = 2 * sizeof(*sv);

	ms_ocall_socketpair_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_socketpair_t);
	void *__tmp = NULL;

	ocalloc_size += (sv != NULL && sgx_is_within_enclave(sv, _len_sv)) ? _len_sv : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_socketpair_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_socketpair_t));

	ms->ms_domain = domain;
	ms->ms_type = type;
	ms->ms_protocol = protocol;
	if (sv != NULL && sgx_is_within_enclave(sv, _len_sv)) {
		ms->ms_sv = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sv);
		memset(ms->ms_sv, 0, _len_sv);
	} else if (sv == NULL) {
		ms->ms_sv = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(179, ms);

	if (retval) *retval = ms->ms_retval;
	if (sv) memcpy((void*)sv, ms->ms_sv, _len_sv);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_setsockopt(int* retval, int sockfd, int level, int optname, const void* optval, unsigned int optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_optval = optlen;

	ms_ocall_setsockopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_setsockopt_t);
	void *__tmp = NULL;

	ocalloc_size += (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) ? _len_optval : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_setsockopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_setsockopt_t));

	ms->ms_sockfd = sockfd;
	ms->ms_level = level;
	ms->ms_optname = optname;
	if (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) {
		ms->ms_optval = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_optval);
		memcpy((void*)ms->ms_optval, optval, _len_optval);
	} else if (optval == NULL) {
		ms->ms_optval = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_optlen = optlen;
	status = sgx_ocall(180, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getsockopt(int* retval, int sockfd, int level, int optname, void* optval, unsigned int* optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_optval = optlen;

	ms_ocall_getsockopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getsockopt_t);
	void *__tmp = NULL;

	ocalloc_size += (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) ? _len_optval : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getsockopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getsockopt_t));

	ms->ms_sockfd = sockfd;
	ms->ms_level = level;
	ms->ms_optname = optname;
	if (optval != NULL && sgx_is_within_enclave(optval, _len_optval)) {
		ms->ms_optval = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_optval);
		memset(ms->ms_optval, 0, _len_optval);
	} else if (optval == NULL) {
		ms->ms_optval = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_optlen = SGX_CAST(unsigned int*, optlen);
	status = sgx_ocall(181, ms);

	if (retval) *retval = ms->ms_retval;
	if (optval) memcpy((void*)optval, ms->ms_optval, _len_optval);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_shutdown(int* retval, int fd, int how)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_shutdown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_shutdown_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_shutdown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_shutdown_t));

	ms->ms_fd = fd;
	ms->ms_how = how;
	status = sgx_ocall(182, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_bind(int* retval, int fd, const struct sockaddr* addr, socklen_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = len;

	ms_ocall_bind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_bind_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_bind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_bind_t));

	ms->ms_fd = fd;
	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addr);
		memcpy((void*)ms->ms_addr, addr, _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(183, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_bind_untrusted(int* retval, int fd, const struct sockaddr* addr, socklen_t len)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_bind_untrusted_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_bind_untrusted_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_bind_untrusted_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_bind_untrusted_t));

	ms->ms_fd = fd;
	ms->ms_addr = SGX_CAST(struct sockaddr*, addr);
	ms->ms_len = len;
	status = sgx_ocall(184, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_listen(int* retval, int fd, int n)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_listen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_listen_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_listen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_listen_t));

	ms->ms_fd = fd;
	ms->ms_n = n;
	status = sgx_ocall(185, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getsockname(int* retval, int fd, struct sockaddr* addr, socklen_t* len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = sizeof(*addr);
	size_t _len_len = sizeof(*len);

	ms_ocall_getsockname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getsockname_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;
	ocalloc_size += (len != NULL && sgx_is_within_enclave(len, _len_len)) ? _len_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getsockname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getsockname_t));

	ms->ms_fd = fd;
	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addr);
		memset(ms->ms_addr, 0, _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (len != NULL && sgx_is_within_enclave(len, _len_len)) {
		ms->ms_len = (socklen_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_len);
		memset(ms->ms_len, 0, _len_len);
	} else if (len == NULL) {
		ms->ms_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(186, ms);

	if (retval) *retval = ms->ms_retval;
	if (addr) memcpy((void*)addr, ms->ms_addr, _len_addr);
	if (len) memcpy((void*)len, ms->ms_len, _len_len);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getpeername(int* retval, int fd, struct sockaddr* addr, socklen_t* len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = sizeof(*addr);
	size_t _len_len = sizeof(*len);

	ms_ocall_getpeername_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getpeername_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;
	ocalloc_size += (len != NULL && sgx_is_within_enclave(len, _len_len)) ? _len_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getpeername_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getpeername_t));

	ms->ms_fd = fd;
	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (struct sockaddr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addr);
		memset(ms->ms_addr, 0, _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (len != NULL && sgx_is_within_enclave(len, _len_len)) {
		ms->ms_len = (socklen_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_len);
		memset(ms->ms_len, 0, _len_len);
	} else if (len == NULL) {
		ms->ms_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(187, ms);

	if (retval) *retval = ms->ms_retval;
	if (addr) memcpy((void*)addr, ms->ms_addr, _len_addr);
	if (len) memcpy((void*)len, ms->ms_len, _len_len);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_recvfrom(ssize_t* retval, int fd, void* untrusted_buf, size_t n, int flags, struct sockaddr* untrusted_addr, socklen_t* addr_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr_len = sizeof(*addr_len);

	ms_ocall_recvfrom_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_recvfrom_t);
	void *__tmp = NULL;

	ocalloc_size += (addr_len != NULL && sgx_is_within_enclave(addr_len, _len_addr_len)) ? _len_addr_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_recvfrom_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_recvfrom_t));

	ms->ms_fd = fd;
	ms->ms_untrusted_buf = SGX_CAST(void*, untrusted_buf);
	ms->ms_n = n;
	ms->ms_flags = flags;
	ms->ms_untrusted_addr = SGX_CAST(struct sockaddr*, untrusted_addr);
	if (addr_len != NULL && sgx_is_within_enclave(addr_len, _len_addr_len)) {
		ms->ms_addr_len = (socklen_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addr_len);
		memset(ms->ms_addr_len, 0, _len_addr_len);
	} else if (addr_len == NULL) {
		ms->ms_addr_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(188, ms);

	if (retval) *retval = ms->ms_retval;
	if (addr_len) memcpy((void*)addr_len, ms->ms_addr_len, _len_addr_len);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sendmsg(ssize_t* retval, int fd, const struct msghdr* message, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_message = sizeof(*message);

	ms_ocall_sendmsg_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sendmsg_t);
	void *__tmp = NULL;

	ocalloc_size += (message != NULL && sgx_is_within_enclave(message, _len_message)) ? _len_message : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sendmsg_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sendmsg_t));

	ms->ms_fd = fd;
	if (message != NULL && sgx_is_within_enclave(message, _len_message)) {
		ms->ms_message = (struct msghdr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_message);
		memcpy((void*)ms->ms_message, message, _len_message);
	} else if (message == NULL) {
		ms->ms_message = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(189, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_recvmsg(ssize_t* retval, int fd, struct msghdr* message, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_message = sizeof(*message);

	ms_ocall_recvmsg_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_recvmsg_t);
	void *__tmp = NULL;

	ocalloc_size += (message != NULL && sgx_is_within_enclave(message, _len_message)) ? _len_message : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_recvmsg_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_recvmsg_t));

	ms->ms_fd = fd;
	if (message != NULL && sgx_is_within_enclave(message, _len_message)) {
		ms->ms_message = (struct msghdr*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_message);
		memset(ms->ms_message, 0, _len_message);
	} else if (message == NULL) {
		ms->ms_message = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(190, ms);

	if (retval) *retval = ms->ms_retval;
	if (message) memcpy((void*)message, ms->ms_message, _len_message);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_freeaddrinfo(void* res)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_freeaddrinfo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_freeaddrinfo_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_freeaddrinfo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_freeaddrinfo_t));

	ms->ms_res = SGX_CAST(void*, res);
	status = sgx_ocall(191, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getaddrinfo(int* retval, const char* node, const char* service, const void* hints, void** res)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_node = node ? strlen(node) + 1 : 0;
	size_t _len_service = service ? strlen(service) + 1 : 0;
	size_t _len_hints = 48;
	size_t _len_res = sizeof(*res);

	ms_ocall_getaddrinfo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getaddrinfo_t);
	void *__tmp = NULL;

	ocalloc_size += (node != NULL && sgx_is_within_enclave(node, _len_node)) ? _len_node : 0;
	ocalloc_size += (service != NULL && sgx_is_within_enclave(service, _len_service)) ? _len_service : 0;
	ocalloc_size += (hints != NULL && sgx_is_within_enclave(hints, _len_hints)) ? _len_hints : 0;
	ocalloc_size += (res != NULL && sgx_is_within_enclave(res, _len_res)) ? _len_res : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getaddrinfo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getaddrinfo_t));

	if (node != NULL && sgx_is_within_enclave(node, _len_node)) {
		ms->ms_node = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_node);
		memcpy((void*)ms->ms_node, node, _len_node);
	} else if (node == NULL) {
		ms->ms_node = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (service != NULL && sgx_is_within_enclave(service, _len_service)) {
		ms->ms_service = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_service);
		memcpy((void*)ms->ms_service, service, _len_service);
	} else if (service == NULL) {
		ms->ms_service = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (hints != NULL && sgx_is_within_enclave(hints, _len_hints)) {
		ms->ms_hints = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_hints);
		memcpy((void*)ms->ms_hints, hints, _len_hints);
	} else if (hints == NULL) {
		ms->ms_hints = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (res != NULL && sgx_is_within_enclave(res, _len_res)) {
		ms->ms_res = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_res);
		memset(ms->ms_res, 0, _len_res);
	} else if (res == NULL) {
		ms->ms_res = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(192, ms);

	if (retval) *retval = ms->ms_retval;
	if (res) memcpy((void*)res, ms->ms_res, _len_res);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getaddrinfo1(int* retval, const char* node, const char* service, const void* hints, void* res)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_node = node ? strlen(node) + 1 : 0;
	size_t _len_service = service ? strlen(service) + 1 : 0;

	ms_ocall_getaddrinfo1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getaddrinfo1_t);
	void *__tmp = NULL;

	ocalloc_size += (node != NULL && sgx_is_within_enclave(node, _len_node)) ? _len_node : 0;
	ocalloc_size += (service != NULL && sgx_is_within_enclave(service, _len_service)) ? _len_service : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getaddrinfo1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getaddrinfo1_t));

	if (node != NULL && sgx_is_within_enclave(node, _len_node)) {
		ms->ms_node = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_node);
		memcpy((void*)ms->ms_node, node, _len_node);
	} else if (node == NULL) {
		ms->ms_node = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (service != NULL && sgx_is_within_enclave(service, _len_service)) {
		ms->ms_service = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_service);
		memcpy((void*)ms->ms_service, service, _len_service);
	} else if (service == NULL) {
		ms->ms_service = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_hints = SGX_CAST(void*, hints);
	ms->ms_res = SGX_CAST(void*, res);
	status = sgx_ocall(193, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sethostent(int stay_open)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sethostent_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sethostent_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sethostent_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sethostent_t));

	ms->ms_stay_open = stay_open;
	status = sgx_ocall(194, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_endhostent()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(195, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_gethostent(struct hostent** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_gethostent_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gethostent_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gethostent_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gethostent_t));

	status = sgx_ocall(196, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_gethostbyaddr(struct hostent** retval, const void* addr, socklen_t len, int type)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = len;

	ms_ocall_gethostbyaddr_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gethostbyaddr_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gethostbyaddr_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gethostbyaddr_t));

	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addr);
		memcpy((void*)ms->ms_addr, addr, _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_type = type;
	status = sgx_ocall(197, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_gethostbyname(struct hostent** retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_gethostbyname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gethostbyname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gethostbyname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gethostbyname_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(198, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_setnetent(int stay_open)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_setnetent_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_setnetent_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_setnetent_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_setnetent_t));

	ms->ms_stay_open = stay_open;
	status = sgx_ocall(199, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_endnetent()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(200, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_getnetent(struct netent** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getnetent_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getnetent_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getnetent_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getnetent_t));

	status = sgx_ocall(201, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getnetbyaddr(struct netent** retval, uint32_t net, int type)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getnetbyaddr_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getnetbyaddr_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getnetbyaddr_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getnetbyaddr_t));

	ms->ms_net = net;
	ms->ms_type = type;
	status = sgx_ocall(202, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getnetbyname(struct netent** retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_getnetbyname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getnetbyname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getnetbyname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getnetbyname_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(203, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_setservent(int stay_open)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_setservent_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_setservent_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_setservent_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_setservent_t));

	ms->ms_stay_open = stay_open;
	status = sgx_ocall(204, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_endservent()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(205, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_getservent(struct servent** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getservent_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getservent_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getservent_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getservent_t));

	status = sgx_ocall(206, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getservbyname(struct servent** retval, const char* name, const char* proto)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;
	size_t _len_proto = proto ? strlen(proto) + 1 : 0;

	ms_ocall_getservbyname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getservbyname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;
	ocalloc_size += (proto != NULL && sgx_is_within_enclave(proto, _len_proto)) ? _len_proto : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getservbyname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getservbyname_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (proto != NULL && sgx_is_within_enclave(proto, _len_proto)) {
		ms->ms_proto = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_proto);
		memcpy((void*)ms->ms_proto, proto, _len_proto);
	} else if (proto == NULL) {
		ms->ms_proto = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(207, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getservbyport(struct servent** retval, int port, const char* proto)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_proto = proto ? strlen(proto) + 1 : 0;

	ms_ocall_getservbyport_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getservbyport_t);
	void *__tmp = NULL;

	ocalloc_size += (proto != NULL && sgx_is_within_enclave(proto, _len_proto)) ? _len_proto : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getservbyport_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getservbyport_t));

	ms->ms_port = port;
	if (proto != NULL && sgx_is_within_enclave(proto, _len_proto)) {
		ms->ms_proto = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_proto);
		memcpy((void*)ms->ms_proto, proto, _len_proto);
	} else if (proto == NULL) {
		ms->ms_proto = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(208, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_setprotoent(int stay_open)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_setprotoent_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_setprotoent_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_setprotoent_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_setprotoent_t));

	ms->ms_stay_open = stay_open;
	status = sgx_ocall(209, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_endprotoent()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(210, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_getprotoent(struct protoent** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getprotoent_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getprotoent_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getprotoent_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getprotoent_t));

	status = sgx_ocall(211, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getprotobyname(struct protoent** retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_getprotobyname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getprotobyname_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getprotobyname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getprotobyname_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(212, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getprotobynumber(struct protoent** retval, int proto)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getprotobynumber_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getprotobynumber_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getprotobynumber_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getprotobynumber_t));

	ms->ms_proto = proto;
	status = sgx_ocall(213, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_gai_strerror(char** retval, int ecode)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_gai_strerror_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_gai_strerror_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_gai_strerror_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_gai_strerror_t));

	ms->ms_ecode = ecode;
	status = sgx_ocall(214, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getnameinfo(int* retval, const struct sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getnameinfo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getnameinfo_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getnameinfo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getnameinfo_t));

	ms->ms_sa = SGX_CAST(struct sockaddr*, sa);
	ms->ms_salen = salen;
	ms->ms_host = SGX_CAST(char*, host);
	ms->ms_hostlen = hostlen;
	ms->ms_serv = SGX_CAST(char*, serv);
	ms->ms_servlen = servlen;
	ms->ms_flags = flags;
	status = sgx_ocall(215, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ntohl(uint32_t* retval, uint32_t netlong)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_ntohl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ntohl_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ntohl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ntohl_t));

	ms->ms_netlong = netlong;
	status = sgx_ocall(216, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ntohs(uint16_t* retval, uint16_t netshort)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_ntohs_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ntohs_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ntohs_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ntohs_t));

	ms->ms_netshort = netshort;
	status = sgx_ocall(217, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_htonl(uint32_t* retval, uint32_t hostlong)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_htonl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_htonl_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_htonl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_htonl_t));

	ms->ms_hostlong = hostlong;
	status = sgx_ocall(218, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_htons(uint16_t* retval, uint16_t hostshort)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_htons_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_htons_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_htons_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_htons_t));

	ms->ms_hostshort = hostshort;
	status = sgx_ocall(219, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ioctl(int* retval, int fd, unsigned long int request, void* arguments)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_ioctl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ioctl_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ioctl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ioctl_t));

	ms->ms_fd = fd;
	ms->ms_request = request;
	ms->ms_arguments = SGX_CAST(void*, arguments);
	status = sgx_ocall(220, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_readv(ssize_t* retval, int __fd, const void* __iovec, int iovec_size, int __count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___iovec = __count * iovec_size;

	ms_ocall_readv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readv_t);
	void *__tmp = NULL;

	ocalloc_size += (__iovec != NULL && sgx_is_within_enclave(__iovec, _len___iovec)) ? _len___iovec : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readv_t));

	ms->ms___fd = __fd;
	if (__iovec != NULL && sgx_is_within_enclave(__iovec, _len___iovec)) {
		ms->ms___iovec = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___iovec);
		memcpy((void*)ms->ms___iovec, __iovec, _len___iovec);
	} else if (__iovec == NULL) {
		ms->ms___iovec = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_iovec_size = iovec_size;
	ms->ms___count = __count;
	status = sgx_ocall(221, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_writev(ssize_t* retval, int __fd, int iovec_id, int iovec_size, int __count)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_writev_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_writev_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_writev_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_writev_t));

	ms->ms___fd = __fd;
	ms->ms_iovec_id = iovec_id;
	ms->ms_iovec_size = iovec_size;
	ms->ms___count = __count;
	status = sgx_ocall(222, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_init_multiple_iovec_outside(int* retval, const void* __iovec, int iovec_size, int __count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___iovec = __count * iovec_size;

	ms_ocall_init_multiple_iovec_outside_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_init_multiple_iovec_outside_t);
	void *__tmp = NULL;

	ocalloc_size += (__iovec != NULL && sgx_is_within_enclave(__iovec, _len___iovec)) ? _len___iovec : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_init_multiple_iovec_outside_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_init_multiple_iovec_outside_t));

	if (__iovec != NULL && sgx_is_within_enclave(__iovec, _len___iovec)) {
		ms->ms___iovec = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___iovec);
		memcpy((void*)ms->ms___iovec, __iovec, _len___iovec);
	} else if (__iovec == NULL) {
		ms->ms___iovec = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_iovec_size = iovec_size;
	ms->ms___count = __count;
	status = sgx_ocall(223, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_copy_base_to_outside(int iovec_id, int i, const void* base, int len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_base = len;

	ms_ocall_copy_base_to_outside_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_copy_base_to_outside_t);
	void *__tmp = NULL;

	ocalloc_size += (base != NULL && sgx_is_within_enclave(base, _len_base)) ? _len_base : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_copy_base_to_outside_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_copy_base_to_outside_t));

	ms->ms_iovec_id = iovec_id;
	ms->ms_i = i;
	if (base != NULL && sgx_is_within_enclave(base, _len_base)) {
		ms->ms_base = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_base);
		memcpy((void*)ms->ms_base, base, _len_base);
	} else if (base == NULL) {
		ms->ms_base = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(224, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_free_iovec_outside(int iovec_id, int iovec_size, int __count)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_free_iovec_outside_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_free_iovec_outside_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_free_iovec_outside_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_free_iovec_outside_t));

	ms->ms_iovec_id = iovec_id;
	ms->ms_iovec_size = iovec_size;
	ms->ms___count = __count;
	status = sgx_ocall(225, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_process_vm_readv(ssize_t* retval, pid_t __pid, const struct iovec* __lvec, unsigned long int __liovcnt, const struct iovec* __rvec, unsigned long int __riovcnt, unsigned long int __flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_process_vm_readv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_process_vm_readv_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_process_vm_readv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_process_vm_readv_t));

	ms->ms___pid = __pid;
	ms->ms___lvec = SGX_CAST(struct iovec*, __lvec);
	ms->ms___liovcnt = __liovcnt;
	ms->ms___rvec = SGX_CAST(struct iovec*, __rvec);
	ms->ms___riovcnt = __riovcnt;
	ms->ms___flags = __flags;
	status = sgx_ocall(226, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_process_vm_writev(ssize_t* retval, pid_t __pid, const struct iovec* __lvec, unsigned long int __liovcnt, const struct iovec* __rvec, unsigned long int __riovcnt, unsigned long int __flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_process_vm_writev_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_process_vm_writev_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_process_vm_writev_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_process_vm_writev_t));

	ms->ms___pid = __pid;
	ms->ms___lvec = SGX_CAST(struct iovec*, __lvec);
	ms->ms___liovcnt = __liovcnt;
	ms->ms___rvec = SGX_CAST(struct iovec*, __rvec);
	ms->ms___riovcnt = __riovcnt;
	ms->ms___flags = __flags;
	status = sgx_ocall(227, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mmap(void** retval, void* __addr, size_t __len, int __prot, int __flags, int __fd, __off_t __offset)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_mmap_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mmap_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mmap_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mmap_t));

	ms->ms___addr = SGX_CAST(void*, __addr);
	ms->ms___len = __len;
	ms->ms___prot = __prot;
	ms->ms___flags = __flags;
	ms->ms___fd = __fd;
	ms->ms___offset = __offset;
	status = sgx_ocall(228, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mmap64(void** retval, void* __addr, size_t __len, int __prot, int __flags, int __fd, __off64_t __offset)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_mmap64_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mmap64_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mmap64_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mmap64_t));

	ms->ms___addr = SGX_CAST(void*, __addr);
	ms->ms___len = __len;
	ms->ms___prot = __prot;
	ms->ms___flags = __flags;
	ms->ms___fd = __fd;
	ms->ms___offset = __offset;
	status = sgx_ocall(229, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_munmap(int* retval, void* __addr, size_t __len)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_munmap_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_munmap_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_munmap_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_munmap_t));

	ms->ms___addr = SGX_CAST(void*, __addr);
	ms->ms___len = __len;
	status = sgx_ocall(230, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mprotect(int* retval, void* __addr, size_t __len, int __prot)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_mprotect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mprotect_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mprotect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mprotect_t));

	ms->ms___addr = SGX_CAST(void*, __addr);
	ms->ms___len = __len;
	ms->ms___prot = __prot;
	status = sgx_ocall(231, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_msync(int* retval, void* __addr, size_t __len, int __flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_msync_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_msync_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_msync_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_msync_t));

	ms->ms___addr = SGX_CAST(void*, __addr);
	ms->ms___len = __len;
	ms->ms___flags = __flags;
	status = sgx_ocall(232, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mlock(int* retval, const void* __addr, size_t __len)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_mlock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mlock_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mlock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mlock_t));

	ms->ms___addr = SGX_CAST(void*, __addr);
	ms->ms___len = __len;
	status = sgx_ocall(233, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_munlock(int* retval, const void* __addr, size_t __len)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_munlock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_munlock_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_munlock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_munlock_t));

	ms->ms___addr = SGX_CAST(void*, __addr);
	ms->ms___len = __len;
	status = sgx_ocall(234, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mlockall(int* retval, int __flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_mlockall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mlockall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mlockall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mlockall_t));

	ms->ms___flags = __flags;
	status = sgx_ocall(235, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_munlockall(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_munlockall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_munlockall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_munlockall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_munlockall_t));

	status = sgx_ocall(236, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mincore(int* retval, void* __start, size_t __len, unsigned char* __vec)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_mincore_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mincore_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mincore_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mincore_t));

	ms->ms___start = SGX_CAST(void*, __start);
	ms->ms___len = __len;
	ms->ms___vec = SGX_CAST(unsigned char*, __vec);
	status = sgx_ocall(237, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_shm_open(int* retval, const char* __name, int __oflag, mode_t __mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___name = __name ? strlen(__name) + 1 : 0;

	ms_ocall_shm_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_shm_open_t);
	void *__tmp = NULL;

	ocalloc_size += (__name != NULL && sgx_is_within_enclave(__name, _len___name)) ? _len___name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_shm_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_shm_open_t));

	if (__name != NULL && sgx_is_within_enclave(__name, _len___name)) {
		ms->ms___name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___name);
		memcpy((void*)ms->ms___name, __name, _len___name);
	} else if (__name == NULL) {
		ms->ms___name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___oflag = __oflag;
	ms->ms___mode = __mode;
	status = sgx_ocall(238, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_shm_unlink(int* retval, const char* __name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___name = __name ? strlen(__name) + 1 : 0;

	ms_ocall_shm_unlink_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_shm_unlink_t);
	void *__tmp = NULL;

	ocalloc_size += (__name != NULL && sgx_is_within_enclave(__name, _len___name)) ? _len___name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_shm_unlink_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_shm_unlink_t));

	if (__name != NULL && sgx_is_within_enclave(__name, _len___name)) {
		ms->ms___name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___name);
		memcpy((void*)ms->ms___name, __name, _len___name);
	} else if (__name == NULL) {
		ms->ms___name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(239, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_poll(int* retval, struct pollfd* __fds, nfds_t __nfds, int __timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_poll_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_poll_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_poll_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_poll_t));

	ms->ms___fds = SGX_CAST(struct pollfd*, __fds);
	ms->ms___nfds = __nfds;
	ms->ms___timeout = __timeout;
	status = sgx_ocall(240, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_create(int* retval, int __size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_epoll_create_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_create_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_create_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_create_t));

	ms->ms___size = __size;
	status = sgx_ocall(241, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_create1(int* retval, int __flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_epoll_create1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_create1_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_create1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_create1_t));

	ms->ms___flags = __flags;
	status = sgx_ocall(242, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_ctl(int* retval, int __epfd, int __op, int __fd, void* __event, int event_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___event = event_size;

	ms_ocall_epoll_ctl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_ctl_t);
	void *__tmp = NULL;

	ocalloc_size += (__event != NULL && sgx_is_within_enclave(__event, _len___event)) ? _len___event : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_ctl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_ctl_t));

	ms->ms___epfd = __epfd;
	ms->ms___op = __op;
	ms->ms___fd = __fd;
	if (__event != NULL && sgx_is_within_enclave(__event, _len___event)) {
		ms->ms___event = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___event);
		memcpy(ms->ms___event, __event, _len___event);
	} else if (__event == NULL) {
		ms->ms___event = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_size = event_size;
	status = sgx_ocall(243, ms);

	if (retval) *retval = ms->ms_retval;
	if (__event) memcpy((void*)__event, ms->ms___event, _len___event);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_wait(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___events = __maxevents * event_size;

	ms_ocall_epoll_wait_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_wait_t);
	void *__tmp = NULL;

	ocalloc_size += (__events != NULL && sgx_is_within_enclave(__events, _len___events)) ? _len___events : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_wait_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_wait_t));

	ms->ms___epfd = __epfd;
	if (__events != NULL && sgx_is_within_enclave(__events, _len___events)) {
		ms->ms___events = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___events);
		memset(ms->ms___events, 0, _len___events);
	} else if (__events == NULL) {
		ms->ms___events = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_size = event_size;
	ms->ms___maxevents = __maxevents;
	ms->ms___timeout = __timeout;
	status = sgx_ocall(244, ms);

	if (retval) *retval = ms->ms_retval;
	if (__events) memcpy((void*)__events, ms->ms___events, _len___events);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_wait1(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___events = __maxevents * event_size;

	ms_ocall_epoll_wait1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_wait1_t);
	void *__tmp = NULL;

	ocalloc_size += (__events != NULL && sgx_is_within_enclave(__events, _len___events)) ? _len___events : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_wait1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_wait1_t));

	ms->ms___epfd = __epfd;
	if (__events != NULL && sgx_is_within_enclave(__events, _len___events)) {
		ms->ms___events = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___events);
		memset(ms->ms___events, 0, _len___events);
	} else if (__events == NULL) {
		ms->ms___events = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_size = event_size;
	ms->ms___maxevents = __maxevents;
	ms->ms___timeout = __timeout;
	status = sgx_ocall(245, ms);

	if (retval) *retval = ms->ms_retval;
	if (__events) memcpy((void*)__events, ms->ms___events, _len___events);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_wait2(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___events = __maxevents * event_size;

	ms_ocall_epoll_wait2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_wait2_t);
	void *__tmp = NULL;

	ocalloc_size += (__events != NULL && sgx_is_within_enclave(__events, _len___events)) ? _len___events : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_wait2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_wait2_t));

	ms->ms___epfd = __epfd;
	if (__events != NULL && sgx_is_within_enclave(__events, _len___events)) {
		ms->ms___events = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___events);
		memset(ms->ms___events, 0, _len___events);
	} else if (__events == NULL) {
		ms->ms___events = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_size = event_size;
	ms->ms___maxevents = __maxevents;
	ms->ms___timeout = __timeout;
	status = sgx_ocall(246, ms);

	if (retval) *retval = ms->ms_retval;
	if (__events) memcpy((void*)__events, ms->ms___events, _len___events);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_wait3(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___events = __maxevents * event_size;

	ms_ocall_epoll_wait3_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_wait3_t);
	void *__tmp = NULL;

	ocalloc_size += (__events != NULL && sgx_is_within_enclave(__events, _len___events)) ? _len___events : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_wait3_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_wait3_t));

	ms->ms___epfd = __epfd;
	if (__events != NULL && sgx_is_within_enclave(__events, _len___events)) {
		ms->ms___events = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___events);
		memset(ms->ms___events, 0, _len___events);
	} else if (__events == NULL) {
		ms->ms___events = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_size = event_size;
	ms->ms___maxevents = __maxevents;
	ms->ms___timeout = __timeout;
	status = sgx_ocall(247, ms);

	if (retval) *retval = ms->ms_retval;
	if (__events) memcpy((void*)__events, ms->ms___events, _len___events);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_wait4(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___events = __maxevents * event_size;

	ms_ocall_epoll_wait4_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_wait4_t);
	void *__tmp = NULL;

	ocalloc_size += (__events != NULL && sgx_is_within_enclave(__events, _len___events)) ? _len___events : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_wait4_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_wait4_t));

	ms->ms___epfd = __epfd;
	if (__events != NULL && sgx_is_within_enclave(__events, _len___events)) {
		ms->ms___events = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___events);
		memset(ms->ms___events, 0, _len___events);
	} else if (__events == NULL) {
		ms->ms___events = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_size = event_size;
	ms->ms___maxevents = __maxevents;
	ms->ms___timeout = __timeout;
	status = sgx_ocall(248, ms);

	if (retval) *retval = ms->ms_retval;
	if (__events) memcpy((void*)__events, ms->ms___events, _len___events);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_wait5(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___events = __maxevents * event_size;

	ms_ocall_epoll_wait5_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_wait5_t);
	void *__tmp = NULL;

	ocalloc_size += (__events != NULL && sgx_is_within_enclave(__events, _len___events)) ? _len___events : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_wait5_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_wait5_t));

	ms->ms___epfd = __epfd;
	if (__events != NULL && sgx_is_within_enclave(__events, _len___events)) {
		ms->ms___events = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___events);
		memset(ms->ms___events, 0, _len___events);
	} else if (__events == NULL) {
		ms->ms___events = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_size = event_size;
	ms->ms___maxevents = __maxevents;
	ms->ms___timeout = __timeout;
	status = sgx_ocall(249, ms);

	if (retval) *retval = ms->ms_retval;
	if (__events) memcpy((void*)__events, ms->ms___events, _len___events);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_wait6(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___events = __maxevents * event_size;

	ms_ocall_epoll_wait6_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_wait6_t);
	void *__tmp = NULL;

	ocalloc_size += (__events != NULL && sgx_is_within_enclave(__events, _len___events)) ? _len___events : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_wait6_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_wait6_t));

	ms->ms___epfd = __epfd;
	if (__events != NULL && sgx_is_within_enclave(__events, _len___events)) {
		ms->ms___events = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___events);
		memset(ms->ms___events, 0, _len___events);
	} else if (__events == NULL) {
		ms->ms___events = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_size = event_size;
	ms->ms___maxevents = __maxevents;
	ms->ms___timeout = __timeout;
	status = sgx_ocall(250, ms);

	if (retval) *retval = ms->ms_retval;
	if (__events) memcpy((void*)__events, ms->ms___events, _len___events);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_wait7(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___events = __maxevents * event_size;

	ms_ocall_epoll_wait7_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_wait7_t);
	void *__tmp = NULL;

	ocalloc_size += (__events != NULL && sgx_is_within_enclave(__events, _len___events)) ? _len___events : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_wait7_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_wait7_t));

	ms->ms___epfd = __epfd;
	if (__events != NULL && sgx_is_within_enclave(__events, _len___events)) {
		ms->ms___events = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___events);
		memset(ms->ms___events, 0, _len___events);
	} else if (__events == NULL) {
		ms->ms___events = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_size = event_size;
	ms->ms___maxevents = __maxevents;
	ms->ms___timeout = __timeout;
	status = sgx_ocall(251, ms);

	if (retval) *retval = ms->ms_retval;
	if (__events) memcpy((void*)__events, ms->ms___events, _len___events);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_epoll_pwait(int* retval, int __epfd, void* __events, int event_size, int __maxevents, int __timeout, void* __ss, int sigset_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___events = __maxevents * event_size;
	size_t _len___ss = sigset_size;

	ms_ocall_epoll_pwait_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_epoll_pwait_t);
	void *__tmp = NULL;

	ocalloc_size += (__events != NULL && sgx_is_within_enclave(__events, _len___events)) ? _len___events : 0;
	ocalloc_size += (__ss != NULL && sgx_is_within_enclave(__ss, _len___ss)) ? _len___ss : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_epoll_pwait_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_epoll_pwait_t));

	ms->ms___epfd = __epfd;
	if (__events != NULL && sgx_is_within_enclave(__events, _len___events)) {
		ms->ms___events = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___events);
		memset(ms->ms___events, 0, _len___events);
	} else if (__events == NULL) {
		ms->ms___events = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_event_size = event_size;
	ms->ms___maxevents = __maxevents;
	ms->ms___timeout = __timeout;
	if (__ss != NULL && sgx_is_within_enclave(__ss, _len___ss)) {
		ms->ms___ss = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___ss);
		memcpy(ms->ms___ss, __ss, _len___ss);
	} else if (__ss == NULL) {
		ms->ms___ss = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_sigset_size = sigset_size;
	status = sgx_ocall(252, ms);

	if (retval) *retval = ms->ms_retval;
	if (__events) memcpy((void*)__events, ms->ms___events, _len___events);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_select(int* retval, int __nfds, fd_set* __readfds, fd_set* __writefds, fd_set* __exceptfds, void* __timeout, int tvsize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___readfds = sizeof(*__readfds);
	size_t _len___writefds = sizeof(*__writefds);
	size_t _len___exceptfds = sizeof(*__exceptfds);
	size_t _len___timeout = tvsize;

	ms_ocall_select_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_select_t);
	void *__tmp = NULL;

	ocalloc_size += (__readfds != NULL && sgx_is_within_enclave(__readfds, _len___readfds)) ? _len___readfds : 0;
	ocalloc_size += (__writefds != NULL && sgx_is_within_enclave(__writefds, _len___writefds)) ? _len___writefds : 0;
	ocalloc_size += (__exceptfds != NULL && sgx_is_within_enclave(__exceptfds, _len___exceptfds)) ? _len___exceptfds : 0;
	ocalloc_size += (__timeout != NULL && sgx_is_within_enclave(__timeout, _len___timeout)) ? _len___timeout : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_select_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_select_t));

	ms->ms___nfds = __nfds;
	if (__readfds != NULL && sgx_is_within_enclave(__readfds, _len___readfds)) {
		ms->ms___readfds = (fd_set*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___readfds);
		memcpy(ms->ms___readfds, __readfds, _len___readfds);
	} else if (__readfds == NULL) {
		ms->ms___readfds = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (__writefds != NULL && sgx_is_within_enclave(__writefds, _len___writefds)) {
		ms->ms___writefds = (fd_set*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___writefds);
		memcpy(ms->ms___writefds, __writefds, _len___writefds);
	} else if (__writefds == NULL) {
		ms->ms___writefds = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (__exceptfds != NULL && sgx_is_within_enclave(__exceptfds, _len___exceptfds)) {
		ms->ms___exceptfds = (fd_set*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___exceptfds);
		memcpy(ms->ms___exceptfds, __exceptfds, _len___exceptfds);
	} else if (__exceptfds == NULL) {
		ms->ms___exceptfds = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (__timeout != NULL && sgx_is_within_enclave(__timeout, _len___timeout)) {
		ms->ms___timeout = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___timeout);
		memcpy(ms->ms___timeout, __timeout, _len___timeout);
	} else if (__timeout == NULL) {
		ms->ms___timeout = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_tvsize = tvsize;
	status = sgx_ocall(253, ms);

	if (retval) *retval = ms->ms_retval;
	if (__readfds) memcpy((void*)__readfds, ms->ms___readfds, _len___readfds);
	if (__writefds) memcpy((void*)__writefds, ms->ms___writefds, _len___writefds);
	if (__exceptfds) memcpy((void*)__exceptfds, ms->ms___exceptfds, _len___exceptfds);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sendfile(ssize_t* retval, int out_fd, int in_fd, off_t* offset, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_offset = count;

	ms_ocall_sendfile_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sendfile_t);
	void *__tmp = NULL;

	ocalloc_size += (offset != NULL && sgx_is_within_enclave(offset, _len_offset)) ? _len_offset : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sendfile_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sendfile_t));

	ms->ms_out_fd = out_fd;
	ms->ms_in_fd = in_fd;
	if (offset != NULL && sgx_is_within_enclave(offset, _len_offset)) {
		ms->ms_offset = (off_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_offset);
		memcpy(ms->ms_offset, offset, _len_offset);
	} else if (offset == NULL) {
		ms->ms_offset = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(254, ms);

	if (retval) *retval = ms->ms_retval;
	if (offset) memcpy((void*)offset, ms->ms_offset, _len_offset);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_waitpid(__pid_t* retval, __pid_t __pid, int* __stat_loc, int __options)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___stat_loc = sizeof(*__stat_loc);

	ms_ocall_waitpid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_waitpid_t);
	void *__tmp = NULL;

	ocalloc_size += (__stat_loc != NULL && sgx_is_within_enclave(__stat_loc, _len___stat_loc)) ? _len___stat_loc : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_waitpid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_waitpid_t));

	ms->ms___pid = __pid;
	if (__stat_loc != NULL && sgx_is_within_enclave(__stat_loc, _len___stat_loc)) {
		ms->ms___stat_loc = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___stat_loc);
		memset(ms->ms___stat_loc, 0, _len___stat_loc);
	} else if (__stat_loc == NULL) {
		ms->ms___stat_loc = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___options = __options;
	status = sgx_ocall(255, ms);

	if (retval) *retval = ms->ms_retval;
	if (__stat_loc) memcpy((void*)__stat_loc, ms->ms___stat_loc, _len___stat_loc);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_waitid(int* retval, idtype_t __idtype, __id_t __id, siginfo_t* __infop, int __options)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___infop = sizeof(*__infop);

	ms_ocall_waitid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_waitid_t);
	void *__tmp = NULL;

	ocalloc_size += (__infop != NULL && sgx_is_within_enclave(__infop, _len___infop)) ? _len___infop : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_waitid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_waitid_t));

	ms->ms___idtype = __idtype;
	ms->ms___id = __id;
	if (__infop != NULL && sgx_is_within_enclave(__infop, _len___infop)) {
		ms->ms___infop = (siginfo_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___infop);
		memcpy(ms->ms___infop, __infop, _len___infop);
	} else if (__infop == NULL) {
		ms->ms___infop = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___options = __options;
	status = sgx_ocall(256, ms);

	if (retval) *retval = ms->ms_retval;
	if (__infop) memcpy((void*)__infop, ms->ms___infop, _len___infop);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_wait(pid_t* retval, int* wstatus)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_wstatus = sizeof(*wstatus);

	ms_ocall_wait_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_wait_t);
	void *__tmp = NULL;

	ocalloc_size += (wstatus != NULL && sgx_is_within_enclave(wstatus, _len_wstatus)) ? _len_wstatus : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_wait_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_wait_t));

	if (wstatus != NULL && sgx_is_within_enclave(wstatus, _len_wstatus)) {
		ms->ms_wstatus = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_wstatus);
		memset(ms->ms_wstatus, 0, _len_wstatus);
	} else if (wstatus == NULL) {
		ms->ms_wstatus = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(257, ms);

	if (retval) *retval = ms->ms_retval;
	if (wstatus) memcpy((void*)wstatus, ms->ms_wstatus, _len_wstatus);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_stat(int* retval, const char* path, struct stat* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = sizeof(*buf);

	ms_ocall_stat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_stat_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_stat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_stat_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (struct stat*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(258, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fstat(int* retval, int fd, struct stat* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = sizeof(*buf);

	ms_ocall_fstat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fstat_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fstat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fstat_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (struct stat*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(259, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_lstat(int* retval, const char* path, struct stat* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = sizeof(*buf);

	ms_ocall_lstat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_lstat_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_lstat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_lstat_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (struct stat*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(260, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_chmod(int* retval, const char* file, mode_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file = file ? strlen(file) + 1 : 0;

	ms_ocall_chmod_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_chmod_t);
	void *__tmp = NULL;

	ocalloc_size += (file != NULL && sgx_is_within_enclave(file, _len_file)) ? _len_file : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_chmod_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_chmod_t));

	if (file != NULL && sgx_is_within_enclave(file, _len_file)) {
		ms->ms_file = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_file);
		memcpy((void*)ms->ms_file, file, _len_file);
	} else if (file == NULL) {
		ms->ms_file = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(261, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fchmod(int* retval, int fd, mode_t mode)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fchmod_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fchmod_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fchmod_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fchmod_t));

	ms->ms_fd = fd;
	ms->ms_mode = mode;
	status = sgx_ocall(262, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fchmodat(int* retval, int fd, const char* file, mode_t mode, int flag)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file = file ? strlen(file) + 1 : 0;

	ms_ocall_fchmodat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fchmodat_t);
	void *__tmp = NULL;

	ocalloc_size += (file != NULL && sgx_is_within_enclave(file, _len_file)) ? _len_file : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fchmodat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fchmodat_t));

	ms->ms_fd = fd;
	if (file != NULL && sgx_is_within_enclave(file, _len_file)) {
		ms->ms_file = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_file);
		memcpy((void*)ms->ms_file, file, _len_file);
	} else if (file == NULL) {
		ms->ms_file = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	ms->ms_flag = flag;
	status = sgx_ocall(263, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_umask(mode_t* retval, mode_t mask)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_umask_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_umask_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_umask_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_umask_t));

	ms->ms_mask = mask;
	status = sgx_ocall(264, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mkdir(int* retval, const char* path, mode_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_mkdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mkdir_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mkdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mkdir_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(265, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mkdirat(int* retval, int fd, const char* path, mode_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_mkdirat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mkdirat_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mkdirat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mkdirat_t));

	ms->ms_fd = fd;
	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(266, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mkfifo(int* retval, const char* path, mode_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_mkfifo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mkfifo_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mkfifo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mkfifo_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(267, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mkfifoat(int* retval, int fd, const char* path, mode_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_mkfifoat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mkfifoat_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mkfifoat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mkfifoat_t));

	ms->ms_fd = fd;
	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(268, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_utime(int* retval, const char* filename, const struct utimbuf* times)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_times = sizeof(*times);

	ms_ocall_utime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_utime_t);
	void *__tmp = NULL;

	ocalloc_size += (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) ? _len_filename : 0;
	ocalloc_size += (times != NULL && sgx_is_within_enclave(times, _len_times)) ? _len_times : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_utime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_utime_t));

	if (filename != NULL && sgx_is_within_enclave(filename, _len_filename)) {
		ms->ms_filename = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_filename);
		memcpy((void*)ms->ms_filename, filename, _len_filename);
	} else if (filename == NULL) {
		ms->ms_filename = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (times != NULL && sgx_is_within_enclave(times, _len_times)) {
		ms->ms_times = (struct utimbuf*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_times);
		memcpy((void*)ms->ms_times, times, _len_times);
	} else if (times == NULL) {
		ms->ms_times = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(269, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_opendir(void** retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_ocall_opendir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_opendir_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_opendir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_opendir_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy((void*)ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(270, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fdopendir(void** retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fdopendir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fdopendir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fdopendir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fdopendir_t));

	ms->ms_fd = fd;
	status = sgx_ocall(271, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_closedir(int* retval, void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_closedir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_closedir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_closedir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_closedir_t));

	ms->ms_dirp = SGX_CAST(void*, dirp);
	status = sgx_ocall(272, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_readdir(struct dirent** retval, void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_readdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readdir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readdir_t));

	ms->ms_dirp = SGX_CAST(void*, dirp);
	status = sgx_ocall(273, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_readdir_r(int* retval, void* dirp, struct dirent* entry, struct dirent** result)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_readdir_r_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readdir_r_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readdir_r_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readdir_r_t));

	ms->ms_dirp = SGX_CAST(void*, dirp);
	ms->ms_entry = SGX_CAST(struct dirent*, entry);
	ms->ms_result = SGX_CAST(struct dirent**, result);
	status = sgx_ocall(274, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_rewinddir(void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_rewinddir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_rewinddir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_rewinddir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_rewinddir_t));

	ms->ms_dirp = SGX_CAST(void*, dirp);
	status = sgx_ocall(275, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_seekdir(void* dirp, long int pos)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_seekdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_seekdir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_seekdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_seekdir_t));

	ms->ms_dirp = SGX_CAST(void*, dirp);
	ms->ms_pos = pos;
	status = sgx_ocall(276, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_telldir(long int* retval, void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_telldir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_telldir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_telldir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_telldir_t));

	ms->ms_dirp = SGX_CAST(void*, dirp);
	status = sgx_ocall(277, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_dirfd(int* retval, void* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_dirfd_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_dirfd_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_dirfd_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_dirfd_t));

	ms->ms_dirp = SGX_CAST(void*, dirp);
	status = sgx_ocall(278, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_alphasort(int* retval, const struct dirent** e1, const struct dirent** e2)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_alphasort_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_alphasort_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_alphasort_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_alphasort_t));

	ms->ms_e1 = SGX_CAST(struct dirent**, e1);
	ms->ms_e2 = SGX_CAST(struct dirent**, e2);
	status = sgx_ocall(279, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getdirentries(ssize_t* retval, int fd, char* buf, size_t nbytes, off_t* basep)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_ocall_getdirentries_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getdirentries_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getdirentries_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getdirentries_t));

	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	ms->ms_basep = SGX_CAST(off_t*, basep);
	status = sgx_ocall(280, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_versionsort(int* retval, const struct dirent** e1, const struct dirent** e2)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_versionsort_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_versionsort_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_versionsort_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_versionsort_t));

	ms->ms_e1 = SGX_CAST(struct dirent**, e1);
	ms->ms_e2 = SGX_CAST(struct dirent**, e2);
	status = sgx_ocall(281, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_prlimit(int* retval, __pid_t pid, enum __rlimit_resource resource, const struct rlimit* new_limit, struct rlimit* old_limit)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_new_limit = sizeof(*new_limit);
	size_t _len_old_limit = sizeof(*old_limit);

	ms_ocall_prlimit_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_prlimit_t);
	void *__tmp = NULL;

	ocalloc_size += (new_limit != NULL && sgx_is_within_enclave(new_limit, _len_new_limit)) ? _len_new_limit : 0;
	ocalloc_size += (old_limit != NULL && sgx_is_within_enclave(old_limit, _len_old_limit)) ? _len_old_limit : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_prlimit_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_prlimit_t));

	ms->ms_pid = pid;
	ms->ms_resource = resource;
	if (new_limit != NULL && sgx_is_within_enclave(new_limit, _len_new_limit)) {
		ms->ms_new_limit = (struct rlimit*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_new_limit);
		memcpy((void*)ms->ms_new_limit, new_limit, _len_new_limit);
	} else if (new_limit == NULL) {
		ms->ms_new_limit = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (old_limit != NULL && sgx_is_within_enclave(old_limit, _len_old_limit)) {
		ms->ms_old_limit = (struct rlimit*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_old_limit);
		memset(ms->ms_old_limit, 0, _len_old_limit);
	} else if (old_limit == NULL) {
		ms->ms_old_limit = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(282, ms);

	if (retval) *retval = ms->ms_retval;
	if (old_limit) memcpy((void*)old_limit, ms->ms_old_limit, _len_old_limit);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getrlimit(int* retval, int resource, struct rlimit* rlim)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_rlim = sizeof(*rlim);

	ms_ocall_getrlimit_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getrlimit_t);
	void *__tmp = NULL;

	ocalloc_size += (rlim != NULL && sgx_is_within_enclave(rlim, _len_rlim)) ? _len_rlim : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getrlimit_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getrlimit_t));

	ms->ms_resource = resource;
	if (rlim != NULL && sgx_is_within_enclave(rlim, _len_rlim)) {
		ms->ms_rlim = (struct rlimit*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_rlim);
		memset(ms->ms_rlim, 0, _len_rlim);
	} else if (rlim == NULL) {
		ms->ms_rlim = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(283, ms);

	if (retval) *retval = ms->ms_retval;
	if (rlim) memcpy((void*)rlim, ms->ms_rlim, _len_rlim);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_setrlimit(int* retval, int resource, const struct rlimit* rlim)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_rlim = sizeof(*rlim);

	ms_ocall_setrlimit_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_setrlimit_t);
	void *__tmp = NULL;

	ocalloc_size += (rlim != NULL && sgx_is_within_enclave(rlim, _len_rlim)) ? _len_rlim : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_setrlimit_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_setrlimit_t));

	ms->ms_resource = resource;
	if (rlim != NULL && sgx_is_within_enclave(rlim, _len_rlim)) {
		ms->ms_rlim = (struct rlimit*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_rlim);
		memcpy((void*)ms->ms_rlim, rlim, _len_rlim);
	} else if (rlim == NULL) {
		ms->ms_rlim = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(284, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_inet_addr(in_addr_t* retval, const char* cp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cp = cp ? strlen(cp) + 1 : 0;

	ms_ocall_inet_addr_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_inet_addr_t);
	void *__tmp = NULL;

	ocalloc_size += (cp != NULL && sgx_is_within_enclave(cp, _len_cp)) ? _len_cp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_inet_addr_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_inet_addr_t));

	if (cp != NULL && sgx_is_within_enclave(cp, _len_cp)) {
		ms->ms_cp = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cp);
		memcpy((void*)ms->ms_cp, cp, _len_cp);
	} else if (cp == NULL) {
		ms->ms_cp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(285, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_inet_lnaof(in_addr_t* retval, struct in_addr in)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_inet_lnaof_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_inet_lnaof_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_inet_lnaof_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_inet_lnaof_t));

	ms->ms_in = in;
	status = sgx_ocall(286, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_inet_makeaddr(struct in_addr* retval, in_addr_t net, in_addr_t host)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_inet_makeaddr_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_inet_makeaddr_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_inet_makeaddr_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_inet_makeaddr_t));

	ms->ms_net = net;
	ms->ms_host = host;
	status = sgx_ocall(287, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_inet_netof(in_addr_t* retval, struct in_addr in)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_inet_netof_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_inet_netof_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_inet_netof_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_inet_netof_t));

	ms->ms_in = in;
	status = sgx_ocall(288, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_inet_network(in_addr_t* retval, const char* cp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cp = cp ? strlen(cp) + 1 : 0;

	ms_ocall_inet_network_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_inet_network_t);
	void *__tmp = NULL;

	ocalloc_size += (cp != NULL && sgx_is_within_enclave(cp, _len_cp)) ? _len_cp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_inet_network_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_inet_network_t));

	if (cp != NULL && sgx_is_within_enclave(cp, _len_cp)) {
		ms->ms_cp = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cp);
		memcpy((void*)ms->ms_cp, cp, _len_cp);
	} else if (cp == NULL) {
		ms->ms_cp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(289, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_inet_ntoa(char** retval, struct in_addr in)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_inet_ntoa_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_inet_ntoa_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_inet_ntoa_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_inet_ntoa_t));

	ms->ms_in = in;
	status = sgx_ocall(290, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_inet_pton(int* retval, int af, const char* cp, void* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cp = cp ? strlen(cp) + 1 : 0;

	ms_ocall_inet_pton_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_inet_pton_t);
	void *__tmp = NULL;

	ocalloc_size += (cp != NULL && sgx_is_within_enclave(cp, _len_cp)) ? _len_cp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_inet_pton_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_inet_pton_t));

	ms->ms_af = af;
	if (cp != NULL && sgx_is_within_enclave(cp, _len_cp)) {
		ms->ms_cp = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cp);
		memcpy((void*)ms->ms_cp, cp, _len_cp);
	} else if (cp == NULL) {
		ms->ms_cp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_buf = SGX_CAST(void*, buf);
	status = sgx_ocall(291, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_inet_ntop(char** retval, int af, const void* cp, char* buf, socklen_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_inet_ntop_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_inet_ntop_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_inet_ntop_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_inet_ntop_t));

	ms->ms_af = af;
	ms->ms_cp = SGX_CAST(void*, cp);
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy(ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(292, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sysctl(int* retval, int* name, int nlen, void* oldval, size_t* oldlenp, void* newval, size_t newlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = nlen;
	size_t _len_newval = newlen;

	ms_ocall_sysctl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sysctl_t);
	void *__tmp = NULL;

	ocalloc_size += (name != NULL && sgx_is_within_enclave(name, _len_name)) ? _len_name : 0;
	ocalloc_size += (newval != NULL && sgx_is_within_enclave(newval, _len_newval)) ? _len_newval : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sysctl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sysctl_t));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		ms->ms_name = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_name);
		memcpy(ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nlen = nlen;
	ms->ms_oldval = SGX_CAST(void*, oldval);
	ms->ms_oldlenp = SGX_CAST(size_t*, oldlenp);
	if (newval != NULL && sgx_is_within_enclave(newval, _len_newval)) {
		ms->ms_newval = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_newval);
		memcpy(ms->ms_newval, newval, _len_newval);
	} else if (newval == NULL) {
		ms->ms_newval = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_newlen = newlen;
	status = sgx_ocall(293, ms);

	if (retval) *retval = ms->ms_retval;
	if (name) memcpy((void*)name, ms->ms_name, _len_name);
	if (newval) memcpy((void*)newval, ms->ms_newval, _len_newval);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sigemptyset(int* retval, sigset_t* set)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_set = sizeof(*set);

	ms_ocall_sigemptyset_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sigemptyset_t);
	void *__tmp = NULL;

	ocalloc_size += (set != NULL && sgx_is_within_enclave(set, _len_set)) ? _len_set : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sigemptyset_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sigemptyset_t));

	if (set != NULL && sgx_is_within_enclave(set, _len_set)) {
		ms->ms_set = (sigset_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_set);
		memcpy(ms->ms_set, set, _len_set);
	} else if (set == NULL) {
		ms->ms_set = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(294, ms);

	if (retval) *retval = ms->ms_retval;
	if (set) memcpy((void*)set, ms->ms_set, _len_set);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sigfillset(int* retval, sigset_t* set)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_set = sizeof(*set);

	ms_ocall_sigfillset_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sigfillset_t);
	void *__tmp = NULL;

	ocalloc_size += (set != NULL && sgx_is_within_enclave(set, _len_set)) ? _len_set : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sigfillset_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sigfillset_t));

	if (set != NULL && sgx_is_within_enclave(set, _len_set)) {
		ms->ms_set = (sigset_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_set);
		memcpy(ms->ms_set, set, _len_set);
	} else if (set == NULL) {
		ms->ms_set = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(295, ms);

	if (retval) *retval = ms->ms_retval;
	if (set) memcpy((void*)set, ms->ms_set, _len_set);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sigaddset(int* retval, sigset_t* set, int signo)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_set = sizeof(*set);

	ms_ocall_sigaddset_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sigaddset_t);
	void *__tmp = NULL;

	ocalloc_size += (set != NULL && sgx_is_within_enclave(set, _len_set)) ? _len_set : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sigaddset_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sigaddset_t));

	if (set != NULL && sgx_is_within_enclave(set, _len_set)) {
		ms->ms_set = (sigset_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_set);
		memcpy(ms->ms_set, set, _len_set);
	} else if (set == NULL) {
		ms->ms_set = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_signo = signo;
	status = sgx_ocall(296, ms);

	if (retval) *retval = ms->ms_retval;
	if (set) memcpy((void*)set, ms->ms_set, _len_set);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sigdelset(int* retval, sigset_t* set, int signo)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_set = sizeof(*set);

	ms_ocall_sigdelset_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sigdelset_t);
	void *__tmp = NULL;

	ocalloc_size += (set != NULL && sgx_is_within_enclave(set, _len_set)) ? _len_set : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sigdelset_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sigdelset_t));

	if (set != NULL && sgx_is_within_enclave(set, _len_set)) {
		ms->ms_set = (sigset_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_set);
		memcpy(ms->ms_set, set, _len_set);
	} else if (set == NULL) {
		ms->ms_set = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_signo = signo;
	status = sgx_ocall(297, ms);

	if (retval) *retval = ms->ms_retval;
	if (set) memcpy((void*)set, ms->ms_set, _len_set);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sigismember(int* retval, const sigset_t* set, int signo)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_set = sizeof(*set);

	ms_ocall_sigismember_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sigismember_t);
	void *__tmp = NULL;

	ocalloc_size += (set != NULL && sgx_is_within_enclave(set, _len_set)) ? _len_set : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sigismember_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sigismember_t));

	if (set != NULL && sgx_is_within_enclave(set, _len_set)) {
		ms->ms_set = (sigset_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_set);
		memcpy((void*)ms->ms_set, set, _len_set);
	} else if (set == NULL) {
		ms->ms_set = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_signo = signo;
	status = sgx_ocall(298, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sigsuspend(int* retval, const sigset_t* set)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_set = sizeof(*set);

	ms_ocall_sigsuspend_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sigsuspend_t);
	void *__tmp = NULL;

	ocalloc_size += (set != NULL && sgx_is_within_enclave(set, _len_set)) ? _len_set : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sigsuspend_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sigsuspend_t));

	if (set != NULL && sgx_is_within_enclave(set, _len_set)) {
		ms->ms_set = (sigset_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_set);
		memcpy((void*)ms->ms_set, set, _len_set);
	} else if (set == NULL) {
		ms->ms_set = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(299, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sigaction(int* retval, int sig, const struct sigaction* act, struct sigaction* oact)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_act = sizeof(*act);
	size_t _len_oact = sizeof(*oact);

	ms_ocall_sigaction_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sigaction_t);
	void *__tmp = NULL;

	ocalloc_size += (act != NULL && sgx_is_within_enclave(act, _len_act)) ? _len_act : 0;
	ocalloc_size += (oact != NULL && sgx_is_within_enclave(oact, _len_oact)) ? _len_oact : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sigaction_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sigaction_t));

	ms->ms_sig = sig;
	if (act != NULL && sgx_is_within_enclave(act, _len_act)) {
		ms->ms_act = (struct sigaction*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_act);
		memcpy((void*)ms->ms_act, act, _len_act);
	} else if (act == NULL) {
		ms->ms_act = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (oact != NULL && sgx_is_within_enclave(oact, _len_oact)) {
		ms->ms_oact = (struct sigaction*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_oact);
		memcpy(ms->ms_oact, oact, _len_oact);
	} else if (oact == NULL) {
		ms->ms_oact = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(300, ms);

	if (retval) *retval = ms->ms_retval;
	if (oact) memcpy((void*)oact, ms->ms_oact, _len_oact);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sigpending(int* retval, sigset_t* set)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_set = sizeof(*set);

	ms_ocall_sigpending_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sigpending_t);
	void *__tmp = NULL;

	ocalloc_size += (set != NULL && sgx_is_within_enclave(set, _len_set)) ? _len_set : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sigpending_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sigpending_t));

	if (set != NULL && sgx_is_within_enclave(set, _len_set)) {
		ms->ms_set = (sigset_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_set);
		memcpy(ms->ms_set, set, _len_set);
	} else if (set == NULL) {
		ms->ms_set = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(301, ms);

	if (retval) *retval = ms->ms_retval;
	if (set) memcpy((void*)set, ms->ms_set, _len_set);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sigwait(int* retval, const sigset_t* set, int* sig)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_set = sizeof(*set);
	size_t _len_sig = sizeof(*sig);

	ms_ocall_sigwait_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sigwait_t);
	void *__tmp = NULL;

	ocalloc_size += (set != NULL && sgx_is_within_enclave(set, _len_set)) ? _len_set : 0;
	ocalloc_size += (sig != NULL && sgx_is_within_enclave(sig, _len_sig)) ? _len_sig : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sigwait_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sigwait_t));

	if (set != NULL && sgx_is_within_enclave(set, _len_set)) {
		ms->ms_set = (sigset_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_set);
		memcpy((void*)ms->ms_set, set, _len_set);
	} else if (set == NULL) {
		ms->ms_set = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (sig != NULL && sgx_is_within_enclave(sig, _len_sig)) {
		ms->ms_sig = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sig);
		memcpy(ms->ms_sig, sig, _len_sig);
	} else if (sig == NULL) {
		ms->ms_sig = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(302, ms);

	if (retval) *retval = ms->ms_retval;
	if (sig) memcpy((void*)sig, ms->ms_sig, _len_sig);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_signal_generic(__sighandler_t* retval, int __sig, __sighandler_t __handler)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_signal_generic_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_signal_generic_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_signal_generic_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_signal_generic_t));

	ms->ms___sig = __sig;
	ms->ms___handler = __handler;
	status = sgx_ocall(303, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sigaction_generic(int* retval, int sig, struct sigaction* act, struct sigaction* oact)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_act = sizeof(*act);
	size_t _len_oact = sizeof(*oact);

	ms_ocall_sigaction_generic_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sigaction_generic_t);
	void *__tmp = NULL;

	ocalloc_size += (act != NULL && sgx_is_within_enclave(act, _len_act)) ? _len_act : 0;
	ocalloc_size += (oact != NULL && sgx_is_within_enclave(oact, _len_oact)) ? _len_oact : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sigaction_generic_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sigaction_generic_t));

	ms->ms_sig = sig;
	if (act != NULL && sgx_is_within_enclave(act, _len_act)) {
		ms->ms_act = (struct sigaction*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_act);
		memcpy(ms->ms_act, act, _len_act);
	} else if (act == NULL) {
		ms->ms_act = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (oact != NULL && sgx_is_within_enclave(oact, _len_oact)) {
		ms->ms_oact = (struct sigaction*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_oact);
		memcpy(ms->ms_oact, oact, _len_oact);
	} else if (oact == NULL) {
		ms->ms_oact = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(304, ms);

	if (retval) *retval = ms->ms_retval;
	if (oact) memcpy((void*)oact, ms->ms_oact, _len_oact);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_signal(__sighandler_t* retval, int __sig, __sighandler_t __handler)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_signal_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_signal_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_signal_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_signal_t));

	ms->ms___sig = __sig;
	ms->ms___handler = __handler;
	status = sgx_ocall(305, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_raise(int* retval, int sig)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_raise_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_raise_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_raise_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_raise_t));

	ms->ms_sig = sig;
	status = sgx_ocall(306, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_kill(int* retval, pid_t pid, int sig)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_kill_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_kill_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_kill_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_kill_t));

	ms->ms_pid = pid;
	ms->ms_sig = sig;
	status = sgx_ocall(307, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pmap_set(int* retval, unsigned long int prognum, unsigned long int versnum, unsigned int protocol, unsigned short int port)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pmap_set_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pmap_set_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pmap_set_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pmap_set_t));

	ms->ms_prognum = prognum;
	ms->ms_versnum = versnum;
	ms->ms_protocol = protocol;
	ms->ms_port = port;
	status = sgx_ocall(308, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pmap_unset(int* retval, unsigned long int prognum, unsigned long int versnum)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pmap_unset_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pmap_unset_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pmap_unset_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pmap_unset_t));

	ms->ms_prognum = prognum;
	ms->ms_versnum = versnum;
	status = sgx_ocall(309, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pmap_getport(unsigned short int* retval, struct sockaddr_in* addr, unsigned long int prognum, unsigned long int versnum, unsigned int protocol)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = sizeof(*addr);

	ms_ocall_pmap_getport_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pmap_getport_t);
	void *__tmp = NULL;

	ocalloc_size += (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) ? _len_addr : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pmap_getport_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pmap_getport_t));

	if (addr != NULL && sgx_is_within_enclave(addr, _len_addr)) {
		ms->ms_addr = (struct sockaddr_in*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_addr);
		memcpy(ms->ms_addr, addr, _len_addr);
	} else if (addr == NULL) {
		ms->ms_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_prognum = prognum;
	ms->ms_versnum = versnum;
	ms->ms_protocol = protocol;
	status = sgx_ocall(310, ms);

	if (retval) *retval = ms->ms_retval;
	if (addr) memcpy((void*)addr, ms->ms_addr, _len_addr);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_svcudp_create(SVCXPRT** retval, int __sock)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_svcudp_create_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_svcudp_create_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_svcudp_create_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_svcudp_create_t));

	ms->ms___sock = __sock;
	status = sgx_ocall(311, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_svc_run()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(312, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_svctcp_create(SVCXPRT** retval, int __sock, u_int __sendsize, u_int __recvsize)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_svctcp_create_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_svctcp_create_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_svctcp_create_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_svctcp_create_t));

	ms->ms___sock = __sock;
	ms->ms___sendsize = __sendsize;
	ms->ms___recvsize = __recvsize;
	status = sgx_ocall(313, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_svc_register(bool_t* retval, SVCXPRT* __xprt, rpcprog_t __prog, rpcvers_t __vers, __dispatch_fn_t __dispatch, rpcprot_t __protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_svc_register_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_svc_register_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_svc_register_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_svc_register_t));

	ms->ms___xprt = SGX_CAST(SVCXPRT*, __xprt);
	ms->ms___prog = __prog;
	ms->ms___vers = __vers;
	ms->ms___dispatch = __dispatch;
	ms->ms___protocol = __protocol;
	status = sgx_ocall(314, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_svc_register_generic(bool_t* retval, SVCXPRT* __xprt, rpcprog_t __prog, rpcvers_t __vers, __dispatch_fn_t __dispatch, rpcprot_t __protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_svc_register_generic_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_svc_register_generic_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_svc_register_generic_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_svc_register_generic_t));

	ms->ms___xprt = SGX_CAST(SVCXPRT*, __xprt);
	ms->ms___prog = __prog;
	ms->ms___vers = __vers;
	ms->ms___dispatch = __dispatch;
	ms->ms___protocol = __protocol;
	status = sgx_ocall(315, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_clnt_create(CLIENT** retval, const char* __host, unsigned long int __prog, unsigned long int __vers, const char* __prot)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___host = __host ? strlen(__host) + 1 : 0;
	size_t _len___prot = __prot ? strlen(__prot) + 1 : 0;

	ms_ocall_clnt_create_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_clnt_create_t);
	void *__tmp = NULL;

	ocalloc_size += (__host != NULL && sgx_is_within_enclave(__host, _len___host)) ? _len___host : 0;
	ocalloc_size += (__prot != NULL && sgx_is_within_enclave(__prot, _len___prot)) ? _len___prot : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_clnt_create_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_clnt_create_t));

	if (__host != NULL && sgx_is_within_enclave(__host, _len___host)) {
		ms->ms___host = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___host);
		memcpy((void*)ms->ms___host, __host, _len___host);
	} else if (__host == NULL) {
		ms->ms___host = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___prog = __prog;
	ms->ms___vers = __vers;
	if (__prot != NULL && sgx_is_within_enclave(__prot, _len___prot)) {
		ms->ms___prot = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___prot);
		memcpy((void*)ms->ms___prot, __prot, _len___prot);
	} else if (__prot == NULL) {
		ms->ms___prot = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(316, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_clnt_perror(CLIENT* __clnt, const char* __msg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___msg = __msg ? strlen(__msg) + 1 : 0;

	ms_ocall_clnt_perror_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_clnt_perror_t);
	void *__tmp = NULL;

	ocalloc_size += (__msg != NULL && sgx_is_within_enclave(__msg, _len___msg)) ? _len___msg : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_clnt_perror_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_clnt_perror_t));

	ms->ms___clnt = SGX_CAST(CLIENT*, __clnt);
	if (__msg != NULL && sgx_is_within_enclave(__msg, _len___msg)) {
		ms->ms___msg = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___msg);
		memcpy((void*)ms->ms___msg, __msg, _len___msg);
	} else if (__msg == NULL) {
		ms->ms___msg = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(317, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_clnt_pcreateerror(const char* __msg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___msg = __msg ? strlen(__msg) + 1 : 0;

	ms_ocall_clnt_pcreateerror_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_clnt_pcreateerror_t);
	void *__tmp = NULL;

	ocalloc_size += (__msg != NULL && sgx_is_within_enclave(__msg, _len___msg)) ? _len___msg : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_clnt_pcreateerror_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_clnt_pcreateerror_t));

	if (__msg != NULL && sgx_is_within_enclave(__msg, _len___msg)) {
		ms->ms___msg = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___msg);
		memcpy((void*)ms->ms___msg, __msg, _len___msg);
	} else if (__msg == NULL) {
		ms->ms___msg = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(318, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_callrpc(int* retval, const char* __host, unsigned long int __prognum, unsigned long int __versnum, unsigned long int __procnum, xdrproc_t __inproc, const char* __in, xdrproc_t __outproc, char* __out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len___host = __host ? strlen(__host) + 1 : 0;
	size_t _len___in = __in ? strlen(__in) + 1 : 0;
	size_t _len___out = __out ? strlen(__out) + 1 : 0;

	ms_ocall_callrpc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_callrpc_t);
	void *__tmp = NULL;

	ocalloc_size += (__host != NULL && sgx_is_within_enclave(__host, _len___host)) ? _len___host : 0;
	ocalloc_size += (__in != NULL && sgx_is_within_enclave(__in, _len___in)) ? _len___in : 0;
	ocalloc_size += (__out != NULL && sgx_is_within_enclave(__out, _len___out)) ? _len___out : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_callrpc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_callrpc_t));

	if (__host != NULL && sgx_is_within_enclave(__host, _len___host)) {
		ms->ms___host = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___host);
		memcpy((void*)ms->ms___host, __host, _len___host);
	} else if (__host == NULL) {
		ms->ms___host = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___prognum = __prognum;
	ms->ms___versnum = __versnum;
	ms->ms___procnum = __procnum;
	ms->ms___inproc = __inproc;
	if (__in != NULL && sgx_is_within_enclave(__in, _len___in)) {
		ms->ms___in = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___in);
		memcpy((void*)ms->ms___in, __in, _len___in);
	} else if (__in == NULL) {
		ms->ms___in = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms___outproc = __outproc;
	if (__out != NULL && sgx_is_within_enclave(__out, _len___out)) {
		ms->ms___out = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len___out);
		memcpy(ms->ms___out, __out, _len___out);
	} else if (__out == NULL) {
		ms->ms___out = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(319, ms);

	if (retval) *retval = ms->ms_retval;
	if (__out) memcpy((void*)__out, ms->ms___out, _len___out);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_svc_sendreply(bool_t* retval, SVCXPRT* __xprt, xdrproc_t __xdr_results, char* __xdr_location)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_svc_sendreply_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_svc_sendreply_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_svc_sendreply_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_svc_sendreply_t));

	ms->ms___xprt = SGX_CAST(SVCXPRT*, __xprt);
	ms->ms___xdr_results = __xdr_results;
	ms->ms___xdr_location = SGX_CAST(char*, __xdr_location);
	status = sgx_ocall(320, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_svcerr_noproc(SVCXPRT* __xprt)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_svcerr_noproc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_svcerr_noproc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_svcerr_noproc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_svcerr_noproc_t));

	ms->ms___xprt = SGX_CAST(SVCXPRT*, __xprt);
	status = sgx_ocall(321, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_svcerr_decode(SVCXPRT* __xprt)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_svcerr_decode_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_svcerr_decode_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_svcerr_decode_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_svcerr_decode_t));

	ms->ms___xprt = SGX_CAST(SVCXPRT*, __xprt);
	status = sgx_ocall(322, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_svcerr_systemerr(SVCXPRT* __xprt)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_svcerr_systemerr_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_svcerr_systemerr_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_svcerr_systemerr_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_svcerr_systemerr_t));

	ms->ms___xprt = SGX_CAST(SVCXPRT*, __xprt);
	status = sgx_ocall(323, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_clnt_call(bool* retval, CLIENT* rh, unsigned long int proc, xdrproc_t xargs, caddr_t argsp, xdrproc_t xres, char* resp, struct timeval timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_clnt_call_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_clnt_call_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_clnt_call_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_clnt_call_t));

	ms->ms_rh = SGX_CAST(CLIENT*, rh);
	ms->ms_proc = proc;
	ms->ms_xargs = xargs;
	ms->ms_argsp = argsp;
	ms->ms_xres = xres;
	ms->ms_resp = SGX_CAST(char*, resp);
	ms->ms_timeout = timeout;
	status = sgx_ocall(324, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_fast_clnt_call(unsigned long int proc)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_fast_clnt_call_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_fast_clnt_call_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_fast_clnt_call_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_fast_clnt_call_t));

	ms->ms_proc = proc;
	status = sgx_ocall(325, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_clnt_control(bool_t* retval, CLIENT* cl, u_int rq, char* in, int in_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_in = in_size;

	ms_ocall_clnt_control_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_clnt_control_t);
	void *__tmp = NULL;

	ocalloc_size += (in != NULL && sgx_is_within_enclave(in, _len_in)) ? _len_in : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_clnt_control_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_clnt_control_t));

	ms->ms_cl = SGX_CAST(CLIENT*, cl);
	ms->ms_rq = rq;
	if (in != NULL && sgx_is_within_enclave(in, _len_in)) {
		ms->ms_in = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_in);
		memcpy(ms->ms_in, in, _len_in);
	} else if (in == NULL) {
		ms->ms_in = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_in_size = in_size;
	status = sgx_ocall(326, ms);

	if (retval) *retval = ms->ms_retval;
	if (in) memcpy((void*)in, ms->ms_in, _len_in);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_svc_getargs(bool_t* retval, SVCXPRT* xprt, xdrproc_t xargs, char* argsp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_svc_getargs_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_svc_getargs_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_svc_getargs_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_svc_getargs_t));

	ms->ms_xprt = SGX_CAST(SVCXPRT*, xprt);
	ms->ms_xargs = xargs;
	ms->ms_argsp = SGX_CAST(char*, argsp);
	status = sgx_ocall(327, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_svc_freeargs(bool_t* retval, SVCXPRT* xprt, xdrproc_t xargs, char* argsp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_svc_freeargs_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_svc_freeargs_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_svc_freeargs_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_svc_freeargs_t));

	ms->ms_xprt = SGX_CAST(SVCXPRT*, xprt);
	ms->ms_xargs = xargs;
	ms->ms_argsp = SGX_CAST(char*, argsp);
	status = sgx_ocall(328, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_getifaddrs(int* retval, struct ifaddrs** ifap)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_getifaddrs_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_getifaddrs_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_getifaddrs_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_getifaddrs_t));

	ms->ms_ifap = SGX_CAST(struct ifaddrs**, ifap);
	status = sgx_ocall(329, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_freeifaddrs(struct ifaddrs* ifa)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_freeifaddrs_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_freeifaddrs_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_freeifaddrs_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_freeifaddrs_t));

	ms->ms_ifa = SGX_CAST(struct ifaddrs*, ifa);
	status = sgx_ocall(330, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_if_nametoindex(unsigned int* retval, const char* ifname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ifname = ifname ? strlen(ifname) + 1 : 0;

	ms_ocall_if_nametoindex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_if_nametoindex_t);
	void *__tmp = NULL;

	ocalloc_size += (ifname != NULL && sgx_is_within_enclave(ifname, _len_ifname)) ? _len_ifname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_if_nametoindex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_if_nametoindex_t));

	if (ifname != NULL && sgx_is_within_enclave(ifname, _len_ifname)) {
		ms->ms_ifname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_ifname);
		memcpy((void*)ms->ms_ifname, ifname, _len_ifname);
	} else if (ifname == NULL) {
		ms->ms_ifname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(331, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_if_indextoname(char** retval, unsigned int ifindex, char* ifname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ifname = ifname ? strlen(ifname) + 1 : 0;

	ms_ocall_if_indextoname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_if_indextoname_t);
	void *__tmp = NULL;

	ocalloc_size += (ifname != NULL && sgx_is_within_enclave(ifname, _len_ifname)) ? _len_ifname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_if_indextoname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_if_indextoname_t));

	ms->ms_ifindex = ifindex;
	if (ifname != NULL && sgx_is_within_enclave(ifname, _len_ifname)) {
		ms->ms_ifname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_ifname);
		memcpy(ms->ms_ifname, ifname, _len_ifname);
	} else if (ifname == NULL) {
		ms->ms_ifname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(332, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_if_nameindex(struct if_nameindex** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_if_nameindex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_if_nameindex_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_if_nameindex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_if_nameindex_t));

	status = sgx_ocall(333, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_if_freenameindex(struct if_nameindex* ptr)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_if_freenameindex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_if_freenameindex_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_if_freenameindex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_if_freenameindex_t));

	ms->ms_ptr = SGX_CAST(struct if_nameindex*, ptr);
	status = sgx_ocall(334, ms);


	sgx_ocfree();
	return status;
}

