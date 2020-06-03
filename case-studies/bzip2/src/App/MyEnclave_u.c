#include "MyEnclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL MyEnclave_do_execve(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	do_execve();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_do_execlp(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	do_execlp();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_printf_string(void* pms)
{
	ms_printf_string_t* ms = SGX_CAST(ms_printf_string_t*, pms);
	printf_string(ms->ms_s);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_create(void* pms)
{
	ms_ocall_pthread_create_t* ms = SGX_CAST(ms_ocall_pthread_create_t*, pms);
	ms->ms_retval = ocall_pthread_create(ms->ms_new_thread, ms->ms___attr, ms->ms_job_id, ms->ms_eid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_self(void* pms)
{
	ms_ocall_pthread_self_t* ms = SGX_CAST(ms_ocall_pthread_self_t*, pms);
	ms->ms_retval = ocall_pthread_self();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_join(void* pms)
{
	ms_ocall_pthread_join_t* ms = SGX_CAST(ms_ocall_pthread_join_t*, pms);
	ms->ms_retval = ocall_pthread_join(ms->ms_pt, ms->ms_thread_result);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_detach(void* pms)
{
	ms_ocall_pthread_detach_t* ms = SGX_CAST(ms_ocall_pthread_detach_t*, pms);
	ms->ms_retval = ocall_pthread_detach(ms->ms_pt);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_equal(void* pms)
{
	ms_ocall_pthread_equal_t* ms = SGX_CAST(ms_ocall_pthread_equal_t*, pms);
	ms->ms_retval = ocall_pthread_equal(ms->ms_pt1, ms->ms_pt2);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_exit(void* pms)
{
	ms_ocall_pthread_exit_t* ms = SGX_CAST(ms_ocall_pthread_exit_t*, pms);
	ocall_pthread_exit(ms->ms_retval);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_cancel(void* pms)
{
	ms_ocall_pthread_cancel_t* ms = SGX_CAST(ms_ocall_pthread_cancel_t*, pms);
	ms->ms_retval = ocall_pthread_cancel(ms->ms_th);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_testcancel(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_pthread_testcancel();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_attr_init(void* pms)
{
	ms_ocall_pthread_attr_init_t* ms = SGX_CAST(ms_ocall_pthread_attr_init_t*, pms);
	ms->ms_retval = ocall_pthread_attr_init(ms->ms___attr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_attr_destroy(void* pms)
{
	ms_ocall_pthread_attr_destroy_t* ms = SGX_CAST(ms_ocall_pthread_attr_destroy_t*, pms);
	ms->ms_retval = ocall_pthread_attr_destroy(ms->ms___attr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_attr_getdetachstate(void* pms)
{
	ms_ocall_pthread_attr_getdetachstate_t* ms = SGX_CAST(ms_ocall_pthread_attr_getdetachstate_t*, pms);
	ms->ms_retval = ocall_pthread_attr_getdetachstate(ms->ms___attr, ms->ms___detachstate);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_attr_setdetachstate(void* pms)
{
	ms_ocall_pthread_attr_setdetachstate_t* ms = SGX_CAST(ms_ocall_pthread_attr_setdetachstate_t*, pms);
	ms->ms_retval = ocall_pthread_attr_setdetachstate(ms->ms___attr, ms->ms___detachstate);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_attr_getguardsize(void* pms)
{
	ms_ocall_pthread_attr_getguardsize_t* ms = SGX_CAST(ms_ocall_pthread_attr_getguardsize_t*, pms);
	ms->ms_retval = ocall_pthread_attr_getguardsize(ms->ms___attr, ms->ms___guardsize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_attr_setguardsize(void* pms)
{
	ms_ocall_pthread_attr_setguardsize_t* ms = SGX_CAST(ms_ocall_pthread_attr_setguardsize_t*, pms);
	ms->ms_retval = ocall_pthread_attr_setguardsize(ms->ms___attr, ms->ms___guardsize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_attr_getschedpolicy(void* pms)
{
	ms_ocall_pthread_attr_getschedpolicy_t* ms = SGX_CAST(ms_ocall_pthread_attr_getschedpolicy_t*, pms);
	ms->ms_retval = ocall_pthread_attr_getschedpolicy(ms->ms___attr, ms->ms___policy);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_attr_setschedpolicy(void* pms)
{
	ms_ocall_pthread_attr_setschedpolicy_t* ms = SGX_CAST(ms_ocall_pthread_attr_setschedpolicy_t*, pms);
	ms->ms_retval = ocall_pthread_attr_setschedpolicy(ms->ms___attr, ms->ms___policy);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_attr_getstacksize(void* pms)
{
	ms_ocall_pthread_attr_getstacksize_t* ms = SGX_CAST(ms_ocall_pthread_attr_getstacksize_t*, pms);
	ms->ms_retval = ocall_pthread_attr_getstacksize(ms->ms___attr, ms->ms___stacksize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_attr_setstacksize(void* pms)
{
	ms_ocall_pthread_attr_setstacksize_t* ms = SGX_CAST(ms_ocall_pthread_attr_setstacksize_t*, pms);
	ms->ms_retval = ocall_pthread_attr_setstacksize(ms->ms___attr, ms->ms___stacksize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_setspecific(void* pms)
{
	ms_ocall_pthread_setspecific_t* ms = SGX_CAST(ms_ocall_pthread_setspecific_t*, pms);
	ms->ms_retval = ocall_pthread_setspecific(ms->ms_key, (const void*)ms->ms_value);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_getspecific(void* pms)
{
	ms_ocall_pthread_getspecific_t* ms = SGX_CAST(ms_ocall_pthread_getspecific_t*, pms);
	ms->ms_retval = ocall_pthread_getspecific(ms->ms_key);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pthread_key_create(void* pms)
{
	ms_ocall_pthread_key_create_t* ms = SGX_CAST(ms_ocall_pthread_key_create_t*, pms);
	ms->ms_retval = ocall_pthread_key_create(ms->ms_key, ms->ms_destructor);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_time(void* pms)
{
	ms_ocall_time_t* ms = SGX_CAST(ms_ocall_time_t*, pms);
	ms->ms_retval = ocall_time(ms->ms_t);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_gettimeofday(void* pms)
{
	ms_ocall_gettimeofday_t* ms = SGX_CAST(ms_ocall_gettimeofday_t*, pms);
	ms->ms_retval = ocall_gettimeofday(ms->ms_tv, ms->ms_tv_size, ms->ms_tz, ms->ms_tz_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_gettimeofday2(void* pms)
{
	ms_ocall_gettimeofday2_t* ms = SGX_CAST(ms_ocall_gettimeofday2_t*, pms);
	ms->ms_retval = ocall_gettimeofday2(ms->ms_tv, ms->ms_tv_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_clock(void* pms)
{
	ms_ocall_clock_t* ms = SGX_CAST(ms_ocall_clock_t*, pms);
	ms->ms_retval = ocall_clock();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_gmtime_r(void* pms)
{
	ms_ocall_gmtime_r_t* ms = SGX_CAST(ms_ocall_gmtime_r_t*, pms);
	ms->ms_retval = ocall_gmtime_r((const time_t*)ms->ms_timer, ms->ms_tp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_localtime_r(void* pms)
{
	ms_ocall_localtime_r_t* ms = SGX_CAST(ms_ocall_localtime_r_t*, pms);
	ms->ms_retval = ocall_localtime_r((const time_t*)ms->ms_timer, ms->ms_tp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mktime(void* pms)
{
	ms_ocall_mktime_t* ms = SGX_CAST(ms_ocall_mktime_t*, pms);
	ms->ms_retval = ocall_mktime(ms->ms_tp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getitimer(void* pms)
{
	ms_ocall_getitimer_t* ms = SGX_CAST(ms_ocall_getitimer_t*, pms);
	ms->ms_retval = ocall_getitimer(ms->ms_which, ms->ms_curr_value);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_setitimer(void* pms)
{
	ms_ocall_setitimer_t* ms = SGX_CAST(ms_ocall_setitimer_t*, pms);
	ms->ms_retval = ocall_setitimer(ms->ms_which, (const struct itimerval*)ms->ms_new_value, ms->ms_old_value);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_nanosleep(void* pms)
{
	ms_ocall_nanosleep_t* ms = SGX_CAST(ms_ocall_nanosleep_t*, pms);
	ms->ms_retval = ocall_nanosleep((const struct timespec*)ms->ms_req, ms->ms_rem);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_wrapper_getopt(void* pms)
{
	ms_wrapper_getopt_t* ms = SGX_CAST(ms_wrapper_getopt_t*, pms);
	ms->ms_retval = wrapper_getopt(ms->ms_argc, ms->ms_argv, (const char*)ms->ms_optstring);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_set_optind(void* pms)
{
	ms_set_optind_t* ms = SGX_CAST(ms_set_optind_t*, pms);
	set_optind(ms->ms_oi);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_set_opterr(void* pms)
{
	ms_set_opterr_t* ms = SGX_CAST(ms_set_opterr_t*, pms);
	set_opterr(ms->ms_oe);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_set_optopt(void* pms)
{
	ms_set_optopt_t* ms = SGX_CAST(ms_set_optopt_t*, pms);
	set_optopt(ms->ms_oo);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_set_optreset(void* pms)
{
	ms_set_optreset_t* ms = SGX_CAST(ms_set_optreset_t*, pms);
	set_optreset(ms->ms_ors);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_get_optarg(void* pms)
{
	ms_get_optarg_t* ms = SGX_CAST(ms_get_optarg_t*, pms);
	ms->ms_retval = get_optarg();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_get_optind(void* pms)
{
	ms_ocall_get_optind_t* ms = SGX_CAST(ms_ocall_get_optind_t*, pms);
	ms->ms_retval = ocall_get_optind();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_get_opterr(void* pms)
{
	ms_ocall_get_opterr_t* ms = SGX_CAST(ms_ocall_get_opterr_t*, pms);
	ms->ms_retval = ocall_get_opterr();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_get_optopt(void* pms)
{
	ms_ocall_get_optopt_t* ms = SGX_CAST(ms_ocall_get_optopt_t*, pms);
	ms->ms_retval = ocall_get_optopt();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getpwuid(void* pms)
{
	ms_ocall_getpwuid_t* ms = SGX_CAST(ms_ocall_getpwuid_t*, pms);
	ms->ms_retval = ocall_getpwuid(ms->ms_uid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getpwnam(void* pms)
{
	ms_ocall_getpwnam_t* ms = SGX_CAST(ms_ocall_getpwnam_t*, pms);
	ms->ms_retval = ocall_getpwnam((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getpwnam_r(void* pms)
{
	ms_ocall_getpwnam_r_t* ms = SGX_CAST(ms_ocall_getpwnam_r_t*, pms);
	ms->ms_retval = ocall_getpwnam_r((const char*)ms->ms_name, ms->ms_pwd, ms->ms_buf, ms->ms_buflen, ms->ms_result);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getgrgid(void* pms)
{
	ms_ocall_getgrgid_t* ms = SGX_CAST(ms_ocall_getgrgid_t*, pms);
	ms->ms_retval = ocall_getgrgid(ms->ms_gid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_initgroups(void* pms)
{
	ms_ocall_initgroups_t* ms = SGX_CAST(ms_ocall_initgroups_t*, pms);
	ms->ms_retval = ocall_initgroups((const char*)ms->ms_user, ms->ms_group);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_uname(void* pms)
{
	ms_ocall_uname_t* ms = SGX_CAST(ms_ocall_uname_t*, pms);
	ms->ms_retval = ocall_uname(ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getenv(void* pms)
{
	ms_ocall_getenv_t* ms = SGX_CAST(ms_ocall_getenv_t*, pms);
	ms->ms_retval = ocall_getenv((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_putenv(void* pms)
{
	ms_ocall_putenv_t* ms = SGX_CAST(ms_ocall_putenv_t*, pms);
	ms->ms_retval = ocall_putenv(ms->ms_string);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_clearenv(void* pms)
{
	ms_ocall_clearenv_t* ms = SGX_CAST(ms_ocall_clearenv_t*, pms);
	ms->ms_retval = ocall_clearenv();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_setenv(void* pms)
{
	ms_ocall_setenv_t* ms = SGX_CAST(ms_ocall_setenv_t*, pms);
	ms->ms_retval = ocall_setenv((const char*)ms->ms_name, (const char*)ms->ms_value, ms->ms_replace);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_unsetenv(void* pms)
{
	ms_ocall_unsetenv_t* ms = SGX_CAST(ms_ocall_unsetenv_t*, pms);
	ms->ms_retval = ocall_unsetenv((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mkstemp(void* pms)
{
	ms_ocall_mkstemp_t* ms = SGX_CAST(ms_ocall_mkstemp_t*, pms);
	ms->ms_retval = ocall_mkstemp(ms->ms_temp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mkdtemp(void* pms)
{
	ms_ocall_mkdtemp_t* ms = SGX_CAST(ms_ocall_mkdtemp_t*, pms);
	ms->ms_retval = ocall_mkdtemp(ms->ms_temp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_open1(void* pms)
{
	ms_ocall_open1_t* ms = SGX_CAST(ms_ocall_open1_t*, pms);
	ms->ms_retval = ocall_open1((const char*)ms->ms_pathname, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_open2(void* pms)
{
	ms_ocall_open2_t* ms = SGX_CAST(ms_ocall_open2_t*, pms);
	ms->ms_retval = ocall_open2((const char*)ms->ms_pathname, ms->ms_flags, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_creat(void* pms)
{
	ms_ocall_creat_t* ms = SGX_CAST(ms_ocall_creat_t*, pms);
	ms->ms_retval = ocall_creat((const char*)ms->ms_pathname, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_openat1(void* pms)
{
	ms_ocall_openat1_t* ms = SGX_CAST(ms_ocall_openat1_t*, pms);
	ms->ms_retval = ocall_openat1(ms->ms_dirfd, (const char*)ms->ms_pathname, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_openat2(void* pms)
{
	ms_ocall_openat2_t* ms = SGX_CAST(ms_ocall_openat2_t*, pms);
	ms->ms_retval = ocall_openat2(ms->ms_dirfd, (const char*)ms->ms_pathname, ms->ms_flags, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fcntl1(void* pms)
{
	ms_ocall_fcntl1_t* ms = SGX_CAST(ms_ocall_fcntl1_t*, pms);
	ms->ms_retval = ocall_fcntl1(ms->ms_fd, ms->ms_cmd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fcntl2(void* pms)
{
	ms_ocall_fcntl2_t* ms = SGX_CAST(ms_ocall_fcntl2_t*, pms);
	ms->ms_retval = ocall_fcntl2(ms->ms_fd, ms->ms_cmd, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fcntl3(void* pms)
{
	ms_ocall_fcntl3_t* ms = SGX_CAST(ms_ocall_fcntl3_t*, pms);
	ms->ms_retval = ocall_fcntl3(ms->ms_fd, ms->ms_cmd, ms->ms_arg, ms->ms_flock_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_gethostname(void* pms)
{
	ms_ocall_gethostname_t* ms = SGX_CAST(ms_ocall_gethostname_t*, pms);
	ms->ms_retval = ocall_gethostname(ms->ms_name, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sethostname(void* pms)
{
	ms_ocall_sethostname_t* ms = SGX_CAST(ms_ocall_sethostname_t*, pms);
	ms->ms_retval = ocall_sethostname((const char*)ms->ms_name, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_lseek(void* pms)
{
	ms_ocall_lseek_t* ms = SGX_CAST(ms_ocall_lseek_t*, pms);
	ms->ms_retval = ocall_lseek(ms->ms_fd, ms->ms_offset, ms->ms_whence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_get_buff_addr(void* pms)
{
	ms_get_buff_addr_t* ms = SGX_CAST(ms_get_buff_addr_t*, pms);
	ms->ms_retval = get_buff_addr(ms->ms_arr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fast_write(void* pms)
{
	ms_ocall_fast_write_t* ms = SGX_CAST(ms_ocall_fast_write_t*, pms);
	ms->ms_retval = ocall_fast_write(ms->ms_fd, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fast_read(void* pms)
{
	ms_ocall_fast_read_t* ms = SGX_CAST(ms_ocall_fast_read_t*, pms);
	ms->ms_retval = ocall_fast_read(ms->ms_fd, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_read(void* pms)
{
	ms_ocall_read_t* ms = SGX_CAST(ms_ocall_read_t*, pms);
	ms->ms_retval = ocall_read(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_write(void* pms)
{
	ms_ocall_write_t* ms = SGX_CAST(ms_ocall_write_t*, pms);
	ms->ms_retval = ocall_write(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_read1(void* pms)
{
	ms_ocall_read1_t* ms = SGX_CAST(ms_ocall_read1_t*, pms);
	ms->ms_retval = ocall_read1(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_write1(void* pms)
{
	ms_ocall_write1_t* ms = SGX_CAST(ms_ocall_write1_t*, pms);
	ms->ms_retval = ocall_write1(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_read2(void* pms)
{
	ms_ocall_read2_t* ms = SGX_CAST(ms_ocall_read2_t*, pms);
	ms->ms_retval = ocall_read2(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_write2(void* pms)
{
	ms_ocall_write2_t* ms = SGX_CAST(ms_ocall_write2_t*, pms);
	ms->ms_retval = ocall_write2(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_read3(void* pms)
{
	ms_ocall_read3_t* ms = SGX_CAST(ms_ocall_read3_t*, pms);
	ms->ms_retval = ocall_read3(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_write3(void* pms)
{
	ms_ocall_write3_t* ms = SGX_CAST(ms_ocall_write3_t*, pms);
	ms->ms_retval = ocall_write3(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_read4(void* pms)
{
	ms_ocall_read4_t* ms = SGX_CAST(ms_ocall_read4_t*, pms);
	ms->ms_retval = ocall_read4(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_write4(void* pms)
{
	ms_ocall_write4_t* ms = SGX_CAST(ms_ocall_write4_t*, pms);
	ms->ms_retval = ocall_write4(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_read5(void* pms)
{
	ms_ocall_read5_t* ms = SGX_CAST(ms_ocall_read5_t*, pms);
	ms->ms_retval = ocall_read5(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_write5(void* pms)
{
	ms_ocall_write5_t* ms = SGX_CAST(ms_ocall_write5_t*, pms);
	ms->ms_retval = ocall_write5(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_read6(void* pms)
{
	ms_ocall_read6_t* ms = SGX_CAST(ms_ocall_read6_t*, pms);
	ms->ms_retval = ocall_read6(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_write6(void* pms)
{
	ms_ocall_write6_t* ms = SGX_CAST(ms_ocall_write6_t*, pms);
	ms->ms_retval = ocall_write6(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_read7(void* pms)
{
	ms_ocall_read7_t* ms = SGX_CAST(ms_ocall_read7_t*, pms);
	ms->ms_retval = ocall_read7(ms->ms_fd, ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_write7(void* pms)
{
	ms_ocall_write7_t* ms = SGX_CAST(ms_ocall_write7_t*, pms);
	ms->ms_retval = ocall_write7(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getpid(void* pms)
{
	ms_ocall_getpid_t* ms = SGX_CAST(ms_ocall_getpid_t*, pms);
	ms->ms_retval = ocall_getpid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getppid(void* pms)
{
	ms_ocall_getppid_t* ms = SGX_CAST(ms_ocall_getppid_t*, pms);
	ms->ms_retval = ocall_getppid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pread(void* pms)
{
	ms_ocall_pread_t* ms = SGX_CAST(ms_ocall_pread_t*, pms);
	ms->ms_retval = ocall_pread(ms->ms_fd, ms->ms_buf, ms->ms_nbytes, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pwrite(void* pms)
{
	ms_ocall_pwrite_t* ms = SGX_CAST(ms_ocall_pwrite_t*, pms);
	ms->ms_retval = ocall_pwrite(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_n, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pipe(void* pms)
{
	ms_ocall_pipe_t* ms = SGX_CAST(ms_ocall_pipe_t*, pms);
	ms->ms_retval = ocall_pipe(ms->ms_pipedes);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pipe2(void* pms)
{
	ms_ocall_pipe2_t* ms = SGX_CAST(ms_ocall_pipe2_t*, pms);
	ms->ms_retval = ocall_pipe2(ms->ms_pipedes, ms->ms_flag);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sleep(void* pms)
{
	ms_ocall_sleep_t* ms = SGX_CAST(ms_ocall_sleep_t*, pms);
	ms->ms_retval = ocall_sleep(ms->ms_seconds);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_usleep(void* pms)
{
	ms_ocall_usleep_t* ms = SGX_CAST(ms_ocall_usleep_t*, pms);
	ms->ms_retval = ocall_usleep(ms->ms_seconds);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_chown(void* pms)
{
	ms_ocall_chown_t* ms = SGX_CAST(ms_ocall_chown_t*, pms);
	ms->ms_retval = ocall_chown((const char*)ms->ms_file, ms->ms_owner, ms->ms_group);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fchown(void* pms)
{
	ms_ocall_fchown_t* ms = SGX_CAST(ms_ocall_fchown_t*, pms);
	ms->ms_retval = ocall_fchown(ms->ms_fd, ms->ms_owner, ms->ms_group);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_lchown(void* pms)
{
	ms_ocall_lchown_t* ms = SGX_CAST(ms_ocall_lchown_t*, pms);
	ms->ms_retval = ocall_lchown((const char*)ms->ms_file, ms->ms_owner, ms->ms_group);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_chdir(void* pms)
{
	ms_ocall_chdir_t* ms = SGX_CAST(ms_ocall_chdir_t*, pms);
	ms->ms_retval = ocall_chdir((const char*)ms->ms_path);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fchdir(void* pms)
{
	ms_ocall_fchdir_t* ms = SGX_CAST(ms_ocall_fchdir_t*, pms);
	ms->ms_retval = ocall_fchdir(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_get_current_dir_name(void* pms)
{
	ms_ocall_get_current_dir_name_t* ms = SGX_CAST(ms_ocall_get_current_dir_name_t*, pms);
	ms->ms_retval = ocall_get_current_dir_name();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_dup(void* pms)
{
	ms_ocall_dup_t* ms = SGX_CAST(ms_ocall_dup_t*, pms);
	ms->ms_retval = ocall_dup(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_dup2(void* pms)
{
	ms_ocall_dup2_t* ms = SGX_CAST(ms_ocall_dup2_t*, pms);
	ms->ms_retval = ocall_dup2(ms->ms_fd, ms->ms_fd2);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_dup3(void* pms)
{
	ms_ocall_dup3_t* ms = SGX_CAST(ms_ocall_dup3_t*, pms);
	ms->ms_retval = ocall_dup3(ms->ms_fd, ms->ms_fd2, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getuid(void* pms)
{
	ms_ocall_getuid_t* ms = SGX_CAST(ms_ocall_getuid_t*, pms);
	ms->ms_retval = ocall_getuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_geteuid(void* pms)
{
	ms_ocall_geteuid_t* ms = SGX_CAST(ms_ocall_geteuid_t*, pms);
	ms->ms_retval = ocall_geteuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getgid(void* pms)
{
	ms_ocall_getgid_t* ms = SGX_CAST(ms_ocall_getgid_t*, pms);
	ms->ms_retval = ocall_getgid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getegid(void* pms)
{
	ms_ocall_getegid_t* ms = SGX_CAST(ms_ocall_getegid_t*, pms);
	ms->ms_retval = ocall_getegid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getpagesize(void* pms)
{
	ms_ocall_getpagesize_t* ms = SGX_CAST(ms_ocall_getpagesize_t*, pms);
	ms->ms_retval = ocall_getpagesize();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getcwd(void* pms)
{
	ms_ocall_getcwd_t* ms = SGX_CAST(ms_ocall_getcwd_t*, pms);
	ms->ms_retval = ocall_getcwd(ms->ms_buf, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_unlink(void* pms)
{
	ms_ocall_unlink_t* ms = SGX_CAST(ms_ocall_unlink_t*, pms);
	ms->ms_retval = ocall_unlink((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_rmdir(void* pms)
{
	ms_ocall_rmdir_t* ms = SGX_CAST(ms_ocall_rmdir_t*, pms);
	ms->ms_retval = ocall_rmdir((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall__exit(void* pms)
{
	ms_ocall__exit_t* ms = SGX_CAST(ms_ocall__exit_t*, pms);
	ocall__exit(ms->ms_stat, ms->ms_eid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_exit(void* pms)
{
	ms_ocall_exit_t* ms = SGX_CAST(ms_ocall_exit_t*, pms);
	ocall_exit(ms->ms_stat, ms->ms_eid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sysconf(void* pms)
{
	ms_ocall_sysconf_t* ms = SGX_CAST(ms_ocall_sysconf_t*, pms);
	ms->ms_retval = ocall_sysconf(ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_setgid(void* pms)
{
	ms_ocall_setgid_t* ms = SGX_CAST(ms_ocall_setgid_t*, pms);
	ms->ms_retval = ocall_setgid(ms->ms_gid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_setuid(void* pms)
{
	ms_ocall_setuid_t* ms = SGX_CAST(ms_ocall_setuid_t*, pms);
	ms->ms_retval = ocall_setuid(ms->ms_uid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_execvp(void* pms)
{
	ms_ocall_execvp_t* ms = SGX_CAST(ms_ocall_execvp_t*, pms);
	ms->ms_retval = ocall_execvp((const char*)ms->ms_file, (const char**)ms->ms_argv);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_ftruncate(void* pms)
{
	ms_ocall_ftruncate_t* ms = SGX_CAST(ms_ocall_ftruncate_t*, pms);
	ms->ms_retval = ocall_ftruncate(ms->ms_fd, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_free(void* pms)
{
	ms_ocall_free_t* ms = SGX_CAST(ms_ocall_free_t*, pms);
	ocall_free(ms->ms_p);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_geterrno(void* pms)
{
	ms_ocall_geterrno_t* ms = SGX_CAST(ms_ocall_geterrno_t*, pms);
	ms->ms_retval = ocall_geterrno();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fsync(void* pms)
{
	ms_ocall_fsync_t* ms = SGX_CAST(ms_ocall_fsync_t*, pms);
	ms->ms_retval = ocall_fsync(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_alarm(void* pms)
{
	ms_ocall_alarm_t* ms = SGX_CAST(ms_ocall_alarm_t*, pms);
	ms->ms_retval = ocall_alarm(ms->ms_seconds);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_copy_arg(void* pms)
{
	ms_ocall_copy_arg_t* ms = SGX_CAST(ms_ocall_copy_arg_t*, pms);
	ms->ms_retval = ocall_copy_arg(ms->ms_buff, ms->ms_buff_size, ms->ms_argv, ms->ms_index);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mknod(void* pms)
{
	ms_ocall_mknod_t* ms = SGX_CAST(ms_ocall_mknod_t*, pms);
	ms->ms_retval = ocall_mknod((const char*)ms->ms_pathname, ms->ms_mode, ms->ms_dev);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_isatty(void* pms)
{
	ms_ocall_isatty_t* ms = SGX_CAST(ms_ocall_isatty_t*, pms);
	ms->ms_retval = ocall_isatty(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_malloc(void* pms)
{
	ms_ocall_malloc_t* ms = SGX_CAST(ms_ocall_malloc_t*, pms);
	ms->ms_retval = ocall_malloc(ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fopen(void* pms)
{
	ms_ocall_fopen_t* ms = SGX_CAST(ms_ocall_fopen_t*, pms);
	ms->ms_retval = ocall_fopen((const char*)ms->ms_filename, (const char*)ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_popen(void* pms)
{
	ms_ocall_popen_t* ms = SGX_CAST(ms_ocall_popen_t*, pms);
	ms->ms_retval = ocall_popen((const char*)ms->ms_command, (const char*)ms->ms_type);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fclose(void* pms)
{
	ms_ocall_fclose_t* ms = SGX_CAST(ms_ocall_fclose_t*, pms);
	ms->ms_retval = ocall_fclose(ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pclose(void* pms)
{
	ms_ocall_pclose_t* ms = SGX_CAST(ms_ocall_pclose_t*, pms);
	ms->ms_retval = ocall_pclose(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fputs(void* pms)
{
	ms_ocall_fputs_t* ms = SGX_CAST(ms_ocall_fputs_t*, pms);
	ms->ms_retval = ocall_fputs((const char*)ms->ms_str, ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_feof(void* pms)
{
	ms_ocall_feof_t* ms = SGX_CAST(ms_ocall_feof_t*, pms);
	ms->ms_retval = ocall_feof(ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_rewind(void* pms)
{
	ms_ocall_rewind_t* ms = SGX_CAST(ms_ocall_rewind_t*, pms);
	ocall_rewind(ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fflush(void* pms)
{
	ms_ocall_fflush_t* ms = SGX_CAST(ms_ocall_fflush_t*, pms);
	ms->ms_retval = ocall_fflush(ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fread(void* pms)
{
	ms_ocall_fread_t* ms = SGX_CAST(ms_ocall_fread_t*, pms);
	ms->ms_retval = ocall_fread(ms->ms_ptr, ms->ms_size, ms->ms_nmemb, ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fwrite(void* pms)
{
	ms_ocall_fwrite_t* ms = SGX_CAST(ms_ocall_fwrite_t*, pms);
	ms->ms_retval = ocall_fwrite((const void*)ms->ms_ptr, ms->ms_size, ms->ms_count, ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_vfprintf(void* pms)
{
	ms_ocall_vfprintf_t* ms = SGX_CAST(ms_ocall_vfprintf_t*, pms);
	ms->ms_retval = ocall_vfprintf(ms->ms_FILESTREAM, (const char*)ms->ms_format, ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_vprintf(void* pms)
{
	ms_ocall_vprintf_t* ms = SGX_CAST(ms_ocall_vprintf_t*, pms);
	ms->ms_retval = ocall_vprintf((const char*)ms->ms_format, ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fgets(void* pms)
{
	ms_ocall_fgets_t* ms = SGX_CAST(ms_ocall_fgets_t*, pms);
	ms->ms_retval = ocall_fgets(ms->ms_str, ms->ms_num, ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fgetc(void* pms)
{
	ms_ocall_fgetc_t* ms = SGX_CAST(ms_ocall_fgetc_t*, pms);
	ms->ms_retval = ocall_fgetc(ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_ungetc(void* pms)
{
	ms_ocall_ungetc_t* ms = SGX_CAST(ms_ocall_ungetc_t*, pms);
	ms->ms_retval = ocall_ungetc(ms->ms_c, ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getc_unlocked(void* pms)
{
	ms_ocall_getc_unlocked_t* ms = SGX_CAST(ms_ocall_getc_unlocked_t*, pms);
	ms->ms_retval = ocall_getc_unlocked(ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_flockfile(void* pms)
{
	ms_ocall_flockfile_t* ms = SGX_CAST(ms_ocall_flockfile_t*, pms);
	ocall_flockfile(ms->ms_filehandle);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_funlockfile(void* pms)
{
	ms_ocall_funlockfile_t* ms = SGX_CAST(ms_ocall_funlockfile_t*, pms);
	ocall_funlockfile(ms->ms_filehandle);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_vsprintf(void* pms)
{
	ms_ocall_vsprintf_t* ms = SGX_CAST(ms_ocall_vsprintf_t*, pms);
	ms->ms_retval = ocall_vsprintf(ms->ms_string, (const char*)ms->ms_format, ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_vasprintf(void* pms)
{
	ms_ocall_vasprintf_t* ms = SGX_CAST(ms_ocall_vasprintf_t*, pms);
	ms->ms_retval = ocall_vasprintf(ms->ms_string, (const char*)ms->ms_format, ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_ftello(void* pms)
{
	ms_ocall_ftello_t* ms = SGX_CAST(ms_ocall_ftello_t*, pms);
	ms->ms_retval = ocall_ftello(ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fseeko(void* pms)
{
	ms_ocall_fseeko_t* ms = SGX_CAST(ms_ocall_fseeko_t*, pms);
	ms->ms_retval = ocall_fseeko(ms->ms_FILESTREAM, ms->ms_offset, ms->ms_whence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_ftell(void* pms)
{
	ms_ocall_ftell_t* ms = SGX_CAST(ms_ocall_ftell_t*, pms);
	ms->ms_retval = ocall_ftell(ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fseek(void* pms)
{
	ms_ocall_fseek_t* ms = SGX_CAST(ms_ocall_fseek_t*, pms);
	ms->ms_retval = ocall_fseek(ms->ms_FILESTREAM, ms->ms_offset, ms->ms_whence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_ferror(void* pms)
{
	ms_ocall_ferror_t* ms = SGX_CAST(ms_ocall_ferror_t*, pms);
	ms->ms_retval = ocall_ferror(ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_perror(void* pms)
{
	ms_ocall_perror_t* ms = SGX_CAST(ms_ocall_perror_t*, pms);
	ocall_perror((const char*)ms->ms_s);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getc(void* pms)
{
	ms_ocall_getc_t* ms = SGX_CAST(ms_ocall_getc_t*, pms);
	ms->ms_retval = ocall_getc(ms->ms_FILESTREAM);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_vfscanf(void* pms)
{
	ms_ocall_vfscanf_t* ms = SGX_CAST(ms_ocall_vfscanf_t*, pms);
	ms->ms_retval = ocall_vfscanf(ms->ms_s, (const char*)ms->ms_format, ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_vscanf(void* pms)
{
	ms_ocall_vscanf_t* ms = SGX_CAST(ms_ocall_vscanf_t*, pms);
	ms->ms_retval = ocall_vscanf((const char*)ms->ms_format, ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_vsscanf(void* pms)
{
	ms_ocall_vsscanf_t* ms = SGX_CAST(ms_ocall_vsscanf_t*, pms);
	ms->ms_retval = ocall_vsscanf((const char*)ms->ms_s, (const char*)ms->ms_format, ms->ms_val);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_putchar(void* pms)
{
	ms_ocall_putchar_t* ms = SGX_CAST(ms_ocall_putchar_t*, pms);
	ms->ms_retval = ocall_putchar(ms->ms_c);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_putc(void* pms)
{
	ms_ocall_putc_t* ms = SGX_CAST(ms_ocall_putc_t*, pms);
	ms->ms_retval = ocall_putc(ms->ms_c, ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_puts(void* pms)
{
	ms_ocall_puts_t* ms = SGX_CAST(ms_ocall_puts_t*, pms);
	ms->ms_retval = ocall_puts((const char*)ms->ms_s);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fputc(void* pms)
{
	ms_ocall_fputc_t* ms = SGX_CAST(ms_ocall_fputc_t*, pms);
	ms->ms_retval = ocall_fputc(ms->ms_c, ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fdopen(void* pms)
{
	ms_ocall_fdopen_t* ms = SGX_CAST(ms_ocall_fdopen_t*, pms);
	ms->ms_retval = ocall_fdopen(ms->ms_fd, (const char*)ms->ms_modes);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fileno(void* pms)
{
	ms_ocall_fileno_t* ms = SGX_CAST(ms_ocall_fileno_t*, pms);
	ms->ms_retval = ocall_fileno(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_rename(void* pms)
{
	ms_ocall_rename_t* ms = SGX_CAST(ms_ocall_rename_t*, pms);
	ms->ms_retval = ocall_rename((const char*)ms->ms__old, (const char*)ms->ms__new);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_remove(void* pms)
{
	ms_ocall_remove_t* ms = SGX_CAST(ms_ocall_remove_t*, pms);
	ms->ms_retval = ocall_remove((const char*)ms->ms_pathname);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_tempnam(void* pms)
{
	ms_ocall_tempnam_t* ms = SGX_CAST(ms_ocall_tempnam_t*, pms);
	ms->ms_retval = ocall_tempnam((const char*)ms->ms_dir, (const char*)ms->ms_pfx);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ms->ms_retval = ocall_print_string((const char*)ms->ms_s);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fprint_string(void* pms)
{
	ms_ocall_fprint_string_t* ms = SGX_CAST(ms_ocall_fprint_string_t*, pms);
	ms->ms_retval = ocall_fprint_string(ms->ms_stream, (const char*)ms->ms_s);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_eventfd(void* pms)
{
	ms_ocall_eventfd_t* ms = SGX_CAST(ms_ocall_eventfd_t*, pms);
	ms->ms_retval = ocall_eventfd(ms->ms_initval, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_socket(void* pms)
{
	ms_ocall_socket_t* ms = SGX_CAST(ms_ocall_socket_t*, pms);
	ms->ms_retval = ocall_socket(ms->ms_domain, ms->ms_type, ms->ms_protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_accept(void* pms)
{
	ms_ocall_accept_t* ms = SGX_CAST(ms_ocall_accept_t*, pms);
	ms->ms_retval = ocall_accept(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_connect(void* pms)
{
	ms_ocall_connect_t* ms = SGX_CAST(ms_ocall_connect_t*, pms);
	ms->ms_retval = ocall_connect(ms->ms_socket, (const struct sockaddr*)ms->ms_address, ms->ms_address_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sendto(void* pms)
{
	ms_ocall_sendto_t* ms = SGX_CAST(ms_ocall_sendto_t*, pms);
	ms->ms_retval = ocall_sendto(ms->ms_sockfd, (const void*)ms->ms_buf, ms->ms_len, ms->ms_flags, (const void*)ms->ms_dest_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_fd, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_fd, (const void*)ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_socketpair(void* pms)
{
	ms_ocall_socketpair_t* ms = SGX_CAST(ms_ocall_socketpair_t*, pms);
	ms->ms_retval = ocall_socketpair(ms->ms_domain, ms->ms_type, ms->ms_protocol, ms->ms_sv);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_setsockopt(void* pms)
{
	ms_ocall_setsockopt_t* ms = SGX_CAST(ms_ocall_setsockopt_t*, pms);
	ms->ms_retval = ocall_setsockopt(ms->ms_sockfd, ms->ms_level, ms->ms_optname, (const void*)ms->ms_optval, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getsockopt(void* pms)
{
	ms_ocall_getsockopt_t* ms = SGX_CAST(ms_ocall_getsockopt_t*, pms);
	ms->ms_retval = ocall_getsockopt(ms->ms_sockfd, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_shutdown(void* pms)
{
	ms_ocall_shutdown_t* ms = SGX_CAST(ms_ocall_shutdown_t*, pms);
	ms->ms_retval = ocall_shutdown(ms->ms_fd, ms->ms_how);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_bind(void* pms)
{
	ms_ocall_bind_t* ms = SGX_CAST(ms_ocall_bind_t*, pms);
	ms->ms_retval = ocall_bind(ms->ms_fd, (const struct sockaddr*)ms->ms_addr, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_bind_untrusted(void* pms)
{
	ms_ocall_bind_untrusted_t* ms = SGX_CAST(ms_ocall_bind_untrusted_t*, pms);
	ms->ms_retval = ocall_bind_untrusted(ms->ms_fd, (const struct sockaddr*)ms->ms_addr, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_listen(void* pms)
{
	ms_ocall_listen_t* ms = SGX_CAST(ms_ocall_listen_t*, pms);
	ms->ms_retval = ocall_listen(ms->ms_fd, ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getsockname(void* pms)
{
	ms_ocall_getsockname_t* ms = SGX_CAST(ms_ocall_getsockname_t*, pms);
	ms->ms_retval = ocall_getsockname(ms->ms_fd, ms->ms_addr, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getpeername(void* pms)
{
	ms_ocall_getpeername_t* ms = SGX_CAST(ms_ocall_getpeername_t*, pms);
	ms->ms_retval = ocall_getpeername(ms->ms_fd, ms->ms_addr, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_recvfrom(void* pms)
{
	ms_ocall_recvfrom_t* ms = SGX_CAST(ms_ocall_recvfrom_t*, pms);
	ms->ms_retval = ocall_recvfrom(ms->ms_fd, ms->ms_untrusted_buf, ms->ms_n, ms->ms_flags, ms->ms_untrusted_addr, ms->ms_addr_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sendmsg(void* pms)
{
	ms_ocall_sendmsg_t* ms = SGX_CAST(ms_ocall_sendmsg_t*, pms);
	ms->ms_retval = ocall_sendmsg(ms->ms_fd, (const struct msghdr*)ms->ms_message, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_recvmsg(void* pms)
{
	ms_ocall_recvmsg_t* ms = SGX_CAST(ms_ocall_recvmsg_t*, pms);
	ms->ms_retval = ocall_recvmsg(ms->ms_fd, ms->ms_message, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_freeaddrinfo(void* pms)
{
	ms_ocall_freeaddrinfo_t* ms = SGX_CAST(ms_ocall_freeaddrinfo_t*, pms);
	ocall_freeaddrinfo(ms->ms_res);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getaddrinfo(void* pms)
{
	ms_ocall_getaddrinfo_t* ms = SGX_CAST(ms_ocall_getaddrinfo_t*, pms);
	ms->ms_retval = ocall_getaddrinfo((const char*)ms->ms_node, (const char*)ms->ms_service, (const void*)ms->ms_hints, ms->ms_res);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getaddrinfo1(void* pms)
{
	ms_ocall_getaddrinfo1_t* ms = SGX_CAST(ms_ocall_getaddrinfo1_t*, pms);
	ms->ms_retval = ocall_getaddrinfo1((const char*)ms->ms_node, (const char*)ms->ms_service, (const void*)ms->ms_hints, ms->ms_res);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sethostent(void* pms)
{
	ms_ocall_sethostent_t* ms = SGX_CAST(ms_ocall_sethostent_t*, pms);
	ocall_sethostent(ms->ms_stay_open);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_endhostent(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_endhostent();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_gethostent(void* pms)
{
	ms_ocall_gethostent_t* ms = SGX_CAST(ms_ocall_gethostent_t*, pms);
	ms->ms_retval = ocall_gethostent();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_gethostbyaddr(void* pms)
{
	ms_ocall_gethostbyaddr_t* ms = SGX_CAST(ms_ocall_gethostbyaddr_t*, pms);
	ms->ms_retval = ocall_gethostbyaddr((const void*)ms->ms_addr, ms->ms_len, ms->ms_type);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_gethostbyname(void* pms)
{
	ms_ocall_gethostbyname_t* ms = SGX_CAST(ms_ocall_gethostbyname_t*, pms);
	ms->ms_retval = ocall_gethostbyname((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_setnetent(void* pms)
{
	ms_ocall_setnetent_t* ms = SGX_CAST(ms_ocall_setnetent_t*, pms);
	ocall_setnetent(ms->ms_stay_open);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_endnetent(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_endnetent();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getnetent(void* pms)
{
	ms_ocall_getnetent_t* ms = SGX_CAST(ms_ocall_getnetent_t*, pms);
	ms->ms_retval = ocall_getnetent();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getnetbyaddr(void* pms)
{
	ms_ocall_getnetbyaddr_t* ms = SGX_CAST(ms_ocall_getnetbyaddr_t*, pms);
	ms->ms_retval = ocall_getnetbyaddr(ms->ms_net, ms->ms_type);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getnetbyname(void* pms)
{
	ms_ocall_getnetbyname_t* ms = SGX_CAST(ms_ocall_getnetbyname_t*, pms);
	ms->ms_retval = ocall_getnetbyname((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_setservent(void* pms)
{
	ms_ocall_setservent_t* ms = SGX_CAST(ms_ocall_setservent_t*, pms);
	ocall_setservent(ms->ms_stay_open);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_endservent(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_endservent();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getservent(void* pms)
{
	ms_ocall_getservent_t* ms = SGX_CAST(ms_ocall_getservent_t*, pms);
	ms->ms_retval = ocall_getservent();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getservbyname(void* pms)
{
	ms_ocall_getservbyname_t* ms = SGX_CAST(ms_ocall_getservbyname_t*, pms);
	ms->ms_retval = ocall_getservbyname((const char*)ms->ms_name, (const char*)ms->ms_proto);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getservbyport(void* pms)
{
	ms_ocall_getservbyport_t* ms = SGX_CAST(ms_ocall_getservbyport_t*, pms);
	ms->ms_retval = ocall_getservbyport(ms->ms_port, (const char*)ms->ms_proto);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_setprotoent(void* pms)
{
	ms_ocall_setprotoent_t* ms = SGX_CAST(ms_ocall_setprotoent_t*, pms);
	ocall_setprotoent(ms->ms_stay_open);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_endprotoent(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_endprotoent();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getprotoent(void* pms)
{
	ms_ocall_getprotoent_t* ms = SGX_CAST(ms_ocall_getprotoent_t*, pms);
	ms->ms_retval = ocall_getprotoent();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getprotobyname(void* pms)
{
	ms_ocall_getprotobyname_t* ms = SGX_CAST(ms_ocall_getprotobyname_t*, pms);
	ms->ms_retval = ocall_getprotobyname((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getprotobynumber(void* pms)
{
	ms_ocall_getprotobynumber_t* ms = SGX_CAST(ms_ocall_getprotobynumber_t*, pms);
	ms->ms_retval = ocall_getprotobynumber(ms->ms_proto);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_gai_strerror(void* pms)
{
	ms_ocall_gai_strerror_t* ms = SGX_CAST(ms_ocall_gai_strerror_t*, pms);
	ms->ms_retval = ocall_gai_strerror(ms->ms_ecode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getnameinfo(void* pms)
{
	ms_ocall_getnameinfo_t* ms = SGX_CAST(ms_ocall_getnameinfo_t*, pms);
	ms->ms_retval = ocall_getnameinfo((const struct sockaddr*)ms->ms_sa, ms->ms_salen, ms->ms_host, ms->ms_hostlen, ms->ms_serv, ms->ms_servlen, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_ntohl(void* pms)
{
	ms_ocall_ntohl_t* ms = SGX_CAST(ms_ocall_ntohl_t*, pms);
	ms->ms_retval = ocall_ntohl(ms->ms_netlong);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_ntohs(void* pms)
{
	ms_ocall_ntohs_t* ms = SGX_CAST(ms_ocall_ntohs_t*, pms);
	ms->ms_retval = ocall_ntohs(ms->ms_netshort);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_htonl(void* pms)
{
	ms_ocall_htonl_t* ms = SGX_CAST(ms_ocall_htonl_t*, pms);
	ms->ms_retval = ocall_htonl(ms->ms_hostlong);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_htons(void* pms)
{
	ms_ocall_htons_t* ms = SGX_CAST(ms_ocall_htons_t*, pms);
	ms->ms_retval = ocall_htons(ms->ms_hostshort);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_ioctl(void* pms)
{
	ms_ocall_ioctl_t* ms = SGX_CAST(ms_ocall_ioctl_t*, pms);
	ms->ms_retval = ocall_ioctl(ms->ms_fd, ms->ms_request, ms->ms_arguments);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_readv(void* pms)
{
	ms_ocall_readv_t* ms = SGX_CAST(ms_ocall_readv_t*, pms);
	ms->ms_retval = ocall_readv(ms->ms___fd, (const void*)ms->ms___iovec, ms->ms_iovec_size, ms->ms___count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_writev(void* pms)
{
	ms_ocall_writev_t* ms = SGX_CAST(ms_ocall_writev_t*, pms);
	ms->ms_retval = ocall_writev(ms->ms___fd, ms->ms_iovec_id, ms->ms_iovec_size, ms->ms___count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_init_multiple_iovec_outside(void* pms)
{
	ms_ocall_init_multiple_iovec_outside_t* ms = SGX_CAST(ms_ocall_init_multiple_iovec_outside_t*, pms);
	ms->ms_retval = ocall_init_multiple_iovec_outside((const void*)ms->ms___iovec, ms->ms_iovec_size, ms->ms___count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_copy_base_to_outside(void* pms)
{
	ms_ocall_copy_base_to_outside_t* ms = SGX_CAST(ms_ocall_copy_base_to_outside_t*, pms);
	ocall_copy_base_to_outside(ms->ms_iovec_id, ms->ms_i, (const void*)ms->ms_base, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_free_iovec_outside(void* pms)
{
	ms_ocall_free_iovec_outside_t* ms = SGX_CAST(ms_ocall_free_iovec_outside_t*, pms);
	ocall_free_iovec_outside(ms->ms_iovec_id, ms->ms_iovec_size, ms->ms___count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_process_vm_readv(void* pms)
{
	ms_ocall_process_vm_readv_t* ms = SGX_CAST(ms_ocall_process_vm_readv_t*, pms);
	ms->ms_retval = ocall_process_vm_readv(ms->ms___pid, (const struct iovec*)ms->ms___lvec, ms->ms___liovcnt, (const struct iovec*)ms->ms___rvec, ms->ms___riovcnt, ms->ms___flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_process_vm_writev(void* pms)
{
	ms_ocall_process_vm_writev_t* ms = SGX_CAST(ms_ocall_process_vm_writev_t*, pms);
	ms->ms_retval = ocall_process_vm_writev(ms->ms___pid, (const struct iovec*)ms->ms___lvec, ms->ms___liovcnt, (const struct iovec*)ms->ms___rvec, ms->ms___riovcnt, ms->ms___flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mmap(void* pms)
{
	ms_ocall_mmap_t* ms = SGX_CAST(ms_ocall_mmap_t*, pms);
	ms->ms_retval = ocall_mmap(ms->ms___addr, ms->ms___len, ms->ms___prot, ms->ms___flags, ms->ms___fd, ms->ms___offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mmap64(void* pms)
{
	ms_ocall_mmap64_t* ms = SGX_CAST(ms_ocall_mmap64_t*, pms);
	ms->ms_retval = ocall_mmap64(ms->ms___addr, ms->ms___len, ms->ms___prot, ms->ms___flags, ms->ms___fd, ms->ms___offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_munmap(void* pms)
{
	ms_ocall_munmap_t* ms = SGX_CAST(ms_ocall_munmap_t*, pms);
	ms->ms_retval = ocall_munmap(ms->ms___addr, ms->ms___len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mprotect(void* pms)
{
	ms_ocall_mprotect_t* ms = SGX_CAST(ms_ocall_mprotect_t*, pms);
	ms->ms_retval = ocall_mprotect(ms->ms___addr, ms->ms___len, ms->ms___prot);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_msync(void* pms)
{
	ms_ocall_msync_t* ms = SGX_CAST(ms_ocall_msync_t*, pms);
	ms->ms_retval = ocall_msync(ms->ms___addr, ms->ms___len, ms->ms___flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mlock(void* pms)
{
	ms_ocall_mlock_t* ms = SGX_CAST(ms_ocall_mlock_t*, pms);
	ms->ms_retval = ocall_mlock((const void*)ms->ms___addr, ms->ms___len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_munlock(void* pms)
{
	ms_ocall_munlock_t* ms = SGX_CAST(ms_ocall_munlock_t*, pms);
	ms->ms_retval = ocall_munlock((const void*)ms->ms___addr, ms->ms___len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mlockall(void* pms)
{
	ms_ocall_mlockall_t* ms = SGX_CAST(ms_ocall_mlockall_t*, pms);
	ms->ms_retval = ocall_mlockall(ms->ms___flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_munlockall(void* pms)
{
	ms_ocall_munlockall_t* ms = SGX_CAST(ms_ocall_munlockall_t*, pms);
	ms->ms_retval = ocall_munlockall();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mincore(void* pms)
{
	ms_ocall_mincore_t* ms = SGX_CAST(ms_ocall_mincore_t*, pms);
	ms->ms_retval = ocall_mincore(ms->ms___start, ms->ms___len, ms->ms___vec);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_shm_open(void* pms)
{
	ms_ocall_shm_open_t* ms = SGX_CAST(ms_ocall_shm_open_t*, pms);
	ms->ms_retval = ocall_shm_open((const char*)ms->ms___name, ms->ms___oflag, ms->ms___mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_shm_unlink(void* pms)
{
	ms_ocall_shm_unlink_t* ms = SGX_CAST(ms_ocall_shm_unlink_t*, pms);
	ms->ms_retval = ocall_shm_unlink((const char*)ms->ms___name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_poll(void* pms)
{
	ms_ocall_poll_t* ms = SGX_CAST(ms_ocall_poll_t*, pms);
	ms->ms_retval = ocall_poll(ms->ms___fds, ms->ms___nfds, ms->ms___timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_create(void* pms)
{
	ms_ocall_epoll_create_t* ms = SGX_CAST(ms_ocall_epoll_create_t*, pms);
	ms->ms_retval = ocall_epoll_create(ms->ms___size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_create1(void* pms)
{
	ms_ocall_epoll_create1_t* ms = SGX_CAST(ms_ocall_epoll_create1_t*, pms);
	ms->ms_retval = ocall_epoll_create1(ms->ms___flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_ctl(void* pms)
{
	ms_ocall_epoll_ctl_t* ms = SGX_CAST(ms_ocall_epoll_ctl_t*, pms);
	ms->ms_retval = ocall_epoll_ctl(ms->ms___epfd, ms->ms___op, ms->ms___fd, ms->ms___event, ms->ms_event_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_wait(void* pms)
{
	ms_ocall_epoll_wait_t* ms = SGX_CAST(ms_ocall_epoll_wait_t*, pms);
	ms->ms_retval = ocall_epoll_wait(ms->ms___epfd, ms->ms___events, ms->ms_event_size, ms->ms___maxevents, ms->ms___timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_wait1(void* pms)
{
	ms_ocall_epoll_wait1_t* ms = SGX_CAST(ms_ocall_epoll_wait1_t*, pms);
	ms->ms_retval = ocall_epoll_wait1(ms->ms___epfd, ms->ms___events, ms->ms_event_size, ms->ms___maxevents, ms->ms___timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_wait2(void* pms)
{
	ms_ocall_epoll_wait2_t* ms = SGX_CAST(ms_ocall_epoll_wait2_t*, pms);
	ms->ms_retval = ocall_epoll_wait2(ms->ms___epfd, ms->ms___events, ms->ms_event_size, ms->ms___maxevents, ms->ms___timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_wait3(void* pms)
{
	ms_ocall_epoll_wait3_t* ms = SGX_CAST(ms_ocall_epoll_wait3_t*, pms);
	ms->ms_retval = ocall_epoll_wait3(ms->ms___epfd, ms->ms___events, ms->ms_event_size, ms->ms___maxevents, ms->ms___timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_wait4(void* pms)
{
	ms_ocall_epoll_wait4_t* ms = SGX_CAST(ms_ocall_epoll_wait4_t*, pms);
	ms->ms_retval = ocall_epoll_wait4(ms->ms___epfd, ms->ms___events, ms->ms_event_size, ms->ms___maxevents, ms->ms___timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_wait5(void* pms)
{
	ms_ocall_epoll_wait5_t* ms = SGX_CAST(ms_ocall_epoll_wait5_t*, pms);
	ms->ms_retval = ocall_epoll_wait5(ms->ms___epfd, ms->ms___events, ms->ms_event_size, ms->ms___maxevents, ms->ms___timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_wait6(void* pms)
{
	ms_ocall_epoll_wait6_t* ms = SGX_CAST(ms_ocall_epoll_wait6_t*, pms);
	ms->ms_retval = ocall_epoll_wait6(ms->ms___epfd, ms->ms___events, ms->ms_event_size, ms->ms___maxevents, ms->ms___timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_wait7(void* pms)
{
	ms_ocall_epoll_wait7_t* ms = SGX_CAST(ms_ocall_epoll_wait7_t*, pms);
	ms->ms_retval = ocall_epoll_wait7(ms->ms___epfd, ms->ms___events, ms->ms_event_size, ms->ms___maxevents, ms->ms___timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_epoll_pwait(void* pms)
{
	ms_ocall_epoll_pwait_t* ms = SGX_CAST(ms_ocall_epoll_pwait_t*, pms);
	ms->ms_retval = ocall_epoll_pwait(ms->ms___epfd, ms->ms___events, ms->ms_event_size, ms->ms___maxevents, ms->ms___timeout, ms->ms___ss, ms->ms_sigset_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_select(void* pms)
{
	ms_ocall_select_t* ms = SGX_CAST(ms_ocall_select_t*, pms);
	ms->ms_retval = ocall_select(ms->ms___nfds, ms->ms___readfds, ms->ms___writefds, ms->ms___exceptfds, ms->ms___timeout, ms->ms_tvsize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sendfile(void* pms)
{
	ms_ocall_sendfile_t* ms = SGX_CAST(ms_ocall_sendfile_t*, pms);
	ms->ms_retval = ocall_sendfile(ms->ms_out_fd, ms->ms_in_fd, ms->ms_offset, ms->ms_count);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_waitpid(void* pms)
{
	ms_ocall_waitpid_t* ms = SGX_CAST(ms_ocall_waitpid_t*, pms);
	ms->ms_retval = ocall_waitpid(ms->ms___pid, ms->ms___stat_loc, ms->ms___options);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_waitid(void* pms)
{
	ms_ocall_waitid_t* ms = SGX_CAST(ms_ocall_waitid_t*, pms);
	ms->ms_retval = ocall_waitid(ms->ms___idtype, ms->ms___id, ms->ms___infop, ms->ms___options);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_wait(void* pms)
{
	ms_ocall_wait_t* ms = SGX_CAST(ms_ocall_wait_t*, pms);
	ms->ms_retval = ocall_wait(ms->ms_wstatus);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_stat(void* pms)
{
	ms_ocall_stat_t* ms = SGX_CAST(ms_ocall_stat_t*, pms);
	ms->ms_retval = ocall_stat((const char*)ms->ms_path, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fstat(void* pms)
{
	ms_ocall_fstat_t* ms = SGX_CAST(ms_ocall_fstat_t*, pms);
	ms->ms_retval = ocall_fstat(ms->ms_fd, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_lstat(void* pms)
{
	ms_ocall_lstat_t* ms = SGX_CAST(ms_ocall_lstat_t*, pms);
	ms->ms_retval = ocall_lstat((const char*)ms->ms_path, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_chmod(void* pms)
{
	ms_ocall_chmod_t* ms = SGX_CAST(ms_ocall_chmod_t*, pms);
	ms->ms_retval = ocall_chmod((const char*)ms->ms_file, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fchmod(void* pms)
{
	ms_ocall_fchmod_t* ms = SGX_CAST(ms_ocall_fchmod_t*, pms);
	ms->ms_retval = ocall_fchmod(ms->ms_fd, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fchmodat(void* pms)
{
	ms_ocall_fchmodat_t* ms = SGX_CAST(ms_ocall_fchmodat_t*, pms);
	ms->ms_retval = ocall_fchmodat(ms->ms_fd, (const char*)ms->ms_file, ms->ms_mode, ms->ms_flag);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_umask(void* pms)
{
	ms_ocall_umask_t* ms = SGX_CAST(ms_ocall_umask_t*, pms);
	ms->ms_retval = ocall_umask(ms->ms_mask);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mkdir(void* pms)
{
	ms_ocall_mkdir_t* ms = SGX_CAST(ms_ocall_mkdir_t*, pms);
	ms->ms_retval = ocall_mkdir((const char*)ms->ms_path, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mkdirat(void* pms)
{
	ms_ocall_mkdirat_t* ms = SGX_CAST(ms_ocall_mkdirat_t*, pms);
	ms->ms_retval = ocall_mkdirat(ms->ms_fd, (const char*)ms->ms_path, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mkfifo(void* pms)
{
	ms_ocall_mkfifo_t* ms = SGX_CAST(ms_ocall_mkfifo_t*, pms);
	ms->ms_retval = ocall_mkfifo((const char*)ms->ms_path, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_mkfifoat(void* pms)
{
	ms_ocall_mkfifoat_t* ms = SGX_CAST(ms_ocall_mkfifoat_t*, pms);
	ms->ms_retval = ocall_mkfifoat(ms->ms_fd, (const char*)ms->ms_path, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_utime(void* pms)
{
	ms_ocall_utime_t* ms = SGX_CAST(ms_ocall_utime_t*, pms);
	ms->ms_retval = ocall_utime((const char*)ms->ms_filename, (const struct utimbuf*)ms->ms_times);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_opendir(void* pms)
{
	ms_ocall_opendir_t* ms = SGX_CAST(ms_ocall_opendir_t*, pms);
	ms->ms_retval = ocall_opendir((const char*)ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fdopendir(void* pms)
{
	ms_ocall_fdopendir_t* ms = SGX_CAST(ms_ocall_fdopendir_t*, pms);
	ms->ms_retval = ocall_fdopendir(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_closedir(void* pms)
{
	ms_ocall_closedir_t* ms = SGX_CAST(ms_ocall_closedir_t*, pms);
	ms->ms_retval = ocall_closedir(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_readdir(void* pms)
{
	ms_ocall_readdir_t* ms = SGX_CAST(ms_ocall_readdir_t*, pms);
	ms->ms_retval = ocall_readdir(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_readdir_r(void* pms)
{
	ms_ocall_readdir_r_t* ms = SGX_CAST(ms_ocall_readdir_r_t*, pms);
	ms->ms_retval = ocall_readdir_r(ms->ms_dirp, ms->ms_entry, ms->ms_result);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_rewinddir(void* pms)
{
	ms_ocall_rewinddir_t* ms = SGX_CAST(ms_ocall_rewinddir_t*, pms);
	ocall_rewinddir(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_seekdir(void* pms)
{
	ms_ocall_seekdir_t* ms = SGX_CAST(ms_ocall_seekdir_t*, pms);
	ocall_seekdir(ms->ms_dirp, ms->ms_pos);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_telldir(void* pms)
{
	ms_ocall_telldir_t* ms = SGX_CAST(ms_ocall_telldir_t*, pms);
	ms->ms_retval = ocall_telldir(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_dirfd(void* pms)
{
	ms_ocall_dirfd_t* ms = SGX_CAST(ms_ocall_dirfd_t*, pms);
	ms->ms_retval = ocall_dirfd(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_alphasort(void* pms)
{
	ms_ocall_alphasort_t* ms = SGX_CAST(ms_ocall_alphasort_t*, pms);
	ms->ms_retval = ocall_alphasort((const struct dirent**)ms->ms_e1, (const struct dirent**)ms->ms_e2);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getdirentries(void* pms)
{
	ms_ocall_getdirentries_t* ms = SGX_CAST(ms_ocall_getdirentries_t*, pms);
	ms->ms_retval = ocall_getdirentries(ms->ms_fd, ms->ms_buf, ms->ms_nbytes, ms->ms_basep);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_versionsort(void* pms)
{
	ms_ocall_versionsort_t* ms = SGX_CAST(ms_ocall_versionsort_t*, pms);
	ms->ms_retval = ocall_versionsort((const struct dirent**)ms->ms_e1, (const struct dirent**)ms->ms_e2);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_prlimit(void* pms)
{
	ms_ocall_prlimit_t* ms = SGX_CAST(ms_ocall_prlimit_t*, pms);
	ms->ms_retval = ocall_prlimit(ms->ms_pid, ms->ms_resource, (const struct rlimit*)ms->ms_new_limit, ms->ms_old_limit);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getrlimit(void* pms)
{
	ms_ocall_getrlimit_t* ms = SGX_CAST(ms_ocall_getrlimit_t*, pms);
	ms->ms_retval = ocall_getrlimit(ms->ms_resource, ms->ms_rlim);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_setrlimit(void* pms)
{
	ms_ocall_setrlimit_t* ms = SGX_CAST(ms_ocall_setrlimit_t*, pms);
	ms->ms_retval = ocall_setrlimit(ms->ms_resource, (const struct rlimit*)ms->ms_rlim);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_inet_addr(void* pms)
{
	ms_ocall_inet_addr_t* ms = SGX_CAST(ms_ocall_inet_addr_t*, pms);
	ms->ms_retval = ocall_inet_addr((const char*)ms->ms_cp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_inet_lnaof(void* pms)
{
	ms_ocall_inet_lnaof_t* ms = SGX_CAST(ms_ocall_inet_lnaof_t*, pms);
	ms->ms_retval = ocall_inet_lnaof(ms->ms_in);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_inet_makeaddr(void* pms)
{
	ms_ocall_inet_makeaddr_t* ms = SGX_CAST(ms_ocall_inet_makeaddr_t*, pms);
	ms->ms_retval = ocall_inet_makeaddr(ms->ms_net, ms->ms_host);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_inet_netof(void* pms)
{
	ms_ocall_inet_netof_t* ms = SGX_CAST(ms_ocall_inet_netof_t*, pms);
	ms->ms_retval = ocall_inet_netof(ms->ms_in);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_inet_network(void* pms)
{
	ms_ocall_inet_network_t* ms = SGX_CAST(ms_ocall_inet_network_t*, pms);
	ms->ms_retval = ocall_inet_network((const char*)ms->ms_cp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_inet_ntoa(void* pms)
{
	ms_ocall_inet_ntoa_t* ms = SGX_CAST(ms_ocall_inet_ntoa_t*, pms);
	ms->ms_retval = ocall_inet_ntoa(ms->ms_in);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_inet_pton(void* pms)
{
	ms_ocall_inet_pton_t* ms = SGX_CAST(ms_ocall_inet_pton_t*, pms);
	ms->ms_retval = ocall_inet_pton(ms->ms_af, (const char*)ms->ms_cp, ms->ms_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_inet_ntop(void* pms)
{
	ms_ocall_inet_ntop_t* ms = SGX_CAST(ms_ocall_inet_ntop_t*, pms);
	ms->ms_retval = ocall_inet_ntop(ms->ms_af, (const void*)ms->ms_cp, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sysctl(void* pms)
{
	ms_ocall_sysctl_t* ms = SGX_CAST(ms_ocall_sysctl_t*, pms);
	ms->ms_retval = ocall_sysctl(ms->ms_name, ms->ms_nlen, ms->ms_oldval, ms->ms_oldlenp, ms->ms_newval, ms->ms_newlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sigemptyset(void* pms)
{
	ms_ocall_sigemptyset_t* ms = SGX_CAST(ms_ocall_sigemptyset_t*, pms);
	ms->ms_retval = ocall_sigemptyset(ms->ms_set);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sigfillset(void* pms)
{
	ms_ocall_sigfillset_t* ms = SGX_CAST(ms_ocall_sigfillset_t*, pms);
	ms->ms_retval = ocall_sigfillset(ms->ms_set);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sigaddset(void* pms)
{
	ms_ocall_sigaddset_t* ms = SGX_CAST(ms_ocall_sigaddset_t*, pms);
	ms->ms_retval = ocall_sigaddset(ms->ms_set, ms->ms_signo);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sigdelset(void* pms)
{
	ms_ocall_sigdelset_t* ms = SGX_CAST(ms_ocall_sigdelset_t*, pms);
	ms->ms_retval = ocall_sigdelset(ms->ms_set, ms->ms_signo);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sigismember(void* pms)
{
	ms_ocall_sigismember_t* ms = SGX_CAST(ms_ocall_sigismember_t*, pms);
	ms->ms_retval = ocall_sigismember((const sigset_t*)ms->ms_set, ms->ms_signo);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sigsuspend(void* pms)
{
	ms_ocall_sigsuspend_t* ms = SGX_CAST(ms_ocall_sigsuspend_t*, pms);
	ms->ms_retval = ocall_sigsuspend((const sigset_t*)ms->ms_set);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sigaction(void* pms)
{
	ms_ocall_sigaction_t* ms = SGX_CAST(ms_ocall_sigaction_t*, pms);
	ms->ms_retval = ocall_sigaction(ms->ms_sig, (const struct sigaction*)ms->ms_act, ms->ms_oact);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sigpending(void* pms)
{
	ms_ocall_sigpending_t* ms = SGX_CAST(ms_ocall_sigpending_t*, pms);
	ms->ms_retval = ocall_sigpending(ms->ms_set);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sigwait(void* pms)
{
	ms_ocall_sigwait_t* ms = SGX_CAST(ms_ocall_sigwait_t*, pms);
	ms->ms_retval = ocall_sigwait((const sigset_t*)ms->ms_set, ms->ms_sig);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_signal_generic(void* pms)
{
	ms_ocall_signal_generic_t* ms = SGX_CAST(ms_ocall_signal_generic_t*, pms);
	ms->ms_retval = ocall_signal_generic(ms->ms___sig, ms->ms___handler);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_sigaction_generic(void* pms)
{
	ms_ocall_sigaction_generic_t* ms = SGX_CAST(ms_ocall_sigaction_generic_t*, pms);
	ms->ms_retval = ocall_sigaction_generic(ms->ms_sig, ms->ms_act, ms->ms_oact);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_signal(void* pms)
{
	ms_ocall_signal_t* ms = SGX_CAST(ms_ocall_signal_t*, pms);
	ms->ms_retval = ocall_signal(ms->ms___sig, ms->ms___handler);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_raise(void* pms)
{
	ms_ocall_raise_t* ms = SGX_CAST(ms_ocall_raise_t*, pms);
	ms->ms_retval = ocall_raise(ms->ms_sig);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_kill(void* pms)
{
	ms_ocall_kill_t* ms = SGX_CAST(ms_ocall_kill_t*, pms);
	ms->ms_retval = ocall_kill(ms->ms_pid, ms->ms_sig);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pmap_set(void* pms)
{
	ms_ocall_pmap_set_t* ms = SGX_CAST(ms_ocall_pmap_set_t*, pms);
	ms->ms_retval = ocall_pmap_set(ms->ms_prognum, ms->ms_versnum, ms->ms_protocol, ms->ms_port);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pmap_unset(void* pms)
{
	ms_ocall_pmap_unset_t* ms = SGX_CAST(ms_ocall_pmap_unset_t*, pms);
	ms->ms_retval = ocall_pmap_unset(ms->ms_prognum, ms->ms_versnum);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_pmap_getport(void* pms)
{
	ms_ocall_pmap_getport_t* ms = SGX_CAST(ms_ocall_pmap_getport_t*, pms);
	ms->ms_retval = ocall_pmap_getport(ms->ms_addr, ms->ms_prognum, ms->ms_versnum, ms->ms_protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svcudp_create(void* pms)
{
	ms_ocall_svcudp_create_t* ms = SGX_CAST(ms_ocall_svcudp_create_t*, pms);
	ms->ms_retval = ocall_svcudp_create(ms->ms___sock);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svc_run(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_svc_run();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svctcp_create(void* pms)
{
	ms_ocall_svctcp_create_t* ms = SGX_CAST(ms_ocall_svctcp_create_t*, pms);
	ms->ms_retval = ocall_svctcp_create(ms->ms___sock, ms->ms___sendsize, ms->ms___recvsize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svc_register(void* pms)
{
	ms_ocall_svc_register_t* ms = SGX_CAST(ms_ocall_svc_register_t*, pms);
	ms->ms_retval = ocall_svc_register(ms->ms___xprt, ms->ms___prog, ms->ms___vers, ms->ms___dispatch, ms->ms___protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svc_register_generic(void* pms)
{
	ms_ocall_svc_register_generic_t* ms = SGX_CAST(ms_ocall_svc_register_generic_t*, pms);
	ms->ms_retval = ocall_svc_register_generic(ms->ms___xprt, ms->ms___prog, ms->ms___vers, ms->ms___dispatch, ms->ms___protocol);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_clnt_create(void* pms)
{
	ms_ocall_clnt_create_t* ms = SGX_CAST(ms_ocall_clnt_create_t*, pms);
	ms->ms_retval = ocall_clnt_create((const char*)ms->ms___host, ms->ms___prog, ms->ms___vers, (const char*)ms->ms___prot);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_clnt_perror(void* pms)
{
	ms_ocall_clnt_perror_t* ms = SGX_CAST(ms_ocall_clnt_perror_t*, pms);
	ocall_clnt_perror(ms->ms___clnt, (const char*)ms->ms___msg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_clnt_pcreateerror(void* pms)
{
	ms_ocall_clnt_pcreateerror_t* ms = SGX_CAST(ms_ocall_clnt_pcreateerror_t*, pms);
	ocall_clnt_pcreateerror((const char*)ms->ms___msg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_callrpc(void* pms)
{
	ms_ocall_callrpc_t* ms = SGX_CAST(ms_ocall_callrpc_t*, pms);
	ms->ms_retval = ocall_callrpc((const char*)ms->ms___host, ms->ms___prognum, ms->ms___versnum, ms->ms___procnum, ms->ms___inproc, (const char*)ms->ms___in, ms->ms___outproc, ms->ms___out);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svc_sendreply(void* pms)
{
	ms_ocall_svc_sendreply_t* ms = SGX_CAST(ms_ocall_svc_sendreply_t*, pms);
	ms->ms_retval = ocall_svc_sendreply(ms->ms___xprt, ms->ms___xdr_results, ms->ms___xdr_location);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svcerr_noproc(void* pms)
{
	ms_ocall_svcerr_noproc_t* ms = SGX_CAST(ms_ocall_svcerr_noproc_t*, pms);
	ocall_svcerr_noproc(ms->ms___xprt);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svcerr_decode(void* pms)
{
	ms_ocall_svcerr_decode_t* ms = SGX_CAST(ms_ocall_svcerr_decode_t*, pms);
	ocall_svcerr_decode(ms->ms___xprt);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svcerr_systemerr(void* pms)
{
	ms_ocall_svcerr_systemerr_t* ms = SGX_CAST(ms_ocall_svcerr_systemerr_t*, pms);
	ocall_svcerr_systemerr(ms->ms___xprt);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_clnt_call(void* pms)
{
	ms_ocall_clnt_call_t* ms = SGX_CAST(ms_ocall_clnt_call_t*, pms);
	ms->ms_retval = ocall_clnt_call(ms->ms_rh, ms->ms_proc, ms->ms_xargs, ms->ms_argsp, ms->ms_xres, ms->ms_resp, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_fast_clnt_call(void* pms)
{
	ms_ocall_fast_clnt_call_t* ms = SGX_CAST(ms_ocall_fast_clnt_call_t*, pms);
	ocall_fast_clnt_call(ms->ms_proc);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_clnt_control(void* pms)
{
	ms_ocall_clnt_control_t* ms = SGX_CAST(ms_ocall_clnt_control_t*, pms);
	ms->ms_retval = ocall_clnt_control(ms->ms_cl, ms->ms_rq, ms->ms_in, ms->ms_in_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svc_getargs(void* pms)
{
	ms_ocall_svc_getargs_t* ms = SGX_CAST(ms_ocall_svc_getargs_t*, pms);
	ms->ms_retval = ocall_svc_getargs(ms->ms_xprt, ms->ms_xargs, ms->ms_argsp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_svc_freeargs(void* pms)
{
	ms_ocall_svc_freeargs_t* ms = SGX_CAST(ms_ocall_svc_freeargs_t*, pms);
	ms->ms_retval = ocall_svc_freeargs(ms->ms_xprt, ms->ms_xargs, ms->ms_argsp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_getifaddrs(void* pms)
{
	ms_ocall_getifaddrs_t* ms = SGX_CAST(ms_ocall_getifaddrs_t*, pms);
	ms->ms_retval = ocall_getifaddrs(ms->ms_ifap);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_freeifaddrs(void* pms)
{
	ms_ocall_freeifaddrs_t* ms = SGX_CAST(ms_ocall_freeifaddrs_t*, pms);
	ocall_freeifaddrs(ms->ms_ifa);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_if_nametoindex(void* pms)
{
	ms_ocall_if_nametoindex_t* ms = SGX_CAST(ms_ocall_if_nametoindex_t*, pms);
	ms->ms_retval = ocall_if_nametoindex((const char*)ms->ms_ifname);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_if_indextoname(void* pms)
{
	ms_ocall_if_indextoname_t* ms = SGX_CAST(ms_ocall_if_indextoname_t*, pms);
	ms->ms_retval = ocall_if_indextoname(ms->ms_ifindex, ms->ms_ifname);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_if_nameindex(void* pms)
{
	ms_ocall_if_nameindex_t* ms = SGX_CAST(ms_ocall_if_nameindex_t*, pms);
	ms->ms_retval = ocall_if_nameindex();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL MyEnclave_ocall_if_freenameindex(void* pms)
{
	ms_ocall_if_freenameindex_t* ms = SGX_CAST(ms_ocall_if_freenameindex_t*, pms);
	ocall_if_freenameindex(ms->ms_ptr);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[335];
} ocall_table_MyEnclave = {
	335,
	{
		(void*)MyEnclave_do_execve,
		(void*)MyEnclave_do_execlp,
		(void*)MyEnclave_printf_string,
		(void*)MyEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)MyEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)MyEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)MyEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)MyEnclave_ocall_pthread_create,
		(void*)MyEnclave_ocall_pthread_self,
		(void*)MyEnclave_ocall_pthread_join,
		(void*)MyEnclave_ocall_pthread_detach,
		(void*)MyEnclave_ocall_pthread_equal,
		(void*)MyEnclave_ocall_pthread_exit,
		(void*)MyEnclave_ocall_pthread_cancel,
		(void*)MyEnclave_ocall_pthread_testcancel,
		(void*)MyEnclave_ocall_pthread_attr_init,
		(void*)MyEnclave_ocall_pthread_attr_destroy,
		(void*)MyEnclave_ocall_pthread_attr_getdetachstate,
		(void*)MyEnclave_ocall_pthread_attr_setdetachstate,
		(void*)MyEnclave_ocall_pthread_attr_getguardsize,
		(void*)MyEnclave_ocall_pthread_attr_setguardsize,
		(void*)MyEnclave_ocall_pthread_attr_getschedpolicy,
		(void*)MyEnclave_ocall_pthread_attr_setschedpolicy,
		(void*)MyEnclave_ocall_pthread_attr_getstacksize,
		(void*)MyEnclave_ocall_pthread_attr_setstacksize,
		(void*)MyEnclave_ocall_pthread_setspecific,
		(void*)MyEnclave_ocall_pthread_getspecific,
		(void*)MyEnclave_ocall_pthread_key_create,
		(void*)MyEnclave_ocall_time,
		(void*)MyEnclave_ocall_gettimeofday,
		(void*)MyEnclave_ocall_gettimeofday2,
		(void*)MyEnclave_ocall_clock,
		(void*)MyEnclave_ocall_gmtime_r,
		(void*)MyEnclave_ocall_localtime_r,
		(void*)MyEnclave_ocall_mktime,
		(void*)MyEnclave_ocall_getitimer,
		(void*)MyEnclave_ocall_setitimer,
		(void*)MyEnclave_ocall_nanosleep,
		(void*)MyEnclave_wrapper_getopt,
		(void*)MyEnclave_set_optind,
		(void*)MyEnclave_set_opterr,
		(void*)MyEnclave_set_optopt,
		(void*)MyEnclave_set_optreset,
		(void*)MyEnclave_get_optarg,
		(void*)MyEnclave_ocall_get_optind,
		(void*)MyEnclave_ocall_get_opterr,
		(void*)MyEnclave_ocall_get_optopt,
		(void*)MyEnclave_ocall_getpwuid,
		(void*)MyEnclave_ocall_getpwnam,
		(void*)MyEnclave_ocall_getpwnam_r,
		(void*)MyEnclave_ocall_getgrgid,
		(void*)MyEnclave_ocall_initgroups,
		(void*)MyEnclave_ocall_uname,
		(void*)MyEnclave_ocall_getenv,
		(void*)MyEnclave_ocall_putenv,
		(void*)MyEnclave_ocall_clearenv,
		(void*)MyEnclave_ocall_setenv,
		(void*)MyEnclave_ocall_unsetenv,
		(void*)MyEnclave_ocall_mkstemp,
		(void*)MyEnclave_ocall_mkdtemp,
		(void*)MyEnclave_ocall_open1,
		(void*)MyEnclave_ocall_open2,
		(void*)MyEnclave_ocall_creat,
		(void*)MyEnclave_ocall_openat1,
		(void*)MyEnclave_ocall_openat2,
		(void*)MyEnclave_ocall_fcntl1,
		(void*)MyEnclave_ocall_fcntl2,
		(void*)MyEnclave_ocall_fcntl3,
		(void*)MyEnclave_ocall_gethostname,
		(void*)MyEnclave_ocall_sethostname,
		(void*)MyEnclave_ocall_lseek,
		(void*)MyEnclave_get_buff_addr,
		(void*)MyEnclave_ocall_fast_write,
		(void*)MyEnclave_ocall_fast_read,
		(void*)MyEnclave_ocall_read,
		(void*)MyEnclave_ocall_write,
		(void*)MyEnclave_ocall_read1,
		(void*)MyEnclave_ocall_write1,
		(void*)MyEnclave_ocall_read2,
		(void*)MyEnclave_ocall_write2,
		(void*)MyEnclave_ocall_read3,
		(void*)MyEnclave_ocall_write3,
		(void*)MyEnclave_ocall_read4,
		(void*)MyEnclave_ocall_write4,
		(void*)MyEnclave_ocall_read5,
		(void*)MyEnclave_ocall_write5,
		(void*)MyEnclave_ocall_read6,
		(void*)MyEnclave_ocall_write6,
		(void*)MyEnclave_ocall_read7,
		(void*)MyEnclave_ocall_write7,
		(void*)MyEnclave_ocall_close,
		(void*)MyEnclave_ocall_getpid,
		(void*)MyEnclave_ocall_getppid,
		(void*)MyEnclave_ocall_pread,
		(void*)MyEnclave_ocall_pwrite,
		(void*)MyEnclave_ocall_pipe,
		(void*)MyEnclave_ocall_pipe2,
		(void*)MyEnclave_ocall_sleep,
		(void*)MyEnclave_ocall_usleep,
		(void*)MyEnclave_ocall_chown,
		(void*)MyEnclave_ocall_fchown,
		(void*)MyEnclave_ocall_lchown,
		(void*)MyEnclave_ocall_chdir,
		(void*)MyEnclave_ocall_fchdir,
		(void*)MyEnclave_ocall_get_current_dir_name,
		(void*)MyEnclave_ocall_dup,
		(void*)MyEnclave_ocall_dup2,
		(void*)MyEnclave_ocall_dup3,
		(void*)MyEnclave_ocall_getuid,
		(void*)MyEnclave_ocall_geteuid,
		(void*)MyEnclave_ocall_getgid,
		(void*)MyEnclave_ocall_getegid,
		(void*)MyEnclave_ocall_getpagesize,
		(void*)MyEnclave_ocall_getcwd,
		(void*)MyEnclave_ocall_unlink,
		(void*)MyEnclave_ocall_rmdir,
		(void*)MyEnclave_ocall__exit,
		(void*)MyEnclave_ocall_exit,
		(void*)MyEnclave_ocall_sysconf,
		(void*)MyEnclave_ocall_setgid,
		(void*)MyEnclave_ocall_setuid,
		(void*)MyEnclave_ocall_execvp,
		(void*)MyEnclave_ocall_ftruncate,
		(void*)MyEnclave_ocall_free,
		(void*)MyEnclave_ocall_geterrno,
		(void*)MyEnclave_ocall_fsync,
		(void*)MyEnclave_ocall_alarm,
		(void*)MyEnclave_ocall_copy_arg,
		(void*)MyEnclave_ocall_mknod,
		(void*)MyEnclave_ocall_isatty,
		(void*)MyEnclave_ocall_malloc,
		(void*)MyEnclave_ocall_fopen,
		(void*)MyEnclave_ocall_popen,
		(void*)MyEnclave_ocall_fclose,
		(void*)MyEnclave_ocall_pclose,
		(void*)MyEnclave_ocall_fputs,
		(void*)MyEnclave_ocall_feof,
		(void*)MyEnclave_ocall_rewind,
		(void*)MyEnclave_ocall_fflush,
		(void*)MyEnclave_ocall_fread,
		(void*)MyEnclave_ocall_fwrite,
		(void*)MyEnclave_ocall_vfprintf,
		(void*)MyEnclave_ocall_vprintf,
		(void*)MyEnclave_ocall_fgets,
		(void*)MyEnclave_ocall_fgetc,
		(void*)MyEnclave_ocall_ungetc,
		(void*)MyEnclave_ocall_getc_unlocked,
		(void*)MyEnclave_ocall_flockfile,
		(void*)MyEnclave_ocall_funlockfile,
		(void*)MyEnclave_ocall_vsprintf,
		(void*)MyEnclave_ocall_vasprintf,
		(void*)MyEnclave_ocall_ftello,
		(void*)MyEnclave_ocall_fseeko,
		(void*)MyEnclave_ocall_ftell,
		(void*)MyEnclave_ocall_fseek,
		(void*)MyEnclave_ocall_ferror,
		(void*)MyEnclave_ocall_perror,
		(void*)MyEnclave_ocall_getc,
		(void*)MyEnclave_ocall_vfscanf,
		(void*)MyEnclave_ocall_vscanf,
		(void*)MyEnclave_ocall_vsscanf,
		(void*)MyEnclave_ocall_putchar,
		(void*)MyEnclave_ocall_putc,
		(void*)MyEnclave_ocall_puts,
		(void*)MyEnclave_ocall_fputc,
		(void*)MyEnclave_ocall_fdopen,
		(void*)MyEnclave_ocall_fileno,
		(void*)MyEnclave_ocall_rename,
		(void*)MyEnclave_ocall_remove,
		(void*)MyEnclave_ocall_tempnam,
		(void*)MyEnclave_ocall_print_string,
		(void*)MyEnclave_ocall_fprint_string,
		(void*)MyEnclave_ocall_eventfd,
		(void*)MyEnclave_ocall_socket,
		(void*)MyEnclave_ocall_accept,
		(void*)MyEnclave_ocall_connect,
		(void*)MyEnclave_ocall_sendto,
		(void*)MyEnclave_ocall_recv,
		(void*)MyEnclave_ocall_send,
		(void*)MyEnclave_ocall_socketpair,
		(void*)MyEnclave_ocall_setsockopt,
		(void*)MyEnclave_ocall_getsockopt,
		(void*)MyEnclave_ocall_shutdown,
		(void*)MyEnclave_ocall_bind,
		(void*)MyEnclave_ocall_bind_untrusted,
		(void*)MyEnclave_ocall_listen,
		(void*)MyEnclave_ocall_getsockname,
		(void*)MyEnclave_ocall_getpeername,
		(void*)MyEnclave_ocall_recvfrom,
		(void*)MyEnclave_ocall_sendmsg,
		(void*)MyEnclave_ocall_recvmsg,
		(void*)MyEnclave_ocall_freeaddrinfo,
		(void*)MyEnclave_ocall_getaddrinfo,
		(void*)MyEnclave_ocall_getaddrinfo1,
		(void*)MyEnclave_ocall_sethostent,
		(void*)MyEnclave_ocall_endhostent,
		(void*)MyEnclave_ocall_gethostent,
		(void*)MyEnclave_ocall_gethostbyaddr,
		(void*)MyEnclave_ocall_gethostbyname,
		(void*)MyEnclave_ocall_setnetent,
		(void*)MyEnclave_ocall_endnetent,
		(void*)MyEnclave_ocall_getnetent,
		(void*)MyEnclave_ocall_getnetbyaddr,
		(void*)MyEnclave_ocall_getnetbyname,
		(void*)MyEnclave_ocall_setservent,
		(void*)MyEnclave_ocall_endservent,
		(void*)MyEnclave_ocall_getservent,
		(void*)MyEnclave_ocall_getservbyname,
		(void*)MyEnclave_ocall_getservbyport,
		(void*)MyEnclave_ocall_setprotoent,
		(void*)MyEnclave_ocall_endprotoent,
		(void*)MyEnclave_ocall_getprotoent,
		(void*)MyEnclave_ocall_getprotobyname,
		(void*)MyEnclave_ocall_getprotobynumber,
		(void*)MyEnclave_ocall_gai_strerror,
		(void*)MyEnclave_ocall_getnameinfo,
		(void*)MyEnclave_ocall_ntohl,
		(void*)MyEnclave_ocall_ntohs,
		(void*)MyEnclave_ocall_htonl,
		(void*)MyEnclave_ocall_htons,
		(void*)MyEnclave_ocall_ioctl,
		(void*)MyEnclave_ocall_readv,
		(void*)MyEnclave_ocall_writev,
		(void*)MyEnclave_ocall_init_multiple_iovec_outside,
		(void*)MyEnclave_ocall_copy_base_to_outside,
		(void*)MyEnclave_ocall_free_iovec_outside,
		(void*)MyEnclave_ocall_process_vm_readv,
		(void*)MyEnclave_ocall_process_vm_writev,
		(void*)MyEnclave_ocall_mmap,
		(void*)MyEnclave_ocall_mmap64,
		(void*)MyEnclave_ocall_munmap,
		(void*)MyEnclave_ocall_mprotect,
		(void*)MyEnclave_ocall_msync,
		(void*)MyEnclave_ocall_mlock,
		(void*)MyEnclave_ocall_munlock,
		(void*)MyEnclave_ocall_mlockall,
		(void*)MyEnclave_ocall_munlockall,
		(void*)MyEnclave_ocall_mincore,
		(void*)MyEnclave_ocall_shm_open,
		(void*)MyEnclave_ocall_shm_unlink,
		(void*)MyEnclave_ocall_poll,
		(void*)MyEnclave_ocall_epoll_create,
		(void*)MyEnclave_ocall_epoll_create1,
		(void*)MyEnclave_ocall_epoll_ctl,
		(void*)MyEnclave_ocall_epoll_wait,
		(void*)MyEnclave_ocall_epoll_wait1,
		(void*)MyEnclave_ocall_epoll_wait2,
		(void*)MyEnclave_ocall_epoll_wait3,
		(void*)MyEnclave_ocall_epoll_wait4,
		(void*)MyEnclave_ocall_epoll_wait5,
		(void*)MyEnclave_ocall_epoll_wait6,
		(void*)MyEnclave_ocall_epoll_wait7,
		(void*)MyEnclave_ocall_epoll_pwait,
		(void*)MyEnclave_ocall_select,
		(void*)MyEnclave_ocall_sendfile,
		(void*)MyEnclave_ocall_waitpid,
		(void*)MyEnclave_ocall_waitid,
		(void*)MyEnclave_ocall_wait,
		(void*)MyEnclave_ocall_stat,
		(void*)MyEnclave_ocall_fstat,
		(void*)MyEnclave_ocall_lstat,
		(void*)MyEnclave_ocall_chmod,
		(void*)MyEnclave_ocall_fchmod,
		(void*)MyEnclave_ocall_fchmodat,
		(void*)MyEnclave_ocall_umask,
		(void*)MyEnclave_ocall_mkdir,
		(void*)MyEnclave_ocall_mkdirat,
		(void*)MyEnclave_ocall_mkfifo,
		(void*)MyEnclave_ocall_mkfifoat,
		(void*)MyEnclave_ocall_utime,
		(void*)MyEnclave_ocall_opendir,
		(void*)MyEnclave_ocall_fdopendir,
		(void*)MyEnclave_ocall_closedir,
		(void*)MyEnclave_ocall_readdir,
		(void*)MyEnclave_ocall_readdir_r,
		(void*)MyEnclave_ocall_rewinddir,
		(void*)MyEnclave_ocall_seekdir,
		(void*)MyEnclave_ocall_telldir,
		(void*)MyEnclave_ocall_dirfd,
		(void*)MyEnclave_ocall_alphasort,
		(void*)MyEnclave_ocall_getdirentries,
		(void*)MyEnclave_ocall_versionsort,
		(void*)MyEnclave_ocall_prlimit,
		(void*)MyEnclave_ocall_getrlimit,
		(void*)MyEnclave_ocall_setrlimit,
		(void*)MyEnclave_ocall_inet_addr,
		(void*)MyEnclave_ocall_inet_lnaof,
		(void*)MyEnclave_ocall_inet_makeaddr,
		(void*)MyEnclave_ocall_inet_netof,
		(void*)MyEnclave_ocall_inet_network,
		(void*)MyEnclave_ocall_inet_ntoa,
		(void*)MyEnclave_ocall_inet_pton,
		(void*)MyEnclave_ocall_inet_ntop,
		(void*)MyEnclave_ocall_sysctl,
		(void*)MyEnclave_ocall_sigemptyset,
		(void*)MyEnclave_ocall_sigfillset,
		(void*)MyEnclave_ocall_sigaddset,
		(void*)MyEnclave_ocall_sigdelset,
		(void*)MyEnclave_ocall_sigismember,
		(void*)MyEnclave_ocall_sigsuspend,
		(void*)MyEnclave_ocall_sigaction,
		(void*)MyEnclave_ocall_sigpending,
		(void*)MyEnclave_ocall_sigwait,
		(void*)MyEnclave_ocall_signal_generic,
		(void*)MyEnclave_ocall_sigaction_generic,
		(void*)MyEnclave_ocall_signal,
		(void*)MyEnclave_ocall_raise,
		(void*)MyEnclave_ocall_kill,
		(void*)MyEnclave_ocall_pmap_set,
		(void*)MyEnclave_ocall_pmap_unset,
		(void*)MyEnclave_ocall_pmap_getport,
		(void*)MyEnclave_ocall_svcudp_create,
		(void*)MyEnclave_ocall_svc_run,
		(void*)MyEnclave_ocall_svctcp_create,
		(void*)MyEnclave_ocall_svc_register,
		(void*)MyEnclave_ocall_svc_register_generic,
		(void*)MyEnclave_ocall_clnt_create,
		(void*)MyEnclave_ocall_clnt_perror,
		(void*)MyEnclave_ocall_clnt_pcreateerror,
		(void*)MyEnclave_ocall_callrpc,
		(void*)MyEnclave_ocall_svc_sendreply,
		(void*)MyEnclave_ocall_svcerr_noproc,
		(void*)MyEnclave_ocall_svcerr_decode,
		(void*)MyEnclave_ocall_svcerr_systemerr,
		(void*)MyEnclave_ocall_clnt_call,
		(void*)MyEnclave_ocall_fast_clnt_call,
		(void*)MyEnclave_ocall_clnt_control,
		(void*)MyEnclave_ocall_svc_getargs,
		(void*)MyEnclave_ocall_svc_freeargs,
		(void*)MyEnclave_ocall_getifaddrs,
		(void*)MyEnclave_ocall_freeifaddrs,
		(void*)MyEnclave_ocall_if_nametoindex,
		(void*)MyEnclave_ocall_if_indextoname,
		(void*)MyEnclave_ocall_if_nameindex,
		(void*)MyEnclave_ocall_if_freenameindex,
	}
};
sgx_status_t MyEnclave_ecall_execute_job(sgx_enclave_id_t eid, pthread_t pthread_self_id, unsigned long int job_id)
{
	sgx_status_t status;
	ms_ecall_execute_job_t ms;
	ms.ms_pthread_self_id = pthread_self_id;
	ms.ms_job_id = job_id;
	status = sgx_ecall(eid, 0, &ocall_table_MyEnclave, &ms);
	return status;
}

sgx_status_t MyEnclave_ecall_set_enclave_id(sgx_enclave_id_t eid, sgx_enclave_id_t self_eid)
{
	sgx_status_t status;
	ms_ecall_set_enclave_id_t ms;
	ms.ms_self_eid = self_eid;
	status = sgx_ecall(eid, 1, &ocall_table_MyEnclave, &ms);
	return status;
}

sgx_status_t MyEnclave_ecall_bzip2_main(sgx_enclave_id_t eid, int* retval, int argc, char** argv)
{
	sgx_status_t status;
	ms_ecall_bzip2_main_t ms;
	ms.ms_argc = argc;
	ms.ms_argv = argv;
	status = sgx_ecall(eid, 2, &ocall_table_MyEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t MyEnclave_ecall_generic_signal_handler(sgx_enclave_id_t eid, unsigned long int handler_id)
{
	sgx_status_t status;
	ms_ecall_generic_signal_handler_t ms;
	ms.ms_handler_id = handler_id;
	status = sgx_ecall(eid, 3, &ocall_table_MyEnclave, &ms);
	return status;
}

sgx_status_t MyEnclave_ecall_generic_rpc_dispatch_handler(sgx_enclave_id_t eid, unsigned long int handler_id, struct svc_req* rqstp, SVCXPRT* transp)
{
	sgx_status_t status;
	ms_ecall_generic_rpc_dispatch_handler_t ms;
	ms.ms_handler_id = handler_id;
	ms.ms_rqstp = rqstp;
	ms.ms_transp = transp;
	status = sgx_ecall(eid, 4, &ocall_table_MyEnclave, &ms);
	return status;
}

