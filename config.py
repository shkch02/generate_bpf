# config.py

CSV_PATH = 'syscalls_x86_64.csv'
BPF_DIR = 'bpf' # *.bpf.c 파일들이 저장될 디렉토리
OUT_DIR = '.' # 최종 출력 디렉토리 (Makefile, monitor_loader.c)
EVENT_HDR = 'include/common_event.h'
EVENT_HDR_USER = 'include/common_event_user.h'

# Known typedefs that are pointers to structs. Add more as needed.
TYPEDEF_TO_UNDERLYING_TYPE = {
    'cap_user_header_t': 'struct __user_cap_header',
    'cap_user_data_t': 'struct __user_cap_data',
}

SPECIAL_MAP = {}

MANUAL_MAP = {
    '_newselect':  'select',       # kernel has __x64_sys__newselect
    'fstatat64':   'newfstatat',    # kernel has __x64_sys_fstatat64
    'mmap2':       'mmap',         # kernel has __x64_sys_mmap
    'oldfstat':    'fstat',        # kernel has __x64_sys_fstat
    'oldlstat':    'lstat',        # kernel has __x64_sys_lstat
    'oldolduname': 'uname',        # kernel has __x64_sys_uname
    'oldstat':     'stat',         # kernel has __x64_sys_stat
    'olduname': 'uname',          # kernel has __x64_sys_uname
    'readdir':     'getdents',     # kernel has __x64_sys_getdents
    'sigaction':   'rt_sigaction', # kernel has __x64_sys_rt_sigaction
    'sigreturn':   'rt_sigreturn', # kernel has __x64_sys_rt_sigreturn
    'syscall':     'syscall',      # kernel has __x64_sys_syscall
    'ugetrlimit':  'getrlimit',    # kernel has __x64_sys_getrlimit
    'umount2':     'umount',       # kernel has __x64_sys_umount2
}