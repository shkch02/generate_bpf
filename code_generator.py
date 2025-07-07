# code_generator.py
import os
import textwrap
import templates
from config import BPF_DIR, OUT_DIR, EVENT_HDR, EVENT_HDR_USER

# --- 인자 바인딩 생성 ---
def make_bindings(name, types, arg_names):
    """ eBPF 코드에 삽입될 인자 바인딩 C 코드를 생성 """
    # 사용자-공간 typedef → 커널 BTF 매핑
    typedef_map = {
        'socklen_t': '__u32', # __kernel_socklen_t not found in vmlinux.h, use __u32
        'id_t':       '__kernel_pid_t',
        'struct timeval':  'struct __kernel_old_timeval',
        'struct timespec': 'struct __kernel_timespec',
        'enum __ptrace_request': '__s32',
        'nfds_t':     '__u32',
        'caddr_t':    '__u64',
        'off64_t':    '__s64',
        'time_t':     '__kernel_time64_t',
        'clockid_t':  '__kernel_clockid_t',
        'timer_t':    '__kernel_timer_t',
        'dev_t':      '__kernel_dev_t',
        'ino_t':      'u64', # __kernel_ino_t not found in vmlinux.h snippet, use u64
        'mode_t':     'umode_t',
        'uid_t':      '__kernel_uid32_t',
        'gid_t':      '__kernel_gid32_t',
        'size_t':     '__kernel_size_t',
        'ssize_t':    '__kernel_ssize_t',
        'loff_t':     '__kernel_loff_t',
        'pid_t':      '__kernel_pid_t',
        'sighandler_t': '__sighandler_t', # Corrected based on log
        'idtype_t': '__s32', # Not found in vmlinux.h, use int
        'enum __ptrace_request': '__s32'
        # 필요 시 추가…
    }

    lines = []
    for idx, (typ, var) in enumerate(zip(types, arg_names), start=1):
        parm = f"PT_REGS_PARM{idx}(ctx)"
        core = typ.replace('const', '').replace('*', '').split('[')[0].strip()
        is_array = '[' in typ
        is_ptr   = '*' in typ

        # 1) 배열, struct timeval/timespec, 또는 (char* 제외) 포인터
        if core in ('struct timeval','struct timespec') or is_array or (is_ptr and core != 'char'):
            lines.append(f"    e->data.{name}.{var}_ptr = (u64){parm};")
            continue

        # 2) 문자열(char*) 포인터 → 사용자 공간에서 문자열 복사
        if is_ptr and core == 'char':
            lines.append(
                f"    bpf_probe_read_user_str(&e->data.{name}.{var}, "
                f"sizeof(e->data.{name}.{var}), (void*){parm});")
            continue

        # 3) 일반 typedef → 매핑된 커널 타입으로 캐스트
        if core in typedef_map:
            ktype = typedef_map[core]
            lines.append(f"    e->data.{name}.{var} = ({ktype}){parm};")
            continue

        # 4) 나머지 기본 타입 → 그대로 캐스트
        lines.append(f"    e->data.{name}.{var} = ({typ}){parm};")

    return "\n".join(lines)

# --- .bpf.c 파일 생성 ---
def generate_bpf_sources(syscalls, df):
    """ CSV와 템플릿을 기반으로 다수의 .bpf.c 파일을 생성 """
    os.makedirs(BPF_DIR, exist_ok=True)
    for alias, base in syscalls:
        if alias in SPECIAL_MAP:
            hook_name = SPECIAL_MAP[alias]
        else:
            hook_name = alias
        row = df[df['syscall name'] == base].iloc[0]
        types, arg_names = get_syscall_info(row, alias)
        
        code = BPF_TEMPLATE.format(
            name=hook_name,
            NAME=base.upper(), # Use base name for event type for consistency
            bindings=make_bindings(base, types, arg_names)
        )
        path = os.path.join(BPF_DIR, f"{alias}_monitor.bpf.c")
        with open(path, 'w') as f:
            f.write(code)
        print(f"Generated {path}")

# --- Makefile 생성 ---
def generate_makefile(targets):
    mk = MAKEFILE.format(targets=' '.join(targets))
    with open(os.path.join(OUT_DIR, 'Makefile'), 'w') as f:
        f.write(mk)
    print("Generated Makefile")

    # --- 로더 C 코드 생성 ---

def generate_loader(targets, df):
    """ 로더 C 코드(monitor_loader.c)를 생성 """
    includes, skeletons, attaches, destroys, event_cases,enum_strings = [], [], [], [], [],[]
    
    # Generate serialization cases for each syscall
    unique_bases = df['syscall name'].unique()
    for base in unique_bases:
        upper_base = base.upper()
        enum_strings.append(f"    [EVT_{upper_base}] = \"{base}\",")
        case_str = f"        case EVT_{base.upper()}:\n"
        
        row = df[df['syscall name'] == base].iloc[0]
        types, arg_names = get_syscall_info(row, base)

        for typ, var in zip(types, arg_names):
        # 1) 포인터(배열·struct·기타 포인터)인 경우
            if '[' in typ or ('*' in typ and 'char' not in typ):
        # 실제 멤버 이름은 var + "_ptr"
                case_str += (
                   f'            fprintf(f, ",\\"{var}\\":%llu", '
                    f'(unsigned long long)e->data.{base}.{var}_ptr);\n'
                )
                continue

    # 2) 문자열(char*)인 경우
            elif '*' in typ and 'char' in typ:
                case_str += (
                    f'            fprintf(f, ",\\"{var}\\":\\"%s\\"", '
                    f'e->data.{base}.{var});\n'
                )
                continue

    # 3) long 계열
            elif typ in ['long', 'ssize_t', 'off_t', 'loff_t', 'time_t']:
                case_str += (
                    f'            fprintf(f, ",\\"{var}\\":%lld", '
                    f'(long long)e->data.{base}.{var});\n'
                )

    # 4) unsigned long 계열
            elif typ in ['unsigned long', 'size_t', 'dev_t', 'ino_t']:
               case_str += (
                   f'            fprintf(f, ",\\"{var}\\":%llu", '
                   f'(unsigned long long)e->data.{base}.{var});\n'
               )

    # 5) 나머지 정수형
            else:
               case_str += (
                   f'            fprintf(f, ",\\"{var}\\":%d", '
                   f'e->data.{base}.{var});\n'
               )

    # 각 case 의 마지막에는 반드시 break
    case_str += "            break;\n"
    event_cases.append(case_str)

    for alias in targets:
        includes.append(f'#include "bpf/{alias}_monitor.skel.h"')
        skeletons.append(f"    struct {alias}_monitor_bpf *{alias}_skel = NULL;")
        attaches.append(textwrap.dedent(f"""
    {alias}_skel = {alias}_monitor_bpf__open_and_load();
    if (!{alias}_skel) {{
        fprintf(stderr, "Failed to open and load {alias} skeleton\\n");
        goto cleanup;
    }}
    if ({alias}_monitor_bpf__attach({alias}_skel) != 0) {{
        fprintf(stderr, "Failed to attach {alias} skeleton\\n");
        goto cleanup;
    }}"""))
        destroys.append(f"    if ({alias}_skel) {alias}_monitor_bpf__destroy({alias}_skel);")

    loader = LOADER_TEMPLATE.format(
        includes='\n'.join(includes),
        skeletons='\n'.join(skeletons),
        attaches='\n'.join(attaches),
        destroys='\n'.join(destroys),
        first=targets[0],
        event_cases='\n'.join(event_cases),
        enum_strings='\n'.join(enum_strings)
    )
    with open(os.path.join(OUT_DIR, 'monitor_loader.c'), 'w') as f:
        f.write(loader)
    print("Generated monitor_loader.c")

# --- common_event.h 생성 ---
def generate_common_event_bpf(df):
    enum_lines, enum_strings, struct_lines, union_lines = [], [], [], []
    
    unique_bases = df['syscall name'].unique()

    for base in unique_bases:
        upper_base = base.upper()
        enum_lines.append(f"    EVT_{upper_base},")
        enum_strings.append(f"    [EVT_{upper_base}] = \"{base}\",")

        row = df[df['syscall name'] == base].iloc[0]
        types, arg_names = get_syscall_info(row, base)
        
        fields = []
        for typ, var in zip(types, arg_names):
            # --- 배열 인자 먼저 처리 ---
            core   = typ.replace('const','').replace('*','').split('[')[0].strip()
            is_ptr = '*' in typ
            # --- 배열, timeval/timespec, 기타 포인터 먼저 처리 ---
            core = typ.replace('const','').replace('*','').split('[')[0].strip()
            is_ptr = '*' in typ
            if '[' in typ or core in ('struct timeval','struct timespec') or (is_ptr and core != 'char'):
                fields.append(f"    __u64 {var}_ptr;")
                continue          

            # 1) 문자열 포인터 -> 고정배열
            if is_ptr and core == 'char':
                fields.append(f"    char {var}[MAX_STR_LEN];")
                continue
            
            # 2) 기타 포인터 -> 주소만 저장
           # if is_ptr:
           #     fields.append(f"    __u64 {var}_ptr;")
           #     continue

            # 3) 사용자 공간 typedef -> 커널 BTF typedef로 매핑
            mapping = {
                'socklen_t': '__u32', # __kernel_socklen_t not found in vmlinux.h, use __u32
                'id_t':       '__kernel_pid_t',
                #'struct timeval':  'struct __kernel_old_timeval',
                #'struct timespec': 'struct __kernel_timespec',
                'enum __ptrace_request': '__s32',
                'nfds_t':     '__u32',
                'caddr_t':    '__u64',
                'off64_t':    '__s64',
                'time_t':     '__kernel_time64_t',
                'clockid_t':  '__kernel_clockid_t',
                'timer_t':    '__kernel_timer_t',
                'dev_t':      '__kernel_dev_t',
                'ino_t':      'u64', # __kernel_ino_t not found in vmlinux.h snippet, use u64
                'mode_t':     'umode_t',
                'uid_t':      '__kernel_uid32_t',
                'gid_t':      '__kernel_gid32_t',
                'size_t':     '__kernel_size_t',
                'ssize_t':    '__kernel_ssize_t',
                'loff_t':     '__kernel_loff_t',
                'pid_t':      '__kernel_pid_t',
                'sighandler_t': '__sighandler_t', # Corrected based on log
                'idtype_t': '__s32', # Not found in vmlinux.h, use int
                'enum __ptrace_request': '__s32', # Not found in vmlinux.h, use int
                # Add other mappings as needed based on compilation errors
            }
            if core in mapping:
                fields.append(f"    {mapping[core]} {var};")
                continue

            # 4) 커널 BTF에 정의된 구조체 이름은 그대로 사용
            # vmlinux.h에서 직접 찾아서 추가해야 합니다.
            btf_structs = {
                'struct __user_cap_header',
                'struct __user_cap_data',
                'struct __kernel_timespec', # Corrected based on log
                'struct __kernel_old_timeval', # Corrected based on log
                'struct timex', # Assuming this exists, if not, it will error again.
                'struct itimerval', # Assuming this exists, if not, it will error again.
                # Add other BTF structs as needed
            }
            if core in btf_structs:
                fields.append(f"    {core} {var};")
                continue

            # 5) 그 외 기본 산술 타입 -> __s32/__u32 등으로 매핑
            basic_map = {
                'int':'__s32','unsigned int':'__u32',
                'long':'__s64','unsigned long':'__u64',
                'short':'__s16','unsigned short':'__u16',
                'char':'__s8','unsigned char':'__u8',
                'bool':'_Bool',
                # pid_t, uid_t 등은 위 typedef 매핑에서 처리
            }
            ktyp = basic_map.get(core, core)
            fields.append(f"    {ktyp} {var};")
        
        struct_code = STRUCT_TMPL.format(name=base, fields="\n".join(fields))
        struct_lines.append(struct_code)
        union_lines.append(f"        struct {base}_event_t {base};")

    content = BPF_HEADER.format(
        enum_entries="\n".join(enum_lines),
        enum_strings="\n".join(enum_strings),
        struct_definitions="\n".join(struct_lines),
        union_entries="\n".join(union_lines)
    )
    os.makedirs(os.path.dirname(EVENT_HDR), exist_ok=True)
    with open(EVENT_HDR, 'w') as f:
        f.write(content)
    print(f"Generated {EVENT_HDR}")

def generate_common_event_user(df):
    enum_lines, enum_strings, struct_lines, union_lines = [], [], [], []
    
    unique_bases = df['syscall name'].unique()

    for base in unique_bases:
        upper_base = base.upper()
        enum_lines.append(f"    EVT_{upper_base},")
        enum_strings.append(f"    [EVT_{upper_base}] = \"{base}\",")

        row = df[df['syscall name'] == base].iloc[0]
        types, arg_names = get_syscall_info(row, base)
        
        fields = []
        for typ, var in zip(types, arg_names):
            # --- 배열 인자 먼저 처리 ---
            core   = typ.replace('const','').replace('*','').split('[')[0].strip()
            is_ptr = '*' in typ
            # --- 배열, timeval/timespec, 기타 포인터 먼저 처리 ---
            core = typ.replace('const','').replace('*','').split('[')[0].strip()
            is_ptr = '*' in typ
            if '[' in typ or core in ('struct timeval','struct timespec') or (is_ptr and core != 'char'):
                fields.append(f"    __u64 {var}_ptr;")
                continue          

            # 1) 문자열 포인터 -> 고정배열
            if is_ptr and core == 'char':
                fields.append(f"    char {var}[MAX_STR_LEN];")
                continue
            
            # 2) 기타 포인터 -> 주소만 저장
           # if is_ptr:
           #     fields.append(f"    __u64 {var}_ptr;")
           #     continue

            # 3) 사용자 공간 typedef -> 커널 BTF typedef로 매핑
            mapping = {
                'socklen_t': '__u32', # __kernel_socklen_t not found in vmlinux.h, use __u32
                'id_t':       '__kernel_pid_t',
                #'struct timeval':  'struct __kernel_old_timeval',
                #'struct timespec': 'struct __kernel_timespec',
                'enum __ptrace_request': '__s32',
                'nfds_t':     '__u32',
                'caddr_t':    '__u64',
                'off64_t':    '__s64',
                'time_t':     '__kernel_time64_t',
                'clockid_t':  '__kernel_clockid_t',
                'timer_t':    '__kernel_timer_t',
                'dev_t':      '__kernel_dev_t',
                'ino_t':      'u64', # __kernel_ino_t not found in vmlinux.h snippet, use u64
                'mode_t':     'umode_t',
                'uid_t':      '__kernel_uid32_t',
                'gid_t':      '__kernel_gid32_t',
                'size_t':     '__kernel_size_t',
                'ssize_t':    '__kernel_ssize_t',
                'loff_t':     '__kernel_loff_t',
                'pid_t':      '__kernel_pid_t',
                'sighandler_t': '__sighandler_t', # Corrected based on log
                'idtype_t': '__s32', # Not found in vmlinux.h, use int
                'enum __ptrace_request': '__s32', # Not found in vmlinux.h, use int
                # Add other mappings as needed based on compilation errors
            }
            if core in mapping:
                fields.append(f"    {mapping[core]} {var};")
                continue

            # 4) 커널 BTF에 정의된 구조체 이름은 그대로 사용
            # vmlinux.h에서 직접 찾아서 추가해야 합니다.
            btf_structs = {
                'struct __user_cap_header',
                'struct __user_cap_data',
                'struct __kernel_timespec', # Corrected based on log
                'struct __kernel_old_timeval', # Corrected based on log
                'struct timex', # Assuming this exists, if not, it will error again.
                'struct itimerval', # Assuming this exists, if not, it will error again.
                # Add other BTF structs as needed
            }
            if core in btf_structs:
                fields.append(f"    {core} {var};")
                continue

            # 5) 그 외 기본 산술 타입 -> __s32/__u32 등으로 매핑
            basic_map = {
                'int':'__s32','unsigned int':'__u32',
                'long':'__s64','unsigned long':'__u64',
                'short':'__s16','unsigned short':'__u16',
                'char':'__s8','unsigned char':'__u8',
                'bool':'_Bool',
                # pid_t, uid_t 등은 위 typedef 매핑에서 처리
            }
            ktyp = basic_map.get(core, core)
            fields.append(f"    {ktyp} {var};")
        
        struct_code = STRUCT_TMPL.format(name=base, fields="\n".join(fields))
        struct_lines.append(struct_code)
        union_lines.append(f"        struct {base}_event_t {base};")

    content = USER_HEADER.format(
        enum_entries="\n".join(enum_lines),
        enum_strings="\n".join(enum_strings),
        struct_definitions="\n".join(struct_lines),
        union_entries="\n".join(union_lines)
    )
    os.makedirs(os.path.dirname(EVENT_HDR_USER), exist_ok=True)
    with open(EVENT_HDR_USER, 'w') as f:
        f.write(content)
    print(f"Generated {EVENT_HDR_USER}")

