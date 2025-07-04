#!/usr/bin/env python3
#해당 코드는 ubuntutu 22.04 LTS에서 실행됨

#디렉토리 정리 필요
#project/
#├─ bpf/
#│  ├─ foo.bpf.c
#│  └─ common_event_bpf.h     ← vmlinux.h 포함
#├─ user/
#│  ├─ monitor_loader.c
#│  └─ common_event_user.h    ← vmlinux.h 없는 순수 구조체 정의
#└─ Makefile
import os
import subprocess
import re
import pandas as pd
import textwrap

# --- 설정 ---
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

# alias_map: 필요 시 파생 syscall 이름 추가
#alias_map = {
 #   'clone': ['clone', 'clone2', 'clone3'],
 # 여기에 추가 파생 이름을 넣으면 자동 확장됨
#}

# --- eBPF 코드 템플릿 ---
# BUGFIX: if(e) -> if(!e)
# BUGFIX: 컨테이너 런타임 필터링 로직을 명확하게 수정하고, 정의되지 않은 'flags' 변수 사용 제거
BPF_TEMPLATE = textwrap.dedent("""
#define __TARGET_ARCH_x86
#ifndef PT_REGS_PARM6
#define PT_REGS_PARM6(ctx) ((ctx)->r9)
#endif
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common_maps.h"
#include "common_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
                    

SEC("kprobe/__x64_sys_{name}")
int trace_{name}(struct pt_regs *ctx) {{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 컨테이너 런타임(runc, conmon, containerd-shim, docker)이 아니면 추적 중단
    bool is_container = false;

    // "runc"
    if (comm[0]=='r' && comm[1]=='u' && comm[2]=='n' && comm[3]=='c')
        is_container = true;

    // "conmon"
    if (comm[0]=='c' && comm[1]=='o' && comm[2]=='n' && comm[3]=='m'
        && comm[4]=='o' && comm[5]=='n')
        is_container = true;

    // "containerd-shim"
    if (comm[0]=='c' && comm[1]=='o' && comm[2]=='n' && comm[3]=='t'
        && comm[4]=='a' && comm[5]=='i' && comm[6]=='n' && comm[7]=='e'
        && comm[8]=='r' && comm[9]=='d' && comm[10]=='-' && comm[11]=='s'
        && comm[12]=='h' && comm[13]=='i' && comm[14]=='m')
        is_container = true;

    // "docker"
    if (comm[0]=='d' && comm[1]=='o' && comm[2]=='c'
        && comm[3]=='k' && comm[4]=='e' && comm[5]=='r')
        is_container = true;

    if (!is_container)
        return 0;

    /* 이하 eBPF 이벤트 생성 코드 계속… */
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->type  = EVT_{NAME};
    e->ts_ns = bpf_ktime_get_ns();
    {bindings}
    bpf_ringbuf_submit(e, 0);
    return 0;
}}
""")

# --- man 페이지에서 인자 이름 추출 ---
def get_proto(syscall):
    """ `man 2 syscall` 호출 후 SYNOPSIS에서 인자 타입과 이름을 추출 """
    try:
        text = subprocess.check_output(['man', '2', syscall], text=True, stderr=subprocess.PIPE)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [], [] # Return empty types and names
    
    m = re.search(r'SYNOPSIS.*?' + re.escape(syscall) + r'\s*\(([^)]*)\)', text, re.DOTALL)
    if not m:
        return [], [] # Return empty types and names
    
    # Clean the argument string: remove comments, split by comma
    arg_string = m.group(1)
    arg_string = re.sub(r'/\*.*?\*/', '', arg_string) # remove C-style comments
    parts = [p.strip() for p in arg_string.split(',')]
    
    types = []
    names = []
    for p in parts:
        p_clean = p.strip()
        
        # Skip void, variadic args, function pointers, and other malformed parts
        if p_clean.lower() == 'void' or '...' in p_clean or '(' in p_clean or not p_clean:
            continue
        
        # Handle cases like "int flags / unsigned int mode" - take the first one
        if '/' in p_clean:
            p_clean = p_clean.split('/')[0].strip()

        toks = p_clean.split()
        if not toks:
            continue
            
        # The last token is the name, the rest is the type
        name = toks[-1]
        typ = " ".join(toks[:-1]).strip()

        # Correctly handle pointer types where '*' is attached to the name
        while name.startswith('*'):
            typ = typ + ' *'
            name = name[1:]
        # If the original name token had array brackets, append them to the type.
        if '[' in toks[-1]:
            typ += toks[-1][toks[-1].find('['):] # Append [2] or whatever

        # If type is empty, it's a malformed entry, skip it.
        if not typ:
            continue

        # Sanitize the name to be a valid C identifier
        # Remove array brackets
        name = name.replace('[', '').replace(']', '')
        # A more restrictive sanitizer to avoid creating invalid identifiers
        name = re.sub(r'[^a-zA-Z0-9_]', '', name)
        
        # If name is empty after sanitizing (e.g. from 'int *'), assign a generic one
        if not name or name in ['void']:
             name = f"arg{len(names)}"

        # We can't really handle `void`, as it's an incomplete type for a field.
        # But `void *` is fine, and the logic above should handle it.
        if typ.strip() == 'void':
            continue

        names.append(name)
        types.append(typ)
        
    return types, names

# --- CSV 파싱 및 alias 확장 ---
def parse_csv():
    """ CSV를 파싱하고 alias를 확장하여 syscall 목록을 반환 """
    try:
        df = pd.read_csv(CSV_PATH)
    except FileNotFoundError:
        print(f"Error: '{CSV_PATH}' not found.")
        exit(1)
    syscalls = []  # list of (alias, base)
    for base in df['syscall name'].unique():
        syscalls.append((base, base)) # alias_map 없이 기본 이름만 사용
    return syscalls, df

# --- REFACTOR: 중복 로직을 헬퍼 함수로 추출 ---
def get_syscall_info(row, syscall_name):
    """ 주어진 syscall에 대한 타입과 인자 이름 목록을 man 페이지에서 직접 추출 """
    types, arg_names = get_proto(syscall_name)
    return types, arg_names

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
        row = df[df['syscall name'] == base].iloc[0]
        types, arg_names = get_syscall_info(row, alias)
        
        code = BPF_TEMPLATE.format(
            name=alias,
            NAME=base.upper(), # Use base name for event type for consistency
            bindings=make_bindings(base, types, arg_names)
        )
        path = os.path.join(BPF_DIR, f"{alias}_monitor.bpf.c")
        with open(path, 'w') as f:
            f.write(code)
        print(f"Generated {path}")

# --- Makefile 생성 ---
MAKEFILE = textwrap.dedent("""
# Auto-generated by generate_bpf.py
BPFTOOL ?= bpftool
CC      = clang
#CFLAGS  := -O2 -g -Wall -Werror -target bpf -I. -Iinclude
LLVM_SYSROOT := $(shell $(CC) --print-resource-dir)/../..
KERNEL_SRCDIR ?= /usr/src/linux-headers-$(shell uname -r)

CFLAGS := -O2 -g -Wall -Werror -target bpf -nostdinc -isystem /usr/include -isystem $(LLVM_SYSROOT)/include -isystem $(LLVM_SYSROOT)/../lib/clang/*/include  -Iinclude -I. -I$(KERNEL_SRCDIR)/tools/lib/bpf/include
                           
# 모든 bpf 오브젝트와 스켈레톤 헤더를 빌드
TARGETS := {targets}
OBJECTS := $(addprefix bpf/,$(addsuffix _monitor.bpf.o, $(TARGETS)))
SKELETONS := $(addprefix bpf/,$(addsuffix _monitor.skel.h, $(TARGETS)))

all: $(OBJECTS) $(SKELETONS) monitor_loader
                          
# 패턴 규칙: _name_monitor.bpf.c -> _name_monitor.bpf.o
bpf/%_monitor.bpf.o: bpf/%_monitor.bpf.c include/common_event.h
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

# 패턴 규칙: .bpf.o -> .skel.h
bpf/%_monitor.skel.h: bpf/%_monitor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

monitor_loader: monitor_loader.c
	gcc -o $@ $< \
	-Iinclude \
	-I. \
	-I$(LLVM_SYSROOT)/include \
	-I$(KERNEL_SRCDIR)/tools/lib/bpf/include \
	-lbpf -lrdkafka -lpthread

clean:
	rm -f *.bpf.o *.skel.h monitor_loader
""")

def generate_makefile(targets):
    mk = MAKEFILE.format(targets=' '.join(targets))
    with open(os.path.join(OUT_DIR, 'Makefile'), 'w') as f:
        f.write(mk)
    print("Generated Makefile")

# --- monitor_loader.c 생성 ---
# IMPROVEMENT: Kafka 관련 로직 개선 및 에러 처리 추가
#bpf 모니터링 스켈레톤 헤더들 생성위치 조정필요
LOADER_TEMPLATE = textwrap.dedent("""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <librdkafka/rdkafka.h>
#include "include/common_event_user.h"
{includes} 
// bpf 모니터링 스켈레톤 헤더들 생성위치 조정필요

static volatile bool running = true;
static rd_kafka_t *rk;
static rd_kafka_topic_t *rkt;
static const char *event_type_str[] = {{
{enum_strings}
    }};
                                           

void sig_handler(int sig) {{
    running = false;
}}

// IMPROVEMENT: Kafka delivery report callback
static void dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {{
    if (rkmessage->err) {{
        fprintf(stderr, " Message delivery failed: %s\\n", rd_kafka_err2str(rkmessage->err));
    }}
}}

static void kafka_init() {{
    char errstr[512];
    rd_kafka_conf_t *conf = rd_kafka_conf_new();

    if (rd_kafka_conf_set(conf, "bootstrap.servers", "localhost:9092", errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {{
        fprintf(stderr, "%s\\n", errstr);
        exit(1);
    }}
    // Set delivery report callback
    rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

    rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!rk) {{
        fprintf(stderr, "Failed to create new producer: %s\\n", errstr);
        exit(1);
    }}
    rkt = rd_kafka_topic_new(rk, "syscall_events", NULL);
}}

static void kafka_send(const char* buffer, size_t len) {{
    if (!buffer || len == 0) return;
    // RD_KAFKA_MSG_F_COPY makes a copy of the payload.
    rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, (void*)buffer, len, NULL, 0, NULL);
    // Poll for delivery reports (and other events).
    rd_kafka_poll(rk, 0);
}}

// IMPROVEMENT: Robust JSON serialization for each event type
static void serialize_and_send(const struct event_t *e) {{
    char *buf = NULL;
    size_t size = 0;
    FILE *f = open_memstream(&buf, &size);
    if (!f) return;

    fprintf(f, "{{\\"type\\":\\"%s\\",\\"pid\\":%u,\\"ts\\":%llu", event_type_str[e->type], e->pid, e->ts_ns);

    // Event-specific data
    switch (e->type) {{
{event_cases}
    default:
        break;
    }}

    fprintf(f, "}}");
    fclose(f);

    kafka_send(buf, size);
    free(buf);
}}

static int on_event(void *ctx, void *data, size_t size) {{
    serialize_and_send((const struct event_t *)data);
    return 0;
}}

int main() {{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    kafka_init();

    {skeletons}
    {attaches}

    int map_fd = bpf_map__fd({first}_skel->maps.events);
    struct ring_buffer *rb = ring_buffer__new(map_fd, on_event, NULL, NULL);
    if (!rb) {{
        fprintf(stderr, "Failed to create ring buffer\\n");
        goto cleanup;
    }}

    printf("Monitoring syscalls... Press Ctrl+C to exit.\\n\\n");
    while (running) {{
        if (ring_buffer__poll(rb, 100) < 0) {{
            fprintf(stderr, "Error polling ring buffer\\n");
            break;
        }}
        // Poll Kafka regularly to serve delivery reports and other callbacks.
        rd_kafka_poll(rk, 0);
    }}

cleanup:
    ring_buffer__free(rb);
    {destroys}
    fprintf(stderr, "\\nFlushing final Kafka messages...\\n");
    rd_kafka_flush(rk, 10 * 1000); // Wait for max 10 seconds
    rd_kafka_topic_destroy(rkt);
    rd_kafka_destroy(rk);
    printf("Cleaned up resources.\\n");
    return 0;
}}
""")

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
def generate_common_event(df):
    """ eBPF가 사용하는 헤더 파일(common_event.h)을 생성 """
    HEADER = textwrap.dedent("""
    #pragma once
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>                      
                    
                             
    // IMPROVEMENT: Increased max string length for paths, etc.
    // This is a hard limit; longer strings will be truncated.
    #define MAX_STR_LEN 1024

    enum event_type {{
    {enum_entries}
        EVT_MAX,
    }};

    
    {struct_definitions}

    struct event_t {{
        __u32 pid;
        enum event_type type;
        __u64 ts_ns;
        union {{
    {union_entries}
        }} data;
    }};
    """)
    
    STRUCT_TMPL = textwrap.dedent("""
    struct {name}_event_t {{
    {fields}
    }};
""")

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

    content = HEADER.format(
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
    """ 로더가 사용하는 헤더 파일(common_event_user.h)을 생성 """
    HEADER = textwrap.dedent("""
#pragma once

/* 1) 필수 헤더 */
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/keyctl.h>
#include <sys/capability.h>
#include <aio.h>
#include <mqueue.h>

/* 2) 축약형 정수 타입 */
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef  int64_t s64;
typedef  int32_t s32;
typedef  int16_t s16;
typedef   int8_t s8;

/* 3) uapi 헤더에 없는, 커널 전용 타입 매핑 */
/*    이미 정의된 표준 타입은 건드리지 않습니다. */
#ifndef umode_t
typedef mode_t             umode_t;           /* 파일 모드 */
#endif

#ifndef __kernel_dev_t
typedef dev_t              __kernel_dev_t;    /* 커널 dev_t */
#endif

#ifndef __kernel_loff_t
typedef long long          __kernel_loff_t;
#endif

#ifndef __kernel_time64_t
typedef long long          __kernel_time64_t;
#endif

#ifndef __kernel_clockid_t
typedef int                __kernel_clockid_t;
#endif

#ifndef __kernel_timer_t
typedef int                __kernel_timer_t;
#endif

#ifndef __kernel_uid32_t
typedef uid_t              __kernel_uid32_t;
#endif

#ifndef __kernel_gid32_t
typedef gid_t              __kernel_gid32_t;
#endif

#ifndef __kernel_size_t
typedef size_t             __kernel_size_t;
#endif

#ifndef __kernel_ssize_t
typedef ssize_t            __kernel_ssize_t;
#endif

#ifndef __kernel_pid_t
typedef pid_t              __kernel_pid_t;
#endif

#ifndef key_serial_t
typedef int                key_serial_t;
#endif

#ifndef aio_context_t
typedef unsigned long      aio_context_t;
#endif
   
                    
                             
    // IMPROVEMENT: Increased max string length for paths, etc.
    // This is a hard limit; longer strings will be truncated.
    #define MAX_STR_LEN 1024

    enum event_type {{
    {enum_entries}
        EVT_MAX,
    }};

    
    {struct_definitions}

    struct event_t {{
        __u32 pid;
        enum event_type type;
        __u64 ts_ns;
        union {{
    {union_entries}
        }} data;
    }};
    """)
    
    STRUCT_TMPL = textwrap.dedent("""
    struct {name}_event_t {{
    {fields}
    }};
""")

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

    content = HEADER.format(
        enum_entries="\n".join(enum_lines),
        enum_strings="\n".join(enum_strings),
        struct_definitions="\n".join(struct_lines),
        union_entries="\n".join(union_lines)
    )
    os.makedirs(os.path.dirname(EVENT_HDR_USER), exist_ok=True)
    with open(EVENT_HDR_USER, 'w') as f:
        f.write(content)
    print(f"Generated {EVENT_HDR_USER}")

# --- main ---
def main():
    """ 스크립트 메인 실행 함수 """
    syscalls, df = parse_csv()
    # alias 목록
    targets = sorted([alias for alias, _ in syscalls])
    
    # 1. bpf 헤더 파일 생성
    generate_common_event(df);

    # 2. 사용자 공간 헤더 파일 생성
    generate_common_event_user(df);
    
    # 3. BPF 소스 파일들 생성
    generate_bpf_sources(syscalls, df);
    
    # 4. Makefile 및 로더 생성
    generate_makefile(targets);
    generate_loader(targets, df);
    
    print("\nGeneration complete. Run 'make' to build.")

if __name__ == '__main__':
    main()