#!/usr/bin/env python3
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

# alias_map: 필요 시 파생 syscall 이름 추가
alias_map = {
    'clone': ['clone', 'clone2', 'clone3'],
    'open':  ['open', 'openat', 'openat2'],
    # 여기에 추가 파생 이름을 넣으면 자동 확장됨
}

# --- eBPF 코드 템플릿 ---
# BUGFIX: if(e) -> if(!e)
# BUGFIX: 컨테이너 런타임 필터링 로직을 명확하게 수정하고, 정의되지 않은 'flags' 변수 사용 제거
BPF_TEMPLATE = textwrap.dedent("""
#define __TARGET_ARCH_x86
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/string.h>

#include "common_maps.h"
#include "common_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/__x64_sys_{name}")
int trace_{name}(struct pt_regs *ctx) {{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 컨테이너 런타임(runc, conmon 등)이 아니면 추적하지 않음
    if (strncmp(comm, "runc", 4) != 0 &&
        strncmp(comm, "conmon", 6) != 0 &&
        strncmp(comm, "containerd-shim", 15) != 0 &&
        strncmp(comm, "docker", 6) != 0) {{
        return 0;
    }}

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {{
        return 0;
    }}
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
    """ `man 2 syscall` 호출 후 SYNOPSIS에서 인자 이름만 추출 """
    try:
        # EFFICIENCY: stderr=subprocess.PIPE is more robust than DEVNULL
        text = subprocess.check_output(['man', '2', syscall], text=True, stderr=subprocess.PIPE)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    # IMPROVEMENT: More robust regex to handle different man page formats
    m = re.search(r'SYNOPSIS.*?' + re.escape(syscall) + r'\s*\(([^)]*)\)', text, re.DOTALL)
    if not m:
        return []
    
    parts = [p.strip() for p in m.group(1).split(',')]
    names = []
    for p in parts:
        # Handle "void" and other non-argument cases
        if p.lower().strip() == 'void':
            continue
        # The argument name is usually the last word
        toks = p.split()
        if toks:
            name = toks[-1]
            # Remove potential array brackets or pointer asterisks from the name
            name = name.replace('[', '').replace(']', '').lstrip('*')
            names.append(name)
    return names

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
        for alias in alias_map.get(base, [base]):
            syscalls.append((alias, base))
    return syscalls, df

# --- REFACTOR: 중복 로직을 헬퍼 함수로 추출 ---
def get_syscall_info(row, syscall_name):
    """ 주어진 syscall에 대한 타입과 인자 이름 목록을 반환 """
    types = []
    # BUGFIX: x86_64 레지스터 순서(rdi, rsi, rdx, r10, r8, r9)를 정확히 매핑
    regs = ['di', 'si', 'dx', '10', '8', '9']
    for i in range(6):
        col = f'arg{i} (%r{regs[i]})'
        # BUGFIX: `row[col] = '-'` 를 `row[col] != '-'` 로 수정
        if col in row and isinstance(row[col], str) and row[col] != '-':
            # 타입 정보만 추출 (e.g., 'const char *' -> 'const char*')
            types.append(" ".join(row[col].split()))

    # man 페이지에서 인자 이름 가져오기, 실패 시 기본값 사용
    arg_names = get_proto(syscall_name)
    # 인자 이름의 개수가 타입 개수와 다를 경우, 기본값으로 대체
    if len(arg_names) != len(types):
        # IMPROVEMENT: More informative log message
        print(f"[Warning] Failed to get arg names for \"{syscall_name}\" from man page. Using default names (arg0, arg1, ...).")
        arg_names = [f"arg{i}" for i in range(len(types))]

    return types, arg_names

# --- 인자 바인딩 생성 ---
def make_bindings(name, types, arg_names):
    """ eBPF 코드에 삽입될 인자 바인딩 C 코드를 생성 """
    lines = []
    for idx, (typ, var) in enumerate(zip(types, arg_names), start=1):
        parm = f"PT_REGS_PARM{idx}(ctx)"
        # 포인터 타입 처리
        if '*' in typ:
            # MODIFIED: struct 포인터와 문자열 포인터를 구분하여 처리
            if 'struct' in typ:
                # struct 포인터는 bpf_probe_read_user로 전체 구조체 복사
                lines.append(f"    bpf_probe_read_user(&e->data.{name}.{var}, sizeof(e->data.{name}.{var}), (void*){parm});")
            elif 'char' in typ:
                # 문자열 포인터는 bpf_probe_read_user_str로 복사
                lines.append(f"    bpf_probe_read_user_str(&e->data.{name}.{var}, sizeof(e->data.{name}.{var}), (void*){parm});")
            else: # 기타 기본 타입 포인터 (int*, long* 등)
                lines.append(f"    bpf_probe_read_user(&e->data.{name}.{var}, sizeof(e->data.{name}.{var}), (void*){parm});")
        # 일반 타입 처리
        else:
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
CC      ?= clang
CFLAGS  := -O2 -g -Wall -Werror -target bpf -I.

# 모든 bpf 오브젝트와 스켈레톤 헤더를 빌드
TARGETS := {targets}
OBJECTS := $(addsuffix _monitor.bpf.o, $(TARGETS))
SKELETONS := $(addsuffix _monitor.skel.h, $(TARGETS))

all: $(OBJECTS) $(SKELETONS)

# 패턴 규칙: .bpf.c -> .bpf.o
%.bpf.o: bpf/%_monitor.bpf.c include/common_event.h
	$(CC) $(CFLAGS) -c $< -o $@

# 패턴 규칙: .bpf.o -> .skel.h
%_monitor.skel.h: %_monitor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -f bpf/*.bpf.o *.skel.h monitor_loader
""")

def generate_makefile(targets):
    mk = MAKEFILE.format(targets=' '.join(targets))
    with open(os.path.join(OUT_DIR, 'Makefile'), 'w') as f:
        f.write(mk)
    print("Generated Makefile")

# --- monitor_loader.c 생성 ---
# IMPROVEMENT: Kafka 관련 로직 개선 및 에러 처리 추가
LOADER_TEMPLATE = textwrap.dedent("""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <librdkafka/rdkafka.h>
#include "include/common_event.h"
{includes}

static volatile bool running = true;
static rd_kafka_t *rk;
static rd_kafka_topic_t *rkt;

void sig_handler(int sig) {{
    running = false;
}}

// IMPROVEMENT: Kafka delivery report callback
static void dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {{
    if (rkmessage->err) {
        fprintf(stderr, "%% Message delivery failed: %%s\n", rd_kafka_err2str(rkmessage->err));
    }
}}

static void kafka_init() {{
    char errstr[512];
    rd_kafka_conf_t *conf = rd_kafka_conf_new();

    if (rd_kafka_conf_set(conf, "bootstrap.servers", "localhost:9092", errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {{
        fprintf(stderr, "%% %%s\n", errstr);
        exit(1);
    }}
    // Set delivery report callback
    rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

    rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!rk) {{
        fprintf(stderr, "%% Failed to create new producer: %%s\n", errstr);
        exit(1);
    }}
    rkt = rd_kafka_topic_new(rk, "syscall_events", NULL);
}}

static void kafka_send(const char* buffer, size_t len) {{
    if (!buffer || len == 0) return;
    // RD_KAFKA_MSG_F_COPY makes a copy of the payload.
    rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, (void*)buffer, len, NULL, 0, NULL);
    // Poll for delivery reports (and other events)
    rd_kafka_poll(rk, 0);
}}

// IMPROVEMENT: Robust JSON serialization for each event type
static void serialize_and_send(const struct event_t *e) {{
    char *buf = NULL;
    size_t size = 0;
    FILE *f = open_memstream(&buf, &size);
    if (!f) return;

    fprintf(f, "{{\"type\":\"%%s\",\"pid\":%%u,\"ts\":%%llu", event_type_str[e->type], e->pid, e->ts_ns);

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
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }}

    printf("Monitoring syscalls... Press Ctrl+C to exit.\n\n");
    while (running) {{
        if (ring_buffer__poll(rb, 100) < 0) {{
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }}
        // Poll Kafka regularly to serve delivery reports and other callbacks.
        rd_kafka_poll(rk, 0);
    }}

cleanup:
    ring_buffer__free(rb);
    {destroys}
    fprintf(stderr, "\nFlushing final Kafka messages...\n");
    rd_kafka_flush(rk, 10 * 1000); // Wait for max 10 seconds
    rd_kafka_topic_destroy(rkt);
    rd_kafka_destroy(rk);
    printf("Cleaned up resources.\n");
    return 0;
}}
""")

def generate_loader(targets, df):
    """ 로더 C 코드(monitor_loader.c)를 생성 """
    includes, skeletons, attaches, destroys, event_cases = [], [], [], [], []
    
    # Generate serialization cases for each syscall
    unique_bases = df['syscall name'].unique()
    for base in unique_bases:
        case_str = f"        case EVT_{base.upper()}:\n"
        
        row = df[df['syscall name'] == base].iloc[0]
        types, arg_names = get_syscall_info(row, base)

        for typ, var in zip(types, arg_names):
            # IMPROVEMENT: Correctly format different types for JSON
            if '*' in typ:
                if 'struct' in typ:
                    # For structs, we can't easily serialize to JSON without more info.
                    # We'll just indicate its presence.
                    case_str += f'            fprintf(f, ",\"{var}\":\"<struct>\"");\n'
                else: # char*
                    case_str += f'            fprintf(f, ",\"{var}\":\"%%s\"", e->data.{base}.{var});\n'
            elif typ in ['long', 'ssize_t', 'off_t', 'loff_t', 'time_t']:
                case_str += f'            fprintf(f, ",\"{var}\":%%lld", (long long)e->data.{base}.{var});\n'
            elif typ in ['unsigned long', 'size_t', 'dev_t', 'ino_t']:
                case_str += f'            fprintf(f, ",\"{var}\":%%llu", (unsigned long long)e->data.{base}.{var});\n'
            else: # int, pid_t, uid_t, etc.
                case_str += f'            fprintf(f, ",\"{var}\":%%d", e->data.{base}.{var});\n'
        case_str += "            break;"
        event_cases.append(case_str)

    for alias in targets:
        includes.append(f'#include "bpf/{alias}_monitor.skel.h"')
        skeletons.append(f"    struct {alias}_monitor_bpf *{alias}_skel = NULL;")
        attaches.append(textwrap.dedent(f"""
    {alias}_skel = {alias}_monitor_bpf__open_and_load();
    if (!{alias}_skel) {{
        fprintf(stderr, "Failed to open and load {alias} skeleton\n");
        goto cleanup;
    }}
    if ({alias}_monitor_bpf__attach({alias}_skel) != 0) {{
        fprintf(stderr, "Failed to attach {alias} skeleton\n");
        goto cleanup;
    }}"""))
        destroys.append(f"    if ({alias}_skel) {alias}_monitor_bpf__destroy({alias}_skel);")

    loader = LOADER_TEMPLATE.format(
        includes='\n'.join(includes),
        skeletons='\n'.join(skeletons),
        attaches='\n'.join(attaches),
        destroys='\n'.join(destroys),
        first=targets[0],
        event_cases='\n'.join(event_cases)
    )
    with open(os.path.join(OUT_DIR, 'monitor_loader.c'), 'w') as f:
        f.write(loader)
    print("Generated monitor_loader.c")


# --- common_event.h 생성 ---
def generate_common_event(df):
    """ eBPF와 로더가 공용으로 사용하는 헤더 파일(common_event.h)을 생성 """
    HEADER = textwrap.dedent("""
    #pragma once
    #include <linux/types.h>

    // IMPROVEMENT: Increased max string length for paths, etc.
    // This is a hard limit; longer strings will be truncated.
    #define MAX_STR_LEN 1024

    enum event_type {{
    {enum_entries}
        EVT_MAX,
    }};

    // For converting enum to string in user-space
    static const char *event_type_str[] = {{
    {enum_strings}
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
            if '*' in typ:
                if 'struct' in typ:
                    struct_type = typ.replace('*', '').strip()
                    fields.append(f"    {struct_type} {var};")
                else:
                    fields.append(f"    char {var}[MAX_STR_LEN];")
            else:
                # IMPROVEMENT: Expanded mapping for kernel types
                ktyp = {{
                    'int': '__s32', 'unsigned int': '__u32',
                    'long': '__s64', 'unsigned long': '__u64',
                    'size_t': '__u64', 'ssize_t': '__s64',
                    'pid_t': '__s32', 'uid_t': '__u32', 'gid_t': '__u32',
                    'mode_t': '__u32', 'umode_t': '__u16',
                    'off_t': '__s64', 'loff_t': '__s64',
                    'dev_t': '__u64', 'ino_t': '__u64',
                    'time_t': '__s64', 'clockid_t': '__s32',
                    'key_t': '__s32', 'qid_t': '__u32',
                }}.get(typ, typ) # Default to itself if not in map
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


# --- main ---
def main():
    """ 스크립트 메인 실행 함수 """
    syscalls, df = parse_csv()
    # alias 목록
    targets = sorted([alias for alias, _ in syscalls])
    
    # 1. 공통 헤더 파일 생성
    generate_common_event(df);
    
    # 2. BPF 소스 파일들 생성
    generate_bpf_sources(syscalls, df);
    
    # 3. Makefile 및 로더 생성
    generate_makefile(targets);
    generate_loader(targets, df);
    
    print("\nGeneration complete. Run 'make' to build.")

if __name__ == '__main__':
    main()