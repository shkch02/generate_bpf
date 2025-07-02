#!/usr/bin/env python3
import os
import subprocess
import re
import pandas as pd
import textwrap

# ——— 설정 ———
CSV_PATH = 'syscalls_x86_64.csv'
BPF_DIR  = 'bpf'
OUT_DIR  = '.'

# alias_map: 필요 시 파생 syscall 이름 추가
# =======================alias_map 생성 코드 필요함 아직 안만듦==============================
alias_map = {
    'clone': ['clone', 'clone2', 'clone3'],
    'open':  ['open', 'openat', 'openat2'],
    # 여기에 추가 파생 이름을 넣으면 자동 확장됨
}

# ——— eBPF 코드 템플릿 ———
BPF_TEMPLATE = """\
#define __TARGET_ARCH_x86
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/string.h>   // for strncmp

#include "common_maps.h"
#include "common_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/__x64_sys_{name}")
int trace_{name}(struct pt_regs *ctx) {{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 네임스페이스 플래그 + 컨테이너 런타임 필터
    if (!(flags & (CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET)) ||
        !(strncmp(comm,"runc",4)==0 ||
          strncmp(comm,"conmon",6)==0 ||
          strncmp(comm,"containerd-shim",15)==0 ||
          strncmp(comm,"docker",6)==0))
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->type  = EVT_{NAME};
    e->ts_ns = bpf_ktime_get_ns();
{bindings}
    bpf_ringbuf_submit(e, 0);
    return 0;
}}
"""

# ——— man 페이지에서 인자 이름 추출 ———
def get_proto(syscall):
    """ `man 2 syscall` 호출 후 SYNOPSIS에서 인자 이름만 추출 """
    try:
        text = subprocess.check_output(['man', '2', syscall],
                                       text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return []
    m = re.search(r'\n\s*' + re.escape(syscall) + r'\s*\(([^)]*)\)', text)
    if not m:
        return []
    args = [arg.strip() for arg in m.group(1).split(',')]
    names = []
    for arg in args:
        parts = arg.split()
        if len(parts) >= 2:
            names.append(parts[-1])
    return names

# ——— CSV 파싱 & syscall 리스트 생성 ———
def parse_csv():
    df = pd.read_csv(CSV_PATH)
    syscalls = []
    for base in df['syscall name'].unique():
        for alias in alias_map.get(base, [base]):
            syscalls.append((alias, base))
    return syscalls, df

# ——— 인자 바인딩 코드 생성 ——— //현재 인자형태에 따라 스칼라, 포인터, 구조체 구분까지는 구현
def make_bindings(name, types, arg_names):
    lines = []
    for idx, (typ, var) in enumerate(zip(types, arg_names), start=1):
        parm = f"PT_REGS_PARM{idx}(ctx)"
        # 포인터 타입
        if '*' in typ:
            # 대상이 스칼라인지 구조체인지 구분
            # 예: 'int *' 또는 'struct foo *'
            base = typ.replace('*','').strip()
            if base in ['int','long','size_t','__u32','__u64']:
                # 스칼라 포인터
                lines.append(f"    {base} tmp_{var};")
                lines.append(
                    f"    bpf_probe_read_user(&tmp_{var}, "
                    f"sizeof(tmp_{var}), (void *){parm});"
                )
                lines.append(f"    e->data.{name}.{var} = tmp_{var};")
            else:
                # 구조체 포인터 혹은 문자열
                lines.append(f"    void *ptr_{var} = (void *){parm};")
                lines.append(
                    f"    bpf_probe_read_user(&e->data.{name}.{var}, "
                    f"sizeof(e->data.{name}.{var}), ptr_{var});"
                )
        else:
            # 일반 스칼라 인자
            lines.append(
                f"    e->data.{name}.{var} = ({typ}){parm};"
            )
    return "\n".join(lines)
# ——— .bpf.c 코드 생성 ———
def generate_bpf_code(name, types, arg_names):
    NAME = name.upper()
    bindings = make_bindings(name, types, arg_names)
    return BPF_TEMPLATE.format(name=name, NAME=NAME, bindings=bindings)

# ——— Makefile 템플릿 ———
MAKEFILE = """\
BPFTOOL := bpftool
CC      := clang
CFLAGS  := -O2 -g -target bpf

TARGETS := {targets}

all: $(TARGETS:%=%_monitor.bpf.o) $(TARGETS:%=%_monitor.skel.h)

%.bpf.o: bpf/%_monitor.bpf.c
\t$(CC) $(CFLAGS) -c $< -o $@

%_monitor.skel.h: %_monitor.bpf.o
\t$(BPFTOOL) gen skeleton $< > $@

clean:
\trm -f bpf/*.bpf.* *.skel.h
"""

# ——— monitor_loader.c 템플릿 ———
LOADER_TEMPLATE = """\
#include <stdio.h>
#include <bpf/libbpf.h>
#include <librdkafka/rdkafka.h>
#include "common_event.h"

{includes}

static rd_kafka_t *rk;
void init_kafka() {{
    char err[512];
    rd_kafka_conf_t *conf = rd_kafka_conf_new();
    rd_kafka_conf_set(conf, "bootstrap.servers", "localhost:9092", err, sizeof(err));
    rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, err, sizeof(err));
}}

static int on_event(void *ctx, void *data, size_t size) {{
    struct event_t *e = data;
    char buf[256];
    int len = snprintf(buf, sizeof(buf),
        "{{\\"type\\":%u,\\"pid\\":%u,\\"ts\\":%llu}}\\n",
        e->type, e->pid, e->ts_ns);
    rd_kafka_producev(
        rk,
        RD_KAFKA_V_TOPIC("syscall_events"),
        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
        RD_KAFKA_V_VALUE(buf, len),
        RD_KAFKA_V_END
    );
    return 0;
}}

int main() {{
{attaches}
    int map_fd = bpf_map__fd({first}_skel->maps.events);
    struct ring_buffer *rb = ring_buffer__new(map_fd, on_event, NULL, NULL);
    init_kafka();
    printf("Monitoring... Ctrl+C to exit\\n");
    while (1)
        ring_buffer__poll(rb, 100);

{destroys}
    return 0;
}}
"""

def main():
    os.makedirs(BPF_DIR, exist_ok=True)
    syscalls, df = parse_csv()

    includes = []
    attaches = []
    destroys = []
    targets = []

    # 1) .bpf.c 생성
    for alias, base in syscalls:
        # CSV에서 타입 리스트
        row = df[df['syscall name'] == base].iloc[0]
        types = []
        for i in range(6):
            col = f'arg{i} (%r{i if i<3 else {3:10,4:8,5:9}[i]})'
            if col in row and isinstance(row[col], str) and row[col] != '-':
                types.append(row[col].split()[0])

        # 인자명 추출
        arg_names = get_proto(alias)
        if not arg_names:
            arg_names = [f"arg{i}" for i in range(1, len(types)+1)]

        code = generate_bpf_code(alias, types, arg_names)
        with open(f"{BPF_DIR}/{alias}_monitor.bpf.c", 'w') as f:
            f.write(code)
        print(f"Generated bpf/{alias}_monitor.bpf.c")

        targets.append(alias)
        includes.append(f'#include "{alias}_monitor.skel.h"')
        attaches.append(textwrap.indent(
            f"struct {alias}_monitor_bpf *{alias}_skel = {alias}_monitor_bpf__open_and_load();\n"
            f"if (!{alias}_skel || {alias}_monitor_bpf__attach({alias}_skel)) return 1;\n", '    '))
        destroys.append(f"    {alias}_monitor_bpf__destroy({alias}_skel);")

    # 2) Makefile 생성
    mk = MAKEFILE.format(targets=' '.join(targets))
    with open(f"{OUT_DIR}/Makefile", 'w') as f:
        f.write(mk)
    print("Generated Makefile")

    # 3) monitor_loader.c 생성
    loader = LOADER_TEMPLATE.format(
        includes='\n'.join(includes),
        attaches='\n'.join(attaches),
        destroys='\n'.join(destroys),
        first=targets[0]
    )
    with open(f"{OUT_DIR}/monitor_loader.c", 'w') as f:
        f.write(loader)
    print("Generated monitor_loader.c")

if __name__ == '__main__':
    main()
