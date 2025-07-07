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
import re
import pandas as pd
import code_generater
import

# ———————————————————————————————————————————————————
# 1) /proc/kallsyms 에서 __x64_sys_* 심볼 추출
with open("/proc/kallsyms") as f:
    kernel_syms = {
        re.sub(r"^__x64_sys_", "", line.split()[-1])
        for line in f
        if "__x64_sys_" in line
    }

# 2) CSV 에서 syscall 이름들 뽑기
df_tmp = pd.read_csv(CSV_PATH)
csv_syscalls = set(df_tmp["syscall name"].tolist())

# 3) 커널에 없는 것들
missing = sorted(csv_syscalls - kernel_syms)

# 4) 자동 후보 추론
auto_map = {}
for name in missing:
    cand = name.lstrip('_')  # 앞 언더바 제거
    for suffix in ('time32','time64','32','64'):
        if cand.endswith(suffix):
            cand = cand[:-len(suffix)]
    if cand in kernel_syms:
        auto_map[name] = cand

# 전역 SPECIAL_MAP 에 자동 매핑 반영
SPECIAL_MAP.update(auto_map)

#여기에 내가 직접 스페셜 맵 요소 수동으로 적을거
SPECIAL_MAP.update(MANUAL_MAP)

# 5) 이제 남은 것들(수동 매핑 필요)만 다시 계산
remaining = [n for n in missing if n not in auto_map and n not in MANUAL_MAP]

if remaining:
    print("=== SPECIAL_MAP에 수동 매핑이 필요한 이름들 ===")
    for name in remaining:
        print(f"    '{name}': '???',  # kernel has __x64_sys_{name}")
    print("==============================================\n")

if auto_map:
    print("=== 자동으로 채워진 SPECIAL_MAP 항목들 ===")
    for k, v in auto_map.items():
        print(f"    '{k}': '{v}',")
    print("=========================================\n")
# ———————————————————————————————————————————————————


# --- main ---
def main():
    """ 스크립트 메인 실행 함수 """
    syscalls, df = parse_csv()
    # alias 목록
    targets = sorted([alias for alias, _ in syscalls])
    
    # 1. bpf 헤더 파일 생성
    generate_common_event_bpf(df);

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