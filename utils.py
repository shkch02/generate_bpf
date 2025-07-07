# utils.py
import re
import subprocess
import pandas as pd
from config import CSV_PATH, MANUAL_MAP

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

# --- REFACTOR: syscall 분석 및 자동 매핑하여 code_generater로 넘겨줘야함(미구현) ---
def analyze_syscall():
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
    