

# utils.py
import os
import re
import subprocess
from config import MANUAL_MAP

# --- man 페이지 분석해서 시스템 콜별 인자 이름 추출 ---
def get_proto(syscall):
    """ `man 2 syscall` 호출 후 SYNOPSIS에서 인자 타입과 이름을 추출 """
    try:
        env = os.environ.copy()
        env['LC_ALL'] = 'C'
        text = subprocess.check_output(['man', '2', syscall], text=True, stderr=subprocess.PIPE, env=env)
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

# ---man 2 syscalls 분석하여 시스템 콜 리스트 튜플형태로 추출 ---
def parse_man():
    """
    'man 2 syscalls' 페이지의 'System call list' 테이블을 파싱하여
    x86_64에서 사용 가능한 시스템 콜 목록을 동적으로 생성합니다.
    """
    print("Parsing 'man 2 syscalls' to get the list of syscalls...")
    try:
        env = os.environ.copy()
        env['LC_ALL'] = 'C'
        text = subprocess.check_output(['man', '2', 'syscalls'], text=True, stderr=subprocess.PIPE, env=env)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("\n[ERROR] 'man 2 syscalls' command failed. Is 'manpages-dev' installed?")
        return []

    # 필터링할 키워드 정의 (소문자로 비교)
    EXCLUDE_KEYWORDS = [
        'alpha', 'arc', 'arm', 'avr32', 'blackfin', 'csky', 'ia-64', 'm68k', 
        'metag', 'mips', 'openrisc', 'parisc', 'powerpc', 'risc-v', 's390', 
        'sh', 'sparc', 'Xtensa', 'tile',
        'not on x86', 'removed in', 'deprecated'
    ]

    syscall_names = set()
    in_table = False

    for line in text.splitlines():
        # 테이블 시작점 찾기
        if "System call" in line and "Kernel" in line and "Notes" in line:
            in_table = True
            continue
        
        # 테이블 종료점 찾기
        if in_table and line.strip() == "SEE ALSO":
            break
            
        if in_table:
            # 빈 줄이나 구분선은 건너뛰기
            if not line.strip() or "──────" in line:
                continue
            
            #정규표현식으로 시스템콜 목록 파싱
            match = re.match(r'^\s*(\w+)\(2\)', line)
            if not match:
                continue
            
            name = match.group(1)
            notes = line[match.end():].strip().lower()
            
            is_excluded = False
            if notes:
                for keyword in EXCLUDE_KEYWORDS:
                    if keyword in notes:
                        is_excluded = True
                        break
            
            if not is_excluded:
                #notImplement 함수들 필터링 필요함 //안필요한거 같기도? 어차피 커널단이랑 비교하니까 
                    syscall_names.add(name)
            if name == 'xtensa':
                break

    if not syscall_names:
        print("\n[WARNING] Could not parse any valid syscalls from man page.")
        return []
        
    print(f"Successfully parsed {len(syscall_names)} filtered syscalls from man page.")
    
    return [(name, name) for name in sorted(list(syscall_names))]


# --- REFACTOR: 중복 로직을 헬퍼 함수로 추출 ---
def get_syscall_info(syscall_name):
    """ 주어진 syscall에 대한 타입과 인자 이름 목록을 man 페이지에서 직접 추출 """
    types, arg_names = get_proto(syscall_name)
    return types, arg_names

# --- REFACTORED & COMBINED: 두 함수의 장점을 결합한 최종 분석 함수 ---
def analyze_syscalls_from_list(target_syscalls):
    """
    사용자가 제공한 시스템 콜 목록을 기반으로 커널 심볼을 찾고,
    매핑 정보를 생성하며, 찾지 못한 심볼은 사용자에게 알려줍니다.
    """
    # 1) /proc/kallsyms 에서 커널 심볼을 한 번만 읽어 Set으로 만듭니다.
    print("Reading kernel symbols from /proc/kallsyms...")
    try:
        with open("/proc/kallsyms") as f:
            kernel_syms = {
                re.sub(r"^__x64_sys_", "", line.split()[-1])
                for line in f
                if "__x64_sys_" in line
            }
    except FileNotFoundError:
        print("[ERROR] /proc/kallsyms not found. Are you running on Linux?")
        return {}, []

    # --- 분석 결과를 저장할 변수들 ---
    user_space_syscalls = sorted(list(set(target_syscalls))) # 입력 목록 (중복제거, 정렬)
    final_syscalls = []      # 최종 처리될 (alias, base) 튜플 리스트
    final_special_map = {}   # 최종 special_map
    
    # --- 매칭되지 않은 심볼을 찾기 위한 과정 ---
    # 2) 커널 심볼과 일치하지 않는 사용자 공간 심볼 목록(missing)을 찾습니다.
    missing = [name for name in user_space_syscalls if name not in kernel_syms]

    # 3) 자동 후보 추론 (auto_map 생성)
    auto_map = {}
    for name in missing:
        # MANUAL_MAP에 이미 정의된 경우는 건너뜁니다.
        if name in MANUAL_MAP:
            continue
            
        cand = name.lstrip('_')
        for suffix in ('time32', 'time64', '32', '64'):
            if cand.endswith(suffix):
                cand = cand[:-len(suffix)]
        
        if cand in kernel_syms:
            auto_map[name] = cand

    # 4) 최종 special_map을 생성합니다. (수동 + 자동)
    final_special_map = MANUAL_MAP.copy()
    final_special_map.update(auto_map)

    # 5) 최종적으로 처리할 시스템 콜 목록(final_syscalls)을 만듭니다.
    for name in user_space_syscalls:
        # 커널에 심볼이 그대로 있는 경우
        if name in kernel_syms:
            final_syscalls.append((name, name))
        # special_map (수동 또는 자동)에 매핑 정보가 있는 경우
        elif name in final_special_map:
            final_syscalls.append((name, final_special_map[name]))
        # 매칭되는 심볼이 전혀 없는 경우 (이 경우는 건너뜀)
        else:
            continue

    # 6) 사용자에게 매핑 결과와 수동 매핑이 필요한 목록을 출력합니다.
    remaining = [n for n in missing if n not in final_special_map]

    if remaining:
        print("\n=== SPECIAL_MAP에 수동 매핑이 필요한 이름들 ===")
        print("# 아래 시스템 콜은 커널 심볼을 찾지 못했습니다. config.py의 MANUAL_MAP에 추가해야 할 수 있습니다.")
        for name in remaining:
            print(f"    '{name}': '???',")
        print("==============================================\n")

    if auto_map:
        print("=== 자동으로 채워진 SPECIAL_MAP 항목들 ===")
        for k, v in auto_map.items():
            print(f"    '{k}': '{v}',")
        print("=========================================\n")
    
    if not final_syscalls:
        print("\n[ERROR] No valid syscalls could be processed from the input list. Aborting.")
        return {}, []

    print(f"Successfully processed {len(final_syscalls)} syscalls.")
    return final_special_map, final_syscalls