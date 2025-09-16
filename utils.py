

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

# --- REFACTOR: syscall 분석 및 자동 매핑하여 syscalls,specail maps 리턴 ---
def analyze_syscall():
    # 1) /proc/kallsyms 에서 __x64_sys_* 심볼 추출
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

    # 2) man 페이지에서 syscall 이름들 뽑기
    syscalls_from_man = parse_man()
    if not syscalls_from_man:
        print("[ERROR] Could not get syscall list. Aborting.")
        return {}, []
        
    user_space_syscalls = {name for name, _ in syscalls_from_man}

    # 3) 커널에 없는 것들
    missing = sorted(user_space_syscalls - kernel_syms)

    # 4) 자동 후보 추론
    auto_map = {}
    for name in missing:
        cand = name.lstrip('_')  # 앞 언더바 제거
        for suffix in ('time32','time64','32','64'):
            if cand.endswith(suffix):
                cand = cand[:-len(suffix)]
        if cand in kernel_syms:
            auto_map[name] = cand

    final_special_map = MANUAL_MAP.copy()
    final_special_map.update(auto_map)
    
    # 5) 이제 남은 것들(수동 매핑 필요)만 다시 계산
    remaining = [n for n in missing if n not in auto_map and n not in MANUAL_MAP]

    if remaining:
        print("\n=== SPECIAL_MAP에 수동 매핑이 필요한 이름들 ===") #여기에 지금 break 들어가고 있음
        for name in remaining:
            print(f"    '{name}': '???',")
        print("==============================================\n")

    if auto_map:
        print("=== 자동으로 채워진 SPECIAL_MAP 항목들 ===")
        for k, v in auto_map.items():
            print(f"    '{k}': '{v}',")
        print("=========================================\n")

    return final_special_map, syscalls_from_man
