

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

# --- [★★ 핵심 수정 ★★] REFACTORED: 1:1 매핑을 수행하도록 로직 변경 ---
def analyze_syscalls_from_list(target_syscalls):
    """
    [REFACTORED]
    사용자가 제공한 (확장된) 시스템 콜 별칭 목록을 기반으로,
    각 별칭의 man 페이지 존재 여부를 검증하고 (alias, alias) 튜플 리스트를 반환합니다.
    N:1 (alias -> base) 매핑 로직을 제거하고 1:1 매핑을 수행합니다.
    """
    # generate_bpf.py의 get_aliases()가 확장된 리스트를 제공했다고 가정합니다.
    syscall_aliases = sorted(list(set(target_syscalls)))
    
    print(f"Analyzing {len(syscall_aliases)} syscall aliases (1:1 mapping)...")

    final_syscalls = []      # 최종 처리될 (alias, alias) 튜플 리스트
    special_map = {}       # 맵은 비어있지만, 호환성을 위해 반환
    skipped_syscalls = []

    # 1:1 매핑을 위해 kallsyms, MANUAL_MAP 로직을 모두 제거합니다.

    for alias in syscall_aliases:
        # 1. get_proto를 호출하여 인자 파싱을 시도합니다.
        #    (get_proto는 'void' 인자나 파싱 실패 시 [], []를 반환할 수 있습니다)
        get_proto(alias)
        
        # 2. man 페이지가 실제로 존재하는지 '확인'합니다.
        #    get_proto가 파싱에 실패해도(e.g., void), man 페이지만 있으면 유효한 syscall로 간주합니다.
        check_cmd = ['man', '2', alias]
        env = os.environ.copy()
        env['LC_ALL'] = 'C'
        
        try:
            # man 페이지만 있는지 확인
            subprocess.check_output(check_cmd, text=True, stderr=subprocess.PIPE, env=env)
            
            # man 페이지가 존재하므로 유효한 syscall로 처리
            print(f"  -> Successfully validated: {alias}")
            final_syscalls.append((alias, alias))

        except (subprocess.CalledProcessError, FileNotFoundError):
            # man 페이지 자체가 없음
            print(f"  [WARN] 'man 2 {alias}' not found. Skipping.")
            skipped_syscalls.append(alias)

    if skipped_syscalls:
        print("\n=== 건너뛴 시스템 콜 목록 (man 2 페이지 없음) ===")
        print(f"# {skipped_syscalls}")
        print("================================================\n")
    
    if not final_syscalls:
        print("\n[ERROR] No valid syscalls could be processed from the input list. Aborting.")
        return {}, []

    print(f"Successfully processed {len(final_syscalls)} syscalls for 1:1 mapping.")
    # special_map은 비어있지만, generate_bpf.py의 API 호환성을 위해 반환
    return special_map, final_syscalls


# --- [★★ 신규 추가 ★★] (테스트용 스텁 함수) ---
def get_aliases(target_syscall):
    """
    [TEST STUB]
    주어진 syscall의 별칭 목록을 반환합니다.
    TODO: 향후 man 2 파싱 로직으로 대체되어야 합니다.
    """
    print(f"[Dev Stub] get_aliases({target_syscall}) called...")
    
    # 테스트용 매핑 (필요에 따라 확장하세요)
    alias_map = {
        'open': ['open', 'openat', 'openat2'],
        'lseek': ['lseek'],
        'close': ['close'],
        # 'read': ['read', 'pread64', 'readv'],
    }
    
    # 매핑에 없으면 자기 자신만 반환
    found = alias_map.get(target_syscall, [target_syscall])
    print(f"           -> returning: {found}")
    return found