#!/usr/bin/env python3
# ubuntu 22.04 LTS에서 실행  
import json
import argparse 

print(r"""
           @@@@@@@@@@     
     @  @@@@@@@             ____  _____  ______                                   _             
 @@@@@@@@@@@@@@====        |  _ \|  __ \|  ____|                                 | |            
@@@@@@@@@@@@@@@=====    ___| |_) | |__) | |__      __ _  ___ _ __   ___ _ __ __ _| |_ ___  _ __ 
@@@@@@@@@@@@@@*=====   / _ \  _ <|  ___/|  __|    / _` |/ _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|
@@@@@+==============  |  __/ |_) | |    | |      | (_| |  __/ | | |  __/ | | (_| | || (_) | |   
@@@@@===============   \___|____/|_|    |_|       \__, |\___|_| |_|\___|_|  \__,_|\__\___/|_|   
 @@@@=============+                                __/ |                                        
     =======   =                                  |___/                                         
     ==========      
      """)
    
print(" [  eBPF generator running... ]\n")

# --- 다른 모듈에서 필요한 함수들을 가져옵니다 ---
#man 2 syscall 파싱 함수로 대체필요함
from utils import analyze_syscalls_from_list,get_aliases
from code_generator import (
    generate_common_event_bpf,
    generate_common_event_user,
    generate_bpf_sources,
    generate_makefile,
    generate_loader
)

def main():


    """ 스크립트 메인 실행 함수 """
    parser = argparse.ArgumentParser(description="Generate eBPF monitoring tools for specific syscalls from a JSON file.")
    parser.add_argument(
        "-f", "--file",
        required=True,  # 이 인자는 필수로 입력받도록 설정
        help="Path to a JSON file containing a list of syscall names to monitor."
    )
    args = parser.parse_args()

    # 1. JSON 파일 읽기 및 예외 처리
    try:
        with open(args.file, 'r') as f:
            target_syscalls = json.load(f)
        if not isinstance(target_syscalls, list):
            # JSON 파일의 최상위 요소가 리스트가 아니면 에러 처리
            raise ValueError("JSON file content must be a list of syscall names.")
    except FileNotFoundError:
        print(f"\n[ERROR] Input file not found: {args.file}")
        return
    except (json.JSONDecodeError, ValueError) as e:
        print(f"\n[ERROR] Invalid or malformed JSON file: {e}")
        return
        
    # (will be 2.)  [수정] 타겟 목록 확장 (get_aliases 호출)
    print("Expanding syscall targets with aliases...")
    all_target_aliases = set()
    for syscall_name in target_syscalls:
        # get_aliases('open')가 ['open', 'openat', 'openat2'] 등을 
        # 반환한다고 가정합니다.
        try:
            aliases_found = get_aliases(syscall_name) # 가정의 함수 호출
            all_target_aliases.update(aliases_found)
        except Exception as e:
            print(f"[WARN] Could not get aliases for '{syscall_name}': {e}")
            # 원본 syscall 이름이라도 추가
            all_target_aliases.add(syscall_name) 
    # 중복 제거된 전체 별칭 목록
    final_target_list = sorted(list(all_target_aliases))
    if not final_target_list:
        print("\n[ERROR] No valid syscall targets found after expansion.")
        return
            
    # (will be 3.) [수정] 확장된 전체 목록으로 시스템 콜 분석
    # ★★★ 여기가 핵심입니다 ★★★
    # analyze_syscalls_from_list가 (alias, base) 튜플을 반환합니다.
    # 이 함수를 수정해서 (alias, alias)를 반환하도록 해야 합니다.
    print("Analyzing syscalls and parsing man pages...")
    special_map, syscalls = analyze_syscalls_from_list(final_target_list)
    # 'syscalls'는 이제 [('open', 'open'), ('openat', 'openat'), ...]
    # 형태가 되어야 합니다.

    # 중복 제거된 전체 별칭 목록
    final_target_list = sorted(list(all_target_aliases))
    if not final_target_list:
        print("\n[ERROR] No valid syscall targets found after expansion.")
        return

    print(f"Final target list: {final_target_list}")

    if not syscalls:
        print("\n[ERROR] Could not retrieve syscall list. Aborting.")
        return

    # 3. 생성할 타겟 목록 정리 (별칭과 기본 이름 분리)
    aliases = sorted([alias for alias, _ in syscalls])
    bases = sorted(list(set(base for _, base in syscalls)))
  
    print("\n" + "="*20 + " [ 변수 확인 ] " + "="*20)
    print(f"✅ ALIASES (별칭 목록):\n{aliases}\n")
    print(f"✅ BASES (기본 함수명 목록):\n{bases}\n")
    print(f"✅ SYSCALLS (전체 매핑 목록):\n{syscalls}")
    print("="*54 + "\n")

    # 4. 각 코드/파일 생성 함수 순차 호출 (code_generator.py에 위임)
    print("\nGenerating BPF common header...")
    generate_common_event_bpf(bases)

    print("Generating user-space common header...")
    generate_common_event_user(bases)

    print("Generating BPF source files...")
    generate_bpf_sources(syscalls, special_map)

    print("Generating Makefile and Loader source...")
    generate_makefile(aliases)
    generate_loader(syscalls)
    #모니터로더 static void fprint_json_escaped_str 함수 인코딩 문제인지 암튼 여기 해결해야함

    print("\n✅ Generation complete. Run 'make' to build.")


if __name__ == '__main__':
    main()