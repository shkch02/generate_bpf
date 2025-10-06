#!/usr/bin/env python3
# ubuntu 22.04 LTS에서 실행  

import json
import argparse 

# --- 다른 모듈에서 필요한 함수들을 가져옵니다 ---
#man 2 syscall 파싱 함수로 대체필요함
from utils import analyze_syscalls_from_list
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

    # 2. 시스템 콜 분석 및 매핑 정보 생성 json받는걸로 리팩토링할 예정 
    print("Analyzing syscalls and parsing man pages...")
    special_map, syscalls = analyze_syscalls_from_list(target_syscalls)

    if not syscalls:
        print("\n[ERROR] Could not retrieve syscall list. Aborting.")
        return

    # 3. 생성할 타겟 목록 정리 (별칭과 기본 이름 분리)
    aliases = sorted([alias for alias, _ in syscalls])
    bases = sorted(list(set(base for _, base in syscalls)))

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