#!/usr/bin/env python3
# ubuntu 22.04 LTS에서 실행

# --- 다른 모듈에서 필요한 함수들을 가져옵니다 ---
from utils import parse_csv, analyze_syscall
from code_generator import (
    generate_common_event_bpf,
    generate_common_event_user,
    generate_bpf_sources,
    generate_makefile,
    generate_loader
)

def main():
    """ 스크립트 메인 실행 함수 """

    # 1. 시스템 콜 분석 및 매핑 정보 생성 (utils.py에 위임)
    print("Analyzing syscalls...") 
    special_map = analyze_syscall() 

    # 2. CSV 파일 파싱 (utils.py에 위임)
    print("\nParsing CSV file...")
    syscalls= parse_csv()

    # 3. 생성할 타겟 목록 정리
    targets = sorted([alias for alias, _ in syscalls])

    # 4. 각 코드/파일 생성 함수 순차 호출 (code_generator.py에 위임)
    print("\nGenerating BPF common header...")
    generate_common_event_bpf(targets)

    print("Generating user-space common header...")
    generate_common_event_user(targets)

    print("Generating BPF source files...")
    generate_bpf_sources(syscalls,special_map)

    print("Generating Makefile and Loader source...")
    generate_makefile(targets)
    generate_loader(targets)

    print("\n✅ Generation complete. Run 'make' to build.")

if __name__ == '__main__':
    main()