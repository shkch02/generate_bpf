import re
import json
import argparse 



def get_syscalls_from_json(args):

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
        
    base = target_syscalls

            
    
  
    return bases

def get_args():
    parser = argparse.ArgumentParser(description="Generate eBPF monitoring tools for specific syscalls from a JSON file.")
    parser.add_argument(
        "-f", "--file",
        required=True, 
        help="Path to a JSON file containing a list of syscall names to monitor."
    )
    args = parser.parse_args()

    bases = get_syscalls_from_json(args)
    
    return special_map, bases
