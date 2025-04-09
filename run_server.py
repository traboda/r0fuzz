import subprocess
import time
import sys
import os
import argparse

session_start = time.strftime("%d%m%Y%H%M%S")
CRASH_log_file = f"crashes/crashes_{session_start}.log"
INTERPRETER_log_file = "logs/Interpreter.log"

def log_crash():
    os.makedirs("crashes", exist_ok=True)
    with open(CRASH_log_file, "a") as f:
        with open(INTERPRETER_log_file, "r") as i:
            f.write(i.readlines()[-1].lstrip("[*] "))
   
    print(f"Crash logged to {CRASH_log_file}")
    return

def run_server(server_path, library_path, replay_mode=False):
    env = os.environ.copy()
    env['LD_PRELOAD'] = library_path
    
    while True:
        try:
            process = subprocess.Popen([server_path], env=env)
            process.wait()
            if process.poll() != 0:
                print(f"Server crashed. Restarting in 2 seconds.")
                print("========================================\n")
                if not replay_mode:
                    log_crash()
                time.sleep(2)
        except KeyboardInterrupt:
            print("Script interrupted by user. Exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            time.sleep(2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a server process with a preloaded library.")
    parser.add_argument("--server", required=True, help="Path to the server executable.")
    parser.add_argument("--library", required=True, help="Path to the library.")
    parser.add_argument("-r", "--replay", action="store_true", help="Run in replay mode (skip crash logging)")
    
    args = parser.parse_args()
    
    run_server(args.server, args.library, args.replay)