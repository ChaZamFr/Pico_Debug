#!/usr/bin/env python3
from concurrent.futures import process
import signal
import subprocess
import time
import sys
import os
import random
import argparse
import re
from threading import Thread
from queue import Queue

ON_POSIX = 'posix' in sys.builtin_module_names


def enqueue_output(out, queue):
    # text=True -> readline() returns str; sentinel must be ''
    for line in iter(out.readline, ''):
        if line == '':
            break
        queue.put(line)
    try:
        out.close()
    except Exception:
        pass


def parse_args():
    p = argparse.ArgumentParser(
        description="OpenOCD + GDB fault injection runner (with CLI timeout control)"
    )
    p.add_argument("openocd_cfg", help="Path to OpenOCD cfg file")
    p.add_argument("elf", help="Path to ELF to load")
    p.add_argument("num_inst", type=int, help="Number of instructions in FI area")
    p.add_argument("run_length_us", type=int, help="Run length of FI area (microseconds)")
    p.add_argument("num_runs", type=int, help="Number of runs")
    p.add_argument("register_fi", type=int, help="Register index to target for FI (e.g., 0 for r0)")
    p.add_argument("reg_len", type=int, help="Register length in bits (e.g., 32)")

    g = p.add_mutually_exclusive_group()
    g.add_argument("-t", "--timeout-seconds", type=float,
                   help="Timeout window in SECONDS (e.g., -t 5.0)")
    g.add_argument("--timeout-us", type=int,
                   help="Timeout window in MICROSECONDS (e.g., --timeout-us 5000000)")

    p.add_argument("--min-timeout-seconds", type=float, default=0.1,
                   help="Minimum timeout in seconds if automatic timeout is chosen (default: 0.1s)")

    return p.parse_args()


def compute_timeout_seconds(args) -> float:
    if getattr(args, "timeout_seconds", None) is not None:
        return max(args.timeout_seconds, 0.0)
    if getattr(args, "timeout_us", None) is not None:
        return max(args.timeout_us / 1_000_000.0, 0.0)
    auto_us = 10 * args.run_length_us
    auto_s = auto_us / 1_000_000.0
    return max(auto_s, float(args.min_timeout_seconds))


def _read_gdb_output(gdb_process, timeout_s, pattern=None):
    """
    Reads from the GDB process stdout until a pattern is matched or a timeout occurs.
    Returns the accumulated output.
    """
    start_time = time.time()
    output_buffer = ""
    while time.time() - start_time < timeout_s:
        try:
            chunk = gdb_process.stdout.read(1)
            if not chunk:
                # GDB process might have closed
                return output_buffer
            output_buffer += chunk
            if pattern and pattern in output_buffer:
                return output_buffer
            if "(gdb)" in output_buffer:
                return output_buffer
        except IOError:
            break
    return output_buffer


def send_gdb_and_collect(gdb_proc, q, cmd, timeout_sec=1.0):
    """
    Send a gdb command (string without trailing newline) to gdb_proc.stdin,
    then collect text output from queue `q` for up to timeout_sec seconds.
    Returns the concatenated output string.
    """
    try:
        gdb_proc.stdin.write(cmd + '\n')
        gdb_proc.stdin.flush()
    except Exception:
        # stdin may be closed or process dead
        return ""
    out = ""
    start = time.time()
    # gather output for up to timeout_sec seconds
    while time.time() - start < timeout_sec:
        while not q.empty():
            out += q.get_nowait()
        # if we've seen a gdb prompt or a typical result line containing '=' or 'Breakpoint' we can break early
        if re.search(r"\$\d+\s*=", out) or re.search(r"Breakpoint\s+\d+", out) or re.search(r"\(gdb\)", out):
            # still keep a short tail to allow multi-line responses
            time.sleep(0.01)
            while not q.empty():
                out += q.get_nowait()
            break
        time.sleep(0.01)
    while not q.empty():
        out += q.get_nowait()
    #print("from the gdb collect function " + out)
    return out


def extract_first_hex(s):
    """
    From a string s (gdb output), return the first 0x... hex as int.
    If none found, return None.
    """
    m = re.search(r"(0x[0-9A-Fa-f]+)", s)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except:
        return None




def start_gdb(gdb_exec, elf_file, gdb_cmds):
    """Start a new GDB process, attach a queue+thread to stdout, send initial commands.
    Returns (gdb_process, queue, thread).
    """
    gdb_process = subprocess.Popen(
        [gdb_exec, "--nx"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    q = Queue()
    t = Thread(target=enqueue_output, args=(gdb_process.stdout, q), daemon=True)
    t.start()
    # send initial gdb commands
    gdb_input_init = '\n'.join(gdb_cmds) + '\n'
    try:
        gdb_process.stdin.write(gdb_input_init)
        gdb_process.stdin.flush()
    except Exception:
        pass
    return gdb_process, q, t


def graceful_kill_gdb(gdb_process, timeout=2.0):
    """Try to cleanly stop/quit a gdb process, then force if necessary."""
    if gdb_process is None:
        return
    try:
        if gdb_process.poll() is None:
            # first try to ask gdb to quit politely
            try:
                gdb_process.stdin.write("quit\n")
                gdb_process.stdin.flush()
            except Exception:
                pass
            # wait briefly
            t0 = time.time()
            while time.time() - t0 < 0.25 and gdb_process.poll() is None:
                time.sleep(0.05)
        if gdb_process.poll() is None and ON_POSIX:
            # send SIGINT to the process group
            try:
                os.killpg(gdb_process.pid, signal.SIGINT)
            except Exception:
                try:
                    os.kill(-gdb_process.pid, signal.SIGINT)
                except Exception:
                    pass
        # wait a bit
        try:
            gdb_process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                gdb_process.terminate()
                gdb_process.wait(timeout=1)
            except Exception:
                try:
                    gdb_process.kill()
                    gdb_process.wait()
                except Exception:
                    pass
    except Exception:
        pass


def main():
    args = parse_args()

    elf_file = args.elf
    openocd_cfg = args.openocd_cfg
    NUM_INST = int(args.num_inst)
    RUN_LENGTH = int(args.run_length_us)          # microseconds
    NUM_RUNS = int(args.num_runs)
    REGISTER_FI = int(args.register_fi)
    REG_LEN = int(args.reg_len)

    timeout = compute_timeout_seconds(args)
    timeout_us_display = int(timeout * 1_000_000)
    #print(f"[INFO] Timeout window: {timeout:.3f} s ({timeout_us_display} µs)")

    if not os.path.exists(elf_file):
        print(f"Error: ELF file '{elf_file}' not found.")
        sys.exit(1)

    if not os.path.exists(openocd_cfg):
        print(f"Error: OpenOCD config file '{openocd_cfg}' not found.")
        sys.exit(1)

    #print(f"Debugging {elf_file} with OpenOCD config {openocd_cfg}")
    gdb_exec = "arm-none-eabi-gdb"

    try:
        #print("Starting OpenOCD...")
        openocd_process = subprocess.Popen(
            ["openocd", "-f", openocd_cfg],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(2)
        if openocd_process.poll() is not None:
            stdout, stderr = openocd_process.communicate()
            print("OpenOCD failed to start.")
            print("Stdout:", stdout)
            print("Stderr:", stderr)
            sys.exit(1)
        print("OpenOCD is running.")

    except FileNotFoundError as e:
        print(f"Error: {e}. Ensure '{e.filename}' is in PATH.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error starting OpenOCD: {e}")
        sys.exit(1)

    # Initial GDB setup commands (used each time we (re)start gdb)
    gdb_cmds = [
        f"file {elf_file}",
        "target remote localhost:3333",
        "monitor reset halt",
        "load",
        "break START_F_INJECT",
        "break END_F_INJECT",
        "break FAULT_CHECK",
        "continue"
    ]

    # Start GDB for the first time
    try:
        gdb_process, q, t = start_gdb(gdb_exec, elf_file, gdb_cmds)
        #print("GDB process started with PID:", gdb_process.pid)
    except FileNotFoundError as e:
        print(f"Error: {e}. Ensure '{e.filename}' is in PATH.")
        openocd_process.terminate()
        openocd_process.wait()
        sys.exit(1)

    run_number = 0
    inserted_breakpoint_num = 4  
    #print("This is where breakpoint is set to 4")
    while True:
        run_number += 1
        print(f"\nRUN {run_number}")

        bit_pos_to_change = random.randint(1, REG_LEN)
        zero_based_bit = bit_pos_to_change - 1
        fault_reg_name = f"r{REGISTER_FI}"
        bitmask = 1 << zero_based_bit

        while True:
            timeout_exit = 0
            success = 0

            start_time = time.time()
            breakpoint_hit = False

            while time.time() - start_time < timeout:
                output_buffer = ""
                while not q.empty():
                    output_buffer += q.get_nowait()

                if output_buffer:
                    
                    if "Breakpoint 1, START_F_INJECT" in output_buffer:
                        breakpoint_hit = True
                        #print("[GDB] START_F_INJECT hit.")

                        
                        pc_out = send_gdb_and_collect(gdb_process, q, "p/x $pc", timeout_sec=1.0)
                        reg_out = send_gdb_and_collect(gdb_process, q, f"p/x ${fault_reg_name}", timeout_sec=1.0)
                        pc_val = extract_first_hex(pc_out)
                        reg_val = extract_first_hex(reg_out)
                        #print(f"[AT START] pc=0x{pc_val:08X}" if pc_val is not None else f"[AT START] pc=unknown")
                        if reg_val is not None:
                            bit_before = (reg_val >> zero_based_bit) & 1
                            #print(f"[AT START] {fault_reg_name} = 0x{reg_val:08X}  (bit {zero_based_bit} = {bit_before})")
                        else:
                            print(f"[AT START] {fault_reg_name} value not found in gdb output:\n{reg_out}")

                        # exit function
                        send_gdb_and_collect(gdb_process, q, "finish", timeout_sec=1.0)
                        pc_out = send_gdb_and_collect(gdb_process, q, "p/x $pc", timeout_sec=1.0)
                        pc_val = extract_first_hex(pc_out)

                        # insert temporary breakpoint in FI region
                        brkpt_offset = 10
                        #print(f"[GDB] Inserting temp breakpoint at $pc+{brkpt_offset} ({hex(brkpt_offset)})")
                        send_gdb_and_collect(gdb_process, q, f"break *$pc+{brkpt_offset}", timeout_sec=1.0)
                        send_gdb_and_collect(gdb_process, q, "continue", timeout_sec=1.0)

                        # Wait for the inserted breakpoint to be reached
                        temp_buffer = ""
                        inset_wait_start = time.time()
                        while time.time() - inset_wait_start < max(1.0, timeout):
                            while not q.empty():
                                temp_buffer += q.get_nowait()
                                #print("temp buffer" + temp_buffer)
                                #print(f"Breakpoint {inserted_breakpoint_num}")
                            if f"Breakpoint {inserted_breakpoint_num}" in temp_buffer:
                                #print("[GDB] Inserted breakpoint reached.")
                                # read original reg
                                orig_out = send_gdb_and_collect(gdb_process, q, f"p/x ${fault_reg_name}", timeout_sec=1.0)
                                orig_val = extract_first_hex(orig_out)
                                if orig_val is None:
                                    print(f"[INJECT] Couldn't parse original {fault_reg_name} from GDB output:\n{orig_out}")
                                else:
                                    bit_before_inject = (orig_val >> zero_based_bit) & 1
                                    #print(f"[INJECT] Original {fault_reg_name} = 0x{orig_val:08X} (bit {zero_based_bit} = {bit_before_inject})")

                                # perform flip
                                send_gdb_and_collect(gdb_process, q, f"set ${fault_reg_name} = ${fault_reg_name} ^ (1 << {zero_based_bit})", timeout_sec=1.0)
                                # read new 
                                new_out = send_gdb_and_collect(gdb_process, q, f"p/x ${fault_reg_name}", timeout_sec=1.0)
                                new_val = extract_first_hex(new_out)
                                if new_val is None:
                                    print(f"[INJECT] Couldn't parse new {fault_reg_name} from GDB output:\n{new_out}")
                                else:
                                    bit_after_inject = (new_val >> zero_based_bit) & 1
                                    #print(f"[INJECT] New {fault_reg_name} = 0x{new_val:08X} (bit {zero_based_bit} = {bit_after_inject})")

                                # delete temp breakpoint and continue
                                #print(f"[GDB] delete {inserted_breakpoint_num}")
                                send_gdb_and_collect(gdb_process, q, f"delete {inserted_breakpoint_num}", timeout_sec=0.5)
                                inserted_breakpoint_num += 1
                                #print("Breakpoint num incremented to " + str(inserted_breakpoint_num))
                                send_gdb_and_collect(gdb_process, q, "continue", timeout_sec=1.0)
                                break
                            time.sleep(0.01)

                    
                    elif "Breakpoint 2, END_F_INJECT" in output_buffer:
                        breakpoint_hit = True
                        #print("[GDB] END_F_INJECT hit.")
                        # Query register value at END
                        reg_out_end = send_gdb_and_collect(gdb_process, q, f"p/x ${fault_reg_name}", timeout_sec=1.0)
                        reg_val_end = extract_first_hex(reg_out_end)
                        if reg_val_end is not None:
                            bit_end = (reg_val_end >> zero_based_bit) & 1
                            #print(f"[AT END] {fault_reg_name} = 0x{reg_val_end:08X} (bit {zero_based_bit} = {bit_end})")
                        else:
                            print(f"[AT END] Could not parse {fault_reg_name} value:\n{reg_out_end}")
                        send_gdb_and_collect(gdb_process, q, "continue", timeout_sec=1.0)

                    
                    elif "Breakpoint 3, FAULT_CHECK" in output_buffer:
                        breakpoint_hit = True
                        #print("[GDB] FAULT_CHECK hit.")
                        fault_out = send_gdb_and_collect(gdb_process, q, "p FAULT", timeout_sec=1.0)
                        # print raw output and try to parse numeric value
                        m = re.search(r"=\s*([0-9]+)", fault_out)
                        if m:
                            print(f"[CHECK] FAULT = {m.group(1)}")
                        else:
                            print(f"[CHECK] FAULT output (raw):\n{fault_out}")

                        sum_out = send_gdb_and_collect(gdb_process, q, "p sum", timeout_sec=1.0)
                        # print raw output and try to parse numeric value
                        m = re.search(r"=\s*([0-9]+)", sum_out)
                        # if m:
                        #     print(f"[CHECK] SUM = {m.group(1)}")
                        # else:
                        #     print(f"[CHECK] SUM output (raw):\n{sum_out}")
                        success = 1
                        send_gdb_and_collect(gdb_process, q, "continue", timeout_sec=1.0)
                        break

                time.sleep(0.05)

            #print(f"==== Run {run_number} done ====")

            if not breakpoint_hit:
                print(f"In Run Number {run_number}, Timeout: Breakpoint not reached within {timeout:.3f} seconds ({timeout_us_display} µs).")
                timeout_exit = 1

                graceful_kill_gdb(gdb_process, timeout=2.0)
                #print(f"Process terminated with return code {gdb_process.returncode}")

                # start a fresh GDB instance
                print("Restarting GDB...")
                try:
                    gdb_process, q, t = start_gdb(gdb_exec, elf_file, gdb_cmds)
                    #print("GDB restarted with PID:", gdb_process.pid)
                except Exception as e:
                    #print("Failed to restart GDB:", e)
                    # give up and exit
                    openocd_process.terminate()
                    openocd_process.wait()
                    sys.exit(1)

            # if timeout_exit:
            #     print("Timed out for this run — moving to next run (run number increases).")

            # if success:
            #     print("Success.")
            # print(f"Time taken for run {run_number}: {time.time() - start_time:.3f} seconds")

            break
            

        if run_number >= NUM_RUNS:
            print("All runs completed")
            break

    # cleanup
    #print("Terminating GDB process...")
    try:
        graceful_kill_gdb(gdb_process, timeout=2.0)
    except Exception:
        pass
    #print("Terminating OpenOCD process...")
    try:
        openocd_process.terminate()
        openocd_process.wait()
    except Exception:
        pass
    #print("Processes terminated.")
    sys.exit(0)


if __name__ == "__main__":
    main()


