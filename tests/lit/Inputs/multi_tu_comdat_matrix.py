import os
import shutil
import subprocess
import sys
import tempfile


def get_base_env():
    env = os.environ.copy()
    if sys.platform.startswith("win") or os.name == "nt":
        for key in list(env.keys()):
            if key.upper() not in env:
                env[key.upper()] = env[key]
        if "SYSTEMROOT" not in env:
            env["SYSTEMROOT"] = r"C:\Windows"
        if "PROGRAMFILES(X86)" not in env:
            env["PROGRAMFILES(X86)"] = r"C:\Program Files (x86)"
        if "PROGRAMFILES" not in env:
            env["PROGRAMFILES"] = r"C:\Program Files"
    return env


def get_protected_env():
    env = get_base_env()
    env["OBF_ENABLE"] = "1"
    return env


def get_unprotected_env():
    env = get_base_env()
    for key in list(env.keys()):
        if key.upper().startswith("OBF_"):
            env.pop(key, None)
    return env


def find_msvc_lib_flags():
    if not (sys.platform.startswith("win") or os.name == "nt"):
        return []

    flags = []
    prog_x86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")

    # 1. Discover active MSVC toolchain directory (via vswhere or filesystem traversal)
    vs_install_dirs = []
    vswhere = os.path.join(prog_x86, "Microsoft Visual Studio", "Installer", "vswhere.exe")
    if os.path.isfile(vswhere):
        try:
            res = subprocess.run([vswhere, "-latest", "-property", "installationPath"], capture_output=True, text=True)
            if res.returncode == 0 and res.stdout.strip():
                vs_install_dirs.append(res.stdout.strip())
        except Exception:
            pass

    found_msvc = False
    for vs_dir in vs_install_dirs:
        msvc_root = os.path.join(vs_dir, "VC", "Tools", "MSVC")
        if os.path.isdir(msvc_root):
            for ver in sorted(os.listdir(msvc_root), reverse=True):
                lib_x64 = os.path.join(msvc_root, ver, "lib", "x64")
                if os.path.isdir(lib_x64):
                    flags.append(f"-L{lib_x64}")
                    found_msvc = True
                    break
        if found_msvc:
            break

    if not found_msvc:
        vs_root = os.path.join(prog_x86, "Microsoft Visual Studio")
        if os.path.isdir(vs_root):
            for root, dirs, _ in os.walk(vs_root):
                if "MSVC" in dirs:
                    msvc_root = os.path.join(root, "MSVC")
                    for ver in sorted(os.listdir(msvc_root), reverse=True):
                        lib_x64 = os.path.join(msvc_root, ver, "lib", "x64")
                        if os.path.isdir(lib_x64):
                            flags.append(f"-L{lib_x64}")
                            found_msvc = True
                            break
                    if found_msvc:
                        break

    # 2. Discover active Windows 10/11 SDK library directory
    wk_root = os.path.join(prog_x86, "Windows Kits", "10", "Lib")
    if os.path.isdir(wk_root):
        for ver in sorted(os.listdir(wk_root), reverse=True):
            ucrt = os.path.join(wk_root, ver, "ucrt", "x64")
            um = os.path.join(wk_root, ver, "um", "x64")
            if os.path.isdir(ucrt) and os.path.isdir(um):
                flags.append(f"-L{ucrt}")
                flags.append(f"-L{um}")
                break

    return flags


def resolve_driver(path):
    path = path.strip('\'"')
    if os.path.isfile(path):
        if not path.endswith((".exe", ".cmd", ".bat")):
            return [sys.executable, path]
        return [path]
    if sys.platform.startswith("win") or os.name == "nt":
        if path.endswith(".exe") and os.path.isfile(path[:-4] + ".cmd"):
            return [path[:-4] + ".cmd"]
        if path.endswith(".exe") and os.path.isfile(path[:-4]):
            return [sys.executable, path[:-4]]
        if os.path.isfile(path + ".cmd"):
            return [path + ".cmd"]
        if os.path.isfile(path + ".bat"):
            return [path + ".bat"]
    found = shutil.which(path)
    if found:
        return [found]
    return [path]


def run_cmd(cmd, env=None):
    if env is None:
        env = get_base_env()
    res = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}\nEXIT: {res.returncode}\nSTDERR: {res.stderr}\nSTDOUT: {res.stdout}")
        sys.exit(res.returncode)
    return res


def main():
    if len(sys.argv) < 5:
        print("Usage: multi_tu_comdat_matrix.py <clangxx> <plugin> <runtime> <out_base>")
        sys.exit(1)

    driver_cmd = resolve_driver(sys.argv[1])
    plugin = sys.argv[2].strip('\'"')
    runtime = sys.argv[3].strip('\'"')
    out_base = sys.argv[4].strip('\'"')
    lib_flags = find_msvc_lib_flags()

    work_dir = tempfile.mkdtemp(prefix="multi_tu_test_")
    log_lines = [f"RESOLVED_DRIVER: {' '.join(driver_cmd)}"]

    try:
        # Case A: Protected TU1 + Unprotected TU2 (Identical Literal)
        tu1_a_src = os.path.join(work_dir, "tu1_a.cpp")
        tu2_a_src = os.path.join(work_dir, "tu2_a.cpp")
        tu1_a_obj = os.path.join(work_dir, "tu1_a.o")
        tu2_a_obj = os.path.join(work_dir, "tu2_a.o")
        app_a_order1 = os.path.join(work_dir, "app_a_order1.exe")
        app_a_order2 = os.path.join(work_dir, "app_a_order2.exe")

        with open(tu1_a_src, "w", encoding="utf-8") as f:
            f.write("""
#if defined(__clang__)
#define OBF_PROTECT(level) __attribute__((annotate("obf:" level)))
#else
#define OBF_PROTECT(level)
#endif
OBF_PROTECT("light")
const char* get_str(void) {
    return "SensitiveData12345";
}
""")

        with open(tu2_a_src, "w", encoding="utf-8") as f:
            f.write("""
extern "C" int printf(const char*, ...);
extern "C" int strcmp(const char*, const char*);
const char* get_str(void);
int main() {
    const char* s = get_str();
    const char* lit = "SensitiveData12345";
    printf("CASE_A: S=%s | L=%s\\n", s, lit);
    if (strcmp(s, "SensitiveData12345") != 0 || strcmp(lit, "SensitiveData12345") != 0) {
        return 1;
    }
    return 0;
}
""")

        run_cmd(driver_cmd + ["-O1", "-fno-inline", f"-fpass-plugin={plugin}", "-c", tu1_a_src, "-o", tu1_a_obj], env=get_protected_env())
        run_cmd(driver_cmd + ["-O1", "-fno-inline", "-c", tu2_a_src, "-o", tu2_a_obj], env=get_unprotected_env())

        # Link order 1: tu2 (unprotected) first
        run_cmd(driver_cmd + lib_flags + [tu2_a_obj, tu1_a_obj, runtime, "-o", app_a_order1], env=get_unprotected_env())
        res1 = subprocess.run([app_a_order1], capture_output=True, text=True)
        log_lines.append(f"CASE_A_ORDER1: exit={res1.returncode} stdout={res1.stdout.strip()}")

        # Link order 2: tu1 (protected) first
        run_cmd(driver_cmd + lib_flags + [tu1_a_obj, tu2_a_obj, runtime, "-o", app_a_order2], env=get_unprotected_env())
        res2 = subprocess.run([app_a_order2], capture_output=True, text=True)
        log_lines.append(f"CASE_A_ORDER2: exit={res2.returncode} stdout={res2.stdout.strip()}")

        # Case B: Protected TU1 + Protected TU2 (Identical Literal)
        tu1_b_src = os.path.join(work_dir, "tu1_b.cpp")
        tu2_b_src = os.path.join(work_dir, "tu2_b.cpp")
        tu1_b_obj = os.path.join(work_dir, "tu1_b.o")
        tu2_b_obj = os.path.join(work_dir, "tu2_b.o")
        app_b_order1 = os.path.join(work_dir, "app_b_order1.exe")
        app_b_order2 = os.path.join(work_dir, "app_b_order2.exe")

        with open(tu1_b_src, "w", encoding="utf-8") as f:
            f.write("""
#if defined(__clang__)
#define OBF_PROTECT(level) __attribute__((annotate("obf:" level)))
#else
#define OBF_PROTECT(level)
#endif
OBF_PROTECT("light")
const char* get_str_tu1(void) {
    return "SensitiveData12345";
}
""")

        with open(tu2_b_src, "w", encoding="utf-8") as f:
            f.write("""
extern "C" int printf(const char*, ...);
extern "C" int strcmp(const char*, const char*);
#if defined(__clang__)
#define OBF_PROTECT(level) __attribute__((annotate("obf:" level)))
#else
#define OBF_PROTECT(level)
#endif
const char* get_str_tu1(void);
OBF_PROTECT("light")
const char* get_str_tu2(void) {
    return "SensitiveData12345";
}
int main() {
    const char* s1 = get_str_tu1();
    const char* s2 = get_str_tu2();
    printf("CASE_B: TU1=%s | TU2=%s\\n", s1, s2);
    if (strcmp(s1, "SensitiveData12345") != 0 || strcmp(s2, "SensitiveData12345") != 0) {
        return 1;
    }
    return 0;
}
""")

        run_cmd(driver_cmd + ["-O1", "-fno-inline", f"-fpass-plugin={plugin}", "-c", tu1_b_src, "-o", tu1_b_obj], env=get_protected_env())
        run_cmd(driver_cmd + ["-O1", "-fno-inline", f"-fpass-plugin={plugin}", "-c", tu2_b_src, "-o", tu2_b_obj], env=get_protected_env())

        # Link order 1: tu2 first
        run_cmd(driver_cmd + lib_flags + [tu2_b_obj, tu1_b_obj, runtime, "-o", app_b_order1], env=get_unprotected_env())
        res3 = subprocess.run([app_b_order1], capture_output=True, text=True)
        log_lines.append(f"CASE_B_ORDER1: exit={res3.returncode} stdout={res3.stdout.strip()}")

        # Link order 2: tu1 first
        run_cmd(driver_cmd + lib_flags + [tu1_b_obj, tu2_b_obj, runtime, "-o", app_b_order2], env=get_unprotected_env())
        res4 = subprocess.run([app_b_order2], capture_output=True, text=True)
        log_lines.append(f"CASE_B_ORDER2: exit={res4.returncode} stdout={res4.stdout.strip()}")

        with open(out_base + ".log", "w", encoding="utf-8") as f:
            f.write("\n".join(log_lines) + "\n")

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
