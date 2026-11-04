"""Portable V9 installer; hardware is accessed only after a menu selection."""
import argparse, ctypes, hashlib, json, os, runpy, shutil, subprocess, sys, time, traceback
from ctypes import wintypes as W
from pathlib import Path
HERE = Path(__file__).resolve().parent
PAYLOAD = Path(getattr(sys, "_MEIPASS", HERE)) / "flasher_payload"
HOME = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else HERE
V9 = "reverse/UpdateT48_SOFTWARE_CRYPTO_PINDETECT_V9_UNTESTED.dat"
STOCK = "OR/UpdateT48.dat"
HASHES = {V9: "e31497085d4aff09d6a0a6407a32cc84c6f2ab401f031a55cf2649c3c64e1bf5",
          STOCK: "8e18ea5d769bb7375620a84f8c2a8269cd7ef485550cee0325819832e45ff437"}

def check_payload():
    manifest = json.loads((PAYLOAD / "manifest.json").read_text(encoding="utf-8"))
    for name, digest in manifest.items():
        if hashlib.sha256((PAYLOAD / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError("Повреждён файл комплекта: " + name)
    sys.path.insert(0, str(PAYLOAD / "emmc_continue"))
    from decode_t48_firmware import decode
    key = (PAYLOAD / "emmc_continue/t48_key.dat").read_bytes()
    for name, digest in HASHES.items():
        if manifest.get(name) != digest:
            raise RuntimeError("Неожиданный образ: " + name)
        _, meta = decode((PAYLOAD / name).read_bytes(), key)
        if not meta["all_block_crcs_valid"]:
            raise RuntimeError("Ошибка CRC: " + name)
    return manifest

def save(path, value):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    os.replace(temp, path)

def workflow(work, name, runner=None):
    report = {"firmware": name, "sha256": HASHES[name], "status": "NOT_CONFIRMED"}
    path = work / "flash_report.json"
    save(path, report)
    env = os.environ.copy()
    env["T48_TOOL_RUNROOT"] = str(work)
    command = [sys.executable]
    if not getattr(sys, "frozen", False):
        command.append(str(HERE / "flasher.py"))
    command += ["--install-worker", str(work / name), HASHES[name]]
    try:
        result = (runner or subprocess.run)(command, env=env)
        if result.returncode:
            raise RuntimeError("Перепрошивка не подтверждена. Проверьте окно Xgpro и журнал.")
        report["status"] = "FLASH_SUCCESS"
    except BaseException as exc:
        report["error"] = str(exc)
        raise
    finally:
        save(path, report)
    return report

def self_test():
    import tempfile
    from types import SimpleNamespace
    manifest = check_payload()
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        for name in HASHES:
            calls = []
            def fake(command, env):
                calls.append((command, env))
                return SimpleNamespace(returncode=0)
            assert workflow(work, name, fake)["status"] == "FLASH_SUCCESS"
            assert calls[0][0][-2:] == [str(work / name), HASHES[name]]
            assert calls[0][1]["T48_TOOL_RUNROOT"] == str(work)
        try:
            workflow(work, V9, lambda *a, **k: SimpleNamespace(returncode=1))
        except RuntimeError:
            pass
        else:
            raise AssertionError("Failed flash accepted")
        assert json.loads((work / "flash_report.json").read_text())["status"] == "NOT_CONFIRMED"
    print("SELF_TEST_PASS: payload hashes/CRCs; V9/stock routing; failure reporting; no hardware access")
    return 0

def main():
    parser = argparse.ArgumentParser(description="T48 V9: установка или возврат стока")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--install-worker", nargs=2, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.install_worker:
        # Restrict the private entry point to a packaged, pinned image.
        candidate, digest = args.install_worker
        check_payload()
        if digest not in HASHES.values() or hashlib.sha256(Path(candidate).read_bytes()).hexdigest() != digest:
            raise RuntimeError("Образ не соответствует комплекту")
        sys.argv = [str(PAYLOAD / "reverse/install_worker.py"), candidate, digest]
        runpy.run_path(sys.argv[0], run_name="__main__")
        return 0
    if args.self_test:
        return self_test()
    manifest = check_payload()
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateMutexW.argtypes = [ctypes.c_void_p, W.BOOL, W.LPCWSTR]
    k.CreateMutexW.restype = W.HANDLE
    handle = k.CreateMutexW(None, False, "Local\\T48CryptoDumpWorkflow")
    if not handle or ctypes.get_last_error() == 183:
        if handle:
            k.CloseHandle.argtypes = [W.HANDLE]
            k.CloseHandle(handle)
        raise RuntimeError("Другая утилита T48 уже запущена")
    try:
        print("T48 V9 — прошивальщик eMMC + TSOP48 NAND")
        print("Закройте Xgpro и другие программы T48. Снимите целевую микросхему.")
        print("V9 аппаратно не проверена. TSOP56 требует оригинальный крипточип.")
        print("1 — установить V9; 2 — вернуть оригинальную прошивку; Q — выйти")
        choice = input("Выбор: ").strip().lower()
        if choice not in ("1", "2"):
            return 0
        name = V9 if choice == "1" else STOCK
        work = HOME / ("t48_flash_" + time.strftime("%Y%m%d_%H%M%S") + "_" + str(time.time_ns() % 1000000))
        work.mkdir()
        for item in manifest:
            if item.startswith(("OR/", "reverse/")):
                target = work / item
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(PAYLOAD / item, target)
        short = ctypes.create_unicode_buffer(32768)
        k.GetShortPathNameW.argtypes = [W.LPCWSTR, W.LPWSTR, W.DWORD]
        k.GetShortPathNameW.restype = W.DWORD
        if k.GetShortPathNameW(str(work), short, len(short)):
            work = Path(short.value)
        if len(str(work / "run_000000" / "Xgpro.exe")) > 110:
            raise RuntimeError("Слишком длинный путь. Переместите EXE в короткую папку и повторите запуск.")
        print("Журналы:", work, flush=True)
        print("Во время записи не отключайте питание и USB.", flush=True)
        workflow(work, name)
        print("Перепрошивка подтверждена Xgpro.")
        input("Enter — закрыть окно")
        return 0
    finally:
        k.CloseHandle.argtypes = [W.HANDLE]
        k.CloseHandle(handle)

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        if len(sys.argv) == 1:
            input("Ошибка. Проверьте окно Xgpro. Enter — закрыть")
        raise SystemExit(1)
