"""Package the existing tested worker and V9/stock; never invokes installation."""
from pathlib import Path
import ast, hashlib, json, shutil, subprocess, sys
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PAYLOAD = HERE / "flasher_payload"

def main():
    worker = ROOT / "reverse/t48_dump_tool/payload/reverse/install_worker.py"
    old_manifest = json.loads((worker.parents[1] / "manifest.json").read_text(encoding="utf-8"))
    assert hashlib.sha256(worker.read_bytes()).hexdigest() == old_manifest["reverse/install_worker.py"]
    source = worker.read_text(encoding="utf-8")
    compile(source, str(worker), "exec")
    assert "T48_TOOL_RUNROOT" in source and "flash_in_progress=True" in source
    assert "FLASH_SUCCESS" in source and "range(120)" in source
    assert "c['text']=='V .1.39'" not in source
    ready = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == "ready_t48")
    scope = {}
    exec(compile(ast.Module(body=[ready], type_ignores=[]), "<readiness>", "exec"), scope)
    assert scope["ready_t48"](bytes((1,1,31,7)))
    assert not scope["ready_t48"](bytes(4))
    files = {
        "reverse/install_worker.py": worker,
        "reverse/UpdateT48_SOFTWARE_CRYPTO_PINDETECT_V9_UNTESTED.dat": HERE / "output/UpdateT48_SOFTWARE_CRYPTO_PINDETECT_V9_UNTESTED.dat",
        "emmc_continue/decode_t48_firmware.py": ROOT / "emmc_continue/decode_t48_firmware.py",
        "emmc_continue/t48_key.dat": ROOT / "emmc_continue/t48_key.dat",
    }
    for p in (ROOT / "OR").iterdir():
        if p.is_file() and (p.suffix.lower() in {".ini", ".dll", ".lst", ".dat"} or p.name.lower() == "xgpro.exe"):
            files["OR/" + p.name] = p
    for name, original in files.items():
        target = PAYLOAD / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target)
    manifest = {name: hashlib.sha256((PAYLOAD / name).read_bytes()).hexdigest() for name in files}
    (PAYLOAD / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    subprocess.run([sys.executable, str(HERE / "flasher.py"), "--self-test"], check=True)
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console",
                    "--name", "T48_V9_Flasher", "--distpath", str(HERE / "dist"),
                    "--workpath", str(HERE / "flasher_build"), "--specpath", str(HERE),
                    "--add-data", str(PAYLOAD) + ";flasher_payload",
                    "--paths", str(PAYLOAD / "emmc_continue"),
                    "--hidden-import", "decode_t48_firmware", str(HERE / "flasher.py")],
                   check=True, cwd=HERE)
    exe = HERE / "dist/T48_V9_Flasher.exe"
    result = subprocess.run([str(exe), "--self-test"], capture_output=True, timeout=60)
    assert result.returncode == 0 and b"SELF_TEST_PASS" in result.stdout, (result.stdout, result.stderr)
    result = subprocess.run([str(exe), "--help"], capture_output=True, timeout=30)
    assert result.returncode == 0 and b"--self-test" in result.stdout
    report = {"exe": exe.name, "sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
              "bytes": exe.stat().st_size, "verification": "PASS: source and bundled EXE self-test, help startup, worker integrity/readiness 1.31",
              "firmware_sha256": manifest["reverse/UpdateT48_SOFTWARE_CRYPTO_PINDETECT_V9_UNTESTED.dat"],
              "hardware": "NOT RUN; no installation performed", "payload_files": len(manifest)}
    (HERE / "dist/verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    readme = """T48 V9 — прошивальщик eMMC + TSOP48 NAND

Запустите T48_V9_Flasher.exe из короткой доступной для записи папки.
Закройте Xgpro и остальные программы T48. Снимите целевую микросхему.
1 — установить общий образ V9; 2 — вернуть оригинальную прошивку; Q — выйти.
После установки V9 остаётся в приборе до следующей перепрошивки.
Не отключайте питание и USB до завершения записи.
Успех подтверждается сообщением Xgpro; журналы сохраняются рядом с EXE в t48_flash_*.
Если запись не подтверждена, проверьте оставленное окно Xgpro. Не запускайте вторую запись одновременно.
Для возврата стока запустите EXE и выберите 2.

Встроены Python, Xgpro 13.16, необходимые DLL, V9 и оригинальная прошивка.
USB-драйвер T48 должен быть заранее установлен в Windows.
Привязка к версии 1.39 снята; проверка готовности принимает 1.31.

V9 программно заменяет E0-проверку ID/статуса/флагов для 15 известных селекторов.
Это не полная эмуляция ATSHA. Для TSOP56 сохранена проверка настоящего крипточипа.
Pin Detect: локальная подмена результата чтения индексов 40/41/43 в обоих сканерах,
независимо от семейства. Прочие контакты проверяются штатно.
После Pin Detect выполняются исходные переключения и очистка GPIO.
Физические номера контактов для этих внутренних индексов не подтверждены.
Реальный крипточип или другая нагрузка могут влиять на электрическое состояние линии.

Сборка и программные проверки выполнены без записи в T48.
V9 и этот EXE на оборудовании ещё не проверены.
"""
    (HERE / "dist/README_RU.txt").write_text(readme, encoding="utf-8-sig", newline="\r\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
