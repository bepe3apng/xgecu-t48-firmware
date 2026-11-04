# XGecu T48 firmware V9

Experimental firmware patch.

## Ready-to-use files

- `reverse/software_crypto/dist/T48_V9_Flasher.exe`: install V9 or restore stock.
- `reverse/software_crypto/dist/README_RU.txt`: Russian instructions.
- `reverse/software_crypto/output/`: DAT, decoded BIN and verification report.
- `reverse/software_crypto/T48_V9_article.md` and `.txt`: Russian research article.

## Build

Windows, Python 3.11, PyInstaller and Capstone are required. From this directory:

```powershell
python -m pip install pyinstaller capstone
python -X utf8 reverse/software_crypto/build_v9.py
python -X utf8 reverse/software_crypto/build_flasher.py
```

The package preserves the original directory layout and includes the existing packaged installation worker. Building does not install firmware on the device.

## Scope

Synthetic E0 identity/status/flags for 15 selectors. TSOP56 still requires its real crypto chip. Pin Detect overrides internal indices 40/41/43 at two call sites. This is not complete ATSHA emulation.

## Distribution and licensing

This is a local collection, not a published release. Xgpro, its DLLs, stock firmware and firmware-derived images remain third-party materials. The bundled EXE and payload also contain those materials. A license for original project code does not grant distribution rights to them. Review redistribution permissions before publishing this entire folder. No new license has been assigned by this packaging step.

Adapter dumps and extracted authentication secrets are excluded. `emmc_continue/t48_key.dat` is the existing firmware-container codec dependency, not an extracted adapter read-key dump.
