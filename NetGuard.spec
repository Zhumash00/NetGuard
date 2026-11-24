# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules
from pathlib import Path
import PySide6

hiddenimports = []
hiddenimports += collect_submodules('scapy.layers')


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('layouts', 'layouts')],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'IPython', 'tkinter'],
    noarchive=False,
    optimize=0,
)
# Python can ship an older runtime than Qt. Load Qt's matching runtime first.
qt_directory = Path(PySide6.__file__).parent
for index, (destination, source, kind) in enumerate(a.binaries):
    if destination.lower() in ("vcruntime140.dll", "vcruntime140_1.dll") and (qt_directory / destination).exists():
        a.binaries[index] = (destination, str(qt_directory / destination), kind)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NetGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['build/NetGuard.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NetGuard',
)
