# PyInstaller spec — bundles FastAPI backend + js-ast sidecar into one exe.
# Build: pip install pyinstaller && pyinstaller codeshield-backend.spec
# Output: dist/codeshield-backend(.exe) -> copy to extension/server/
# frozen layout keeps js-ast/ beside the exe via _MEIPASS fallback in main.
block_cipher = None

a = Analysis(
    ['app/main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('app', 'app'),
        ('js-ast/scan.js', 'js-ast'),
        ('js-ast/worker.js', 'js-ast'),
        ('js-ast/package.json', 'js-ast'),
        ('js-ast/node_modules/@babel', 'js-ast/node_modules/@babel'),
    ],
    hiddenimports=['uvicorn', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto',
                   'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.websockets',
                   'uvicorn.lifespan', 'fastapi', 'pydantic', 'httpx', 'psutil'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='codeshield-backend',
    debug=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
