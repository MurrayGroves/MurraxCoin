# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(['wallet.py'],
             pathex=['/home/murrax2/Documents/Coad/MurraxCoin/Wallet'],
             binaries=[],
             datas=[],
             hiddenimports=['websockets','aioconsole','pycryptodome','pynacl','base64','zlib','websockets.legacy','websockets.legacy.client'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='wallet',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True )
