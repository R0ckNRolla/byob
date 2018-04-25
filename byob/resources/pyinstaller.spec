# -*- mode: python -*-

block_cipher = pyi_crypto.PyiBlockCipher(key='[128_BIT_KEY]')


a = Analysis(['[PY_FILE]'],
             pathex=['[DIST_PATH]'],
             binaries=[],
             datas=[],
             hiddenimports=[HIDDEN_IMPORTS],
             hookspath=[],
             runtime_hooks=[],
             excludes=['site'],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='[NAME]',
          debug=False,
          strip=False,
          upx=False,
          runtime_tmpdir=None,
          console=False, icon='[ICON_PATH]')