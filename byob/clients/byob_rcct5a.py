import zlib,base64,marshal;exec marshal.loads(zlib.decompress(base64.b64decode('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')))