import os
import pefile
import argparse

from pathlib import Path

dlls_whitelist = ["kernel32.dll",
                  "ntdll.dll",
                  "msvcrt.dll",
                  "winhttp.dll",
                  "advapi32.dll",
                  "gdi32.dll",
                  "rpcrt4.dll",
                  "shlwapi.dll",
                  "urlmon.dll",
                  "wininet.dll",
                  "ws2_32_.dll"]


def peexport(fn):
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    pe = pefile.PE(fn, fast_load=True)
    pe.parse_data_directories(directories=d)
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not e.name:
            continue
        yield e.name.decode()


def getfiles(path, whitelist=[]):
    # path = os.fsencode(path)
    for fn in os.listdir(path):
        if len(whitelist) and fn.lower() not in whitelist:
            continue
        fn = Path(path, fn)
        if fn.name.endswith(".dll"):
            yield fn


def format(fn: Path):
    dllname = fn.name.split('.')[:-1][0]
    for name in peexport(fn):
        print(f'{dllname},{name}')
        # print(f'{dllname}::{name}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="PE file or folder of DLL to list export for")
    parser.add_argument("-w", "--whitelist", action="store_true")
    args = parser.parse_args()

    file = Path(args.file)
    if file.is_dir():
        if not args.whitelist:
            dlls_whitelist = []
        [format(fn) for fn in getfiles(file, dlls_whitelist)]
    else:
        format(file)


if __name__ == "__main__":
    main()
