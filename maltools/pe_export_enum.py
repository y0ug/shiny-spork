import os
import pefile
import argparse

from pathlib import Path

whitelist = ["kernel32.dll",
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


def pe_export(fn):
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    pe = pefile.PE(fn, fast_load=True)
    pe.parse_data_directories(directories=d)
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name:
            yield e.name.decode()


def getfiles(path, whitelist=[]):
    for fn in os.listdir(path):
        fn = Path(path, fn)
        if len(whitelist):
            if fn.name.lower() in whitelist:
                yield fn
        elif fn.name.endswith(".dll"):
            yield fn


def format(fn: Path):
    dllname = fn.stem
    for name in pe_export(fn):
        print(f'{dllname},{name}')


def main():
    global whitelist

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="PE file or folder of DLL to list export for")
    parser.add_argument("-w", "--whitelist", action="store_true")
    args = parser.parse_args()

    file = Path(args.file)
    if file.is_dir():
        if not args.whitelist:
            whitelist = []
        [format(fn) for fn in getfiles(file, whitelist)]
        # list(map(format, getfiles(file, whitelist)))
    else:
        format(file)


if __name__ == "__main__":
    main()
