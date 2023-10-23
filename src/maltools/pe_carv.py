import logging
import argparse
import re
from pathlib import Path

import pefile


def pe_get_ext(pe):
    if pe.is_dll():
        return 'dll'
    if pe.is_exe():
        return 'exe'
    if pe.is_driver():
        return 'sys'
    else:
        return 'bin'


def carv_pe(data: bytes):
    i = 1
    # For each address that contains MZ
    for m in re.finditer(b'\x4d\x5a', data):
        try:
            pe = pefile.PE(data=data[m.start():])
        except Exception:
            logging.info(f"failed to parse PE at {m.start():x}")
            continue
        logging.info(f"found valid PE at {m.start():x}")
        pe.close()
        fn = f'{i}.{pe_get_ext(pe)}'
        open(fn, 'wb').write(pe.trim())
        i += 1

    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument('-v', '--verbose', action='count', default=0)
    # parser.add_argument('-d', '--dumps', action='store_true')
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(args.verbose, len(levels) - 1)]
    logging.basicConfig(level=level)

    # pe = pefile.PE(args.file)
    data = open(args.file, 'rb').read()
    carv_pe(data)


if __name__ == "__main__":
    main()
