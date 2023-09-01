#!/usr/bin/env python3
import sys
import binascii
import argparse
import logging
from pathlib import Path
from datetime import datetime

import pefile
import magic


def res_print(entries, depth=0):
    for entry in entries:
        if hasattr(entry, 'directory'):
            print('\t'*depth, end='')
            timestamp = getattr(entry.directory, 'TimeDateStamp', 0)
            if timestamp:
                timestamp = datetime.fromtimestamp(timestamp)
            print(f'id:{entry.id} type: {pefile.RESOURCE_TYPE.get(entry.id)} '
                  'name: {entry.name} timestamp: {timestamp}')
            res_print(entry.directory.entries, depth+1)
        else:
            tabs = '\t'*depth
            print(f'{tabs}data size = {entry.data.struct.Size}')
            print(f'{tabs}data offset = {entry.data.struct.OffsetToData}')
            data = pe.get_data(entry.data.struct.OffsetToData,
                               entry.data.struct.Size)
            print(f'{tabs}data crc32 = {binascii.crc32(data):x}')
            print(f'{tabs}data magic = {magic.from_buffer(data)}')


def pe_list_resource(pe):
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return
    res_print(pe.DIRECTORY_ENTRY_RESOURCE.entries)


# @ TODO rewrite pe_dump so it can take an ID path and dump it
def pe_dump_resource(pe):
    e = pe.DIRECTORY_ENTRY_RESOURCE.entries
    e = e[0].directory.entries[0].directory.entries[0]
    offset = e.data.struct.OffsetToData
    size = e.data.struct.Size
    data = pe.get_data(offset, size)
    sys.stdout.buffer.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument('-v', '--verbose', action='count', default=0)
    # parser.add_argument('-d', '--dumps', action='store_true')
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(args.verbose, len(levels) - 1)]
    logging.basicConfig(level=level)

    pe = pefile.PE(args.file)
    if args.dumps:
        pe_dump_resource(pe)
    else:
        pe_list_resource(pe)
