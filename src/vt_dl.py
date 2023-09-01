#!/usr/bin/env python3
import vt
import os
import argparse
import logging

from pathlib import Path

VT_API_KEY = os.environ['VT_API_KEY']

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("hash")
    parser.add_argument('-v', '--verbose', action='count', default=0)
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(args.verbose, len(levels) - 1)]
    logging.basicConfig(level=level)

    fn = Path(args.hash)

    client = vt.Client(VT_API_KEY)
    try:
        with open(fn, 'wb') as f:
            client.download_file(args.hash, f)
            logging.info(f'file download to {fn}')
    except vt.error.APIError as ex:
        logging.error(ex.message)
        fn.unlink()
    client.close()
