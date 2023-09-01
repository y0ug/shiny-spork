from triage import Client
import logging
import argparse
import sys
import os
import json


def report_info(client: Client, sample_id: int):
    report = client.overview_report(sample_id)
    print(json.dumps(report, indent=2))


logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Triage tools')
    parser.add_argument('--max', default=10, type=int)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--query', help='example "family:emotet AND not tag:xlm AND from:2022-04"')
    group.add_argument('--samples', help='sample id', nargs='+')

    args = parser.parse_args(sys.argv[1:])

    api_url = os.environ['TRIAGE_API_URL']
    api_key = os.environ['TRIAGE_API_KEY']

    client = Client(api_key, root_url=api_url)
    if args.samples:
        for sample_id in args.samples:
            logging.info('fetching %s', sample_id)
            report_info(client, sample_id)
    else:
        for sample in client.search(args.query, max=args.max):
            logging.info('fetching %s submitted at %s', sample['id'], sample['submitted'])
            report_info(client, sample['id'])
            # pprint.pprint(report)
