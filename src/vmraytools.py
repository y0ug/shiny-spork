import sys
import argparse
import logging
import json
import io
import time
import os
from pathlib import Path

from vmray.rest_api import VMRayRESTAPI, VMRayRESTAPIError


class UnicodeFileType(argparse.FileType):
    def __init__(self, *args, **kwargs):
        argparse.FileType.__init__(self, *args, **kwargs)

    def __call__(self, string):
        try:
            sanitized_str = str(string)
        except UnicodeDecodeError:
            import ast
            sanitized_str = str(ast.literal_eval("u" + repr(string)))

        return argparse.FileType.__call__(self, sanitized_str)


class VMRayEx(Exception):
    pass


class VMRayExNotSupHash(VMRayEx):
    pass


class VMRayApi(object):
    def __init__(self, server: str, api_key: str, verify_ssl: bool = True):
        self.api = VMRayRESTAPI(server, api_key, verify_ssl)

    def _hash_type(self, val: str) -> str:
        if len(val) == 32:
            t = 'md5'
        elif len(val) == 44:
            t = 'sha1'
        elif len(val) == 64:
            t = 'sha256'
        else:
            raise VMRayExNotSupHash()
        return t

    def get_analysis(self, analysis_id: int) -> dict:
        logging.info(f"getting analysis {analysis_id}")
        data = self.api.call("GET", f"/rest/analysis/{analysis_id}")
        return data

    def get_sample(self, hash_value: str) -> dict:
        hash_type = self._hash_type(hash_value)
        logging.info(f"getting sample info for {hash_value} ({hash_type})")
        samples = self.api.call("GET", f"/rest/sample/{hash_type}/{hash_value}")
        return samples

    def download_sample(self, hash_value: str) -> io.BytesIO:
        samples = self.get_sample(hash_value)
        logging.info(f"downloading {samples[0]['sample_id']}")
        data = self.api.call(
            "GET", "/rest/sample/{}/file".format(samples[0]["sample_id"]), raw_data=True)
        return data

    def find_analysis(self, hash_value: str) -> list[dict]:
        samples = self.get_sample(hash_value)
        out = []
        for sample in samples:
            logging.info(f"finding analysis for {sample['sample_id']}")
            data = self.api.call("GET",
                                 f"/rest/analysis/sample/{sample['sample_id']}")
            out.append(data)
        return out

    def download_analysis(self, analysis_id: int, filename: None | str = None) -> io.BytesIO:
        if filename:
            logging.info(f"downloading {filename} for {analysis_id}")
            data = self.api.call("GET",
                                 f"/rest/analysis/{analysis_id}/archive/{filename}",
                                 raw_data=True)
        else:
            logging.info(f"downloading archive for {analysis_id}")
            data = self.api.call("GET",
                                 f"/rest/analysis/{analysis_id}/archive",
                                 raw_data=True)
        return data

    def submit(self, filename: Path, wait: bool = False, **kwargs) -> dict:
        params = kwargs
        params['sample_file'] = filename

        logging.info(f"submitting sample {filename}")
        data = self.api.call("POST", "/rest/sample/submit", params)
        logging.info(json.dumps(data, indent=2))

        if wait:
            self.wait_submission(data)
        return data

    def wait_submission(self, submit_data, sleep_interval=1):
        pending_submissions = list(submit_data["submissions"])
        while True:
            for submission in list(pending_submissions):
                try:
                    submission_data = self.api.call(
                        "GET", f"/rest/submission/{submission['submission_id']}")
                    if submission_data["submission_finished"]:
                        pending_submissions.remove(submission)
                    else:
                        break
                except VMRayRESTAPIError:
                    break

            if not pending_submissions:
                break

            time.sleep(sleep_interval)


class VMRayTools(object):
    vmray: VMRayApi
    _args: list[str]

    def __init__(self):
        cmds = [c for c in dir(self) if not c.startswith('_')]
        parser = argparse.ArgumentParser(
            description='Ticket/Report multitools for malware analysis')
        parser.add_argument('command', help='Subcommand to run', choices=cmds)
        args = parser.parse_args(sys.argv[1:2])

        server = os.environ['VMRAY_SERVER']
        api_key = os.environ['VMRAY_API_KEY']

        self.vmray = VMRayApi(server, api_key)

        self._argv = sys.argv[2:]

        getattr(self, args.command)()

    def _set_log_level(self, verbose: int):
        '''Set log level at 0 warning, 1 info, 2 debug'''
        levels = [logging.WARNING, logging.INFO, logging.DEBUG]
        level = levels[min(verbose, len(levels) - 1)]
        logging.basicConfig(level=level)

    def dl_sample(self):
        parser = argparse.ArgumentParser(description='Download a sample')
        parser.add_argument("hash", type=str, help="hash of the file")
        parser.add_argument('-v', '--verbose', action='count', default=0)

        args = parser.parse_args(self._argv)
        self._set_log_level(args.verbose)

        fp_sample = self.vmray.download_sample(args.hash)
        fn = f'{args.hash.lower()}.zip'
        logging.info(f"writing sample to {fn}")
        with io.open(fn, "wb") as fobj:
            fobj.write(fp_sample.read())

    def submit(self):
        parser = argparse.ArgumentParser(description='Submit sample')
        parser.add_argument("sample_file", type=UnicodeFileType("rb"), help="Path to sample file")
        parser.add_argument('-v', '--verbose', action='count', default=0)
        parser.add_argument("--archive_action", type=str, help="Archive action")
        parser.add_argument("--archive_password", type=str, help="Archive password")
        parser.add_argument("--cmd_line", type=str, help="Command line")
        parser.add_argument("--comment", type=str, help="Submission comment")
        parser.add_argument("--compound_sample", action="store_true",
                            help="Treat sample as compound sample")
        parser.add_argument("--no_compound_sample", action="store_false", dest="compound_sample",
                            help="Do not treat sample file as compound sample")
        parser.add_argument("--entry_point", type=str, help="Entry point")
        parser.add_argument("--jobrule_entries", type=str, help="Jobrule entries")
        parser.add_argument("--prescript_file", type=UnicodeFileType("rb"),
                            help="Path to prescript file")
        parser.add_argument("--reanalyze", action="store_true",
                            help="Reanalyze sample if analyses already exist")
        parser.add_argument("--no_reanalyze", action="store_false", dest="reanalyze",
                            help="Reanalyze sample if analyses already exist")
        parser.add_argument("--sample_type", type=str, help="Use this sample type")
        parser.add_argument("--shareable", action="store_true",
                            help="Sample can be shared with public")
        parser.add_argument("--not_shareable", action="store_false", dest="shareable",
                            help="Sample cannot be shared with public sample")
        parser.add_argument("--user_config", type=str, help="User configuration")
        parser.add_argument("--wait", "-w", action="store_true",
                            help="Wait for jobs to finish before exiting")

        args = parser.parse_args(self._argv)
        self._set_log_level(args.verbose)

        params = {}
        if args.archive_action is not None:
            params["archive_action"] = args.archive_action
        if args.archive_password is not None:
            params["archive_password"] = args.archive_password
        if args.cmd_line is not None:
            params["cmd_line"] = args.cmd_line
        if args.comment is not None:
            params["comment"] = args.comment
        if args.compound_sample is not None:
            params["compound_sample"] = args.compound_sample
        if args.entry_point is not None:
            params["entry_point"] = args.entry_point
        if args.jobrule_entries is not None:
            params["jobrule_entries"] = args.jobrule_entries
        if args.prescript_file is not None:
            params["prescript_file"] = args.prescript_file
        if args.reanalyze is not None:
            params["reanalyze"] = args.reanalyze
        if args.sample_type is not None:
            params["sample_type"] = args.sample_type
        if args.shareable is not None:
            params["shareable"] = args.shareable
        if args.user_config is not None:
            params["user_config"] = args.user_config

        # we are passing the sample_file in argument
        # if args.sample_file is not None:
        #     params["sample_file"] = args.sample_file
        self.vmray.submit(args.sample_file, **params)


def main():
    '''main function'''
    VMRayTools()


if __name__ == "__main__":
    main()
