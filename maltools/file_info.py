#!/usr/bin/env python3
import sys
import argparse
import hashlib
import time
import os
from collections import OrderedDict

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    sys.stderr.write(
        "Could not import 'pefile'. PE metadata won't be available\n")
    sys.stderr.write("Install: 'pip install pefile'\n")
    HAS_PEFILE = False

try:
    # import yara
    HAS_YARA = False
except ImportError:
    sys.stderr.write(
        "Could not import 'yara'. Yara rules won't be available\n")
    sys.stderr.write("Install: 'pip install yara-python'\n")
    HAS_YARA = False
except OSError:
    HAS_YARA = False
    sys.stderr.write("Install: 'yara library'\n")


try:
    import magic
    HAS_MAGIC = True
except ImportError:
    sys.stderr.write(
        "Could not import 'magic'. File magic won't be available\n")
    sys.stderr.write("Install: 'pip install python-magic'\n")
    HAS_MAGIC = False

try:
    import vt
    HAS_VT = True
except ImportError:
    sys.stderr.write(
        "Could not import 'vt-py'. VirusTotal module won't be available\n")
    sys.stderr.write("Install: 'pip install vt-py'\n")
    HAS_VT = False


def human_readable_size(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


yara_rules = {
    # https://github.com/x64dbg/yarasigs/blob/master/crypto_signatures.yara
    'crypto': './crypto_signatures.yara',
    'case': './case.yara',
}

VT_API_KEY = os.environ.get('VT_API_KEY', None)


class FileInfo:
    def __init__(self, file_path):
        self.__pe = None
        self.filename = os.path.basename(file_path)
        self.file_path = file_path

        fp = open(self.file_path, 'rb')
        self.__file_data = fp.read()

        self.timestamps = {}
        self.hashs = OrderedDict({})
        self.pe_info = {}
        self.size = len(self.__file_data)
        self.size_human = human_readable_size(self.size)
        self.yara_matches = OrderedDict()
        self.vt_report = None

        if HAS_MAGIC:
            self.file_magic = magic.from_buffer(self.__file_data)

        self.__hashsum()
        if HAS_PEFILE and self.__file_data[:2] == b"MZ":
            try:
                self.__pe = pefile.PE(data=self.__file_data, fast_load=True)
                self.__pe_timestamp()
                self.__pe_advance()
            except pefile.PEFormatError:
                sys.stderr.write("failed to parse PE\n")

        if HAS_YARA:
            for k, v in yara_rules.items():
                try:
                    rules = yara.compile(filepath=v)  # noqa: F821
                    self.yara_matches[k] = rules.match(data=self.__file_data)  # noqa: E501
                except Exception:
                    pass

        if HAS_VT and VT_API_KEY:
            vt_client = vt.Client(VT_API_KEY)
            try:
                self.vt_report = vt_client.get_object(f'/files/{self.hashs["sha256"]}')
            except vt.error.APIError:
                pass
            vt_client.close()

    def __is_pe(self):
        # return self.__file_data[:2] == b"MZ"
        return self.__pe is not None

    def __hashsum(self):
        fct = OrderedDict(
            {'md5': hashlib.md5, 'sha1': hashlib.sha1, 'sha256': hashlib.sha256})
        for k, v in fct.items():
            m = v()
            m.update(self.__file_data)
            self.hashs[k] = m.hexdigest()

    def __pe_timestamp(self):
        entry = {}
        entry['epoch'] = time.gmtime(self.__pe.FILE_HEADER.TimeDateStamp)
        entry['timestamp'] = time.strftime(
            '%Y-%m-%d %H:%M:%S %Z', entry['epoch'])
        self.timestamps['pe_file_header'] = entry

        image_flags = pefile.retrieve_flags(
            pefile.IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')

        flags = []
        for flag in sorted(image_flags):
            if getattr(self.__pe.FILE_HEADER, flag[0]):
                flags.append(flag[0])
        flags_str = ', '.join(flags)
        self.pe_info['image_flags'] = flags_str

    def __pe_advance(self):
        # We fast load the PE so we need to parse the directories
        d = [pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
             pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
             pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
             pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS']]
        self.__pe.parse_data_directories(directories=d)

        if hasattr(self.__pe, "DIRECTORY_ENTRY_EXPORT"):
            self.pe_exports = [[e.name, e.address]
                               for e in
                               self.__pe.DIRECTORY_ENTRY_EXPORT.symbols]

        if hasattr(self.__pe, "DIRECTORY_ENTRY_IMPORT"):
            self.pe_imports = {
                lib.dll: [[imp.name, imp.ordinal] for imp in lib.imports]
                for lib in self.__pe.DIRECTORY_ENTRY_IMPORT}

        self.pe_sections = [{'name': x.Name.decode(),
                             'va': x.VirtualAddress, 'va_size': x.Misc_VirtualSize,
                             'raw_size': x.SizeOfRawData, 'md5': x.get_hash_md5(),
                             'entropy': x.get_entropy()}
                            for x in self.__pe.sections]
        self.hashs['imphash'] = self.__pe.get_imphash()

    def __str__(self):
        line_tpl = "%-12s : %s\n"

        out = '## %s\n' % (self.filename)
        out += line_tpl % ("file size",
                           "%d (%s)" % (self.size, self.size_human))

        if HAS_MAGIC:
            out += line_tpl % ('file magic', self.file_magic)

        for k, v in self.hashs.items():
            out += line_tpl % (k, v)

        if self.__is_pe() and HAS_PEFILE:
            out += line_tpl % ('pe flag', self.pe_info['image_flags'], )
            out += line_tpl % ('pe date',
                               self.timestamps['pe_file_header']['timestamp'], )
            for x in self.pe_sections:
                s = "{name:s} 0x{va:08x} 0x{va_size:08x} 0x{raw_size:08x} {md5:s} {entropy:f}".format(  # noqa: E501
                    **x)
                out += line_tpl % ('pe section', s)

        if HAS_YARA and len(self.yara_matches) > 0:
            v = ", ".join([x.rule for x in self.yara_matches['crypto']])
            out += line_tpl % ("yara crypto", v)
            v = ", ".join([x.rule for x in self.yara_matches['case']])
            out += line_tpl % ("yara case", v)

        if HAS_VT and self.vt_report:
            total_avs = sum([v for _, v in self.vt_report.last_analysis_stats.items()])
            v = "detection %d/%d" % (self.vt_report.last_analysis_stats['malicious'],
                                     total_avs)
            out += line_tpl % ("VT ratio", v)
            out += line_tpl % ("VT names", ', '.join(self.vt_report.names))
            out += line_tpl % ("VT times_submitted", self.vt_report.times_submitted)
            out += line_tpl % ("VT unique_sources", self.vt_report.unique_sources)
            out += line_tpl % ("VT first_seen", self.vt_report.first_submission_date)
            out += line_tpl % ("VT last_seen", self.vt_report.last_submission_date)
            out += line_tpl % ("VT last_scan", self.vt_report.last_analysis_date)
            v = "[link](%s)" % (f'https://www.virustotal.com/gui/file/{self.vt_report.sha256}')
            out += line_tpl % ("VT link", v)

            av_wanted = ['Kaspersky', 'F-Secure', 'Comodo', 'Sophos',
                         'TrendMicro', 'Symantec', 'McAfee', 'Microsoft', 'ESET-NOD32']

            for k, v in self.vt_report.last_analysis_results.items():
                if v['result'] and k in av_wanted:
                    out += line_tpl % ("VT/%s" % (k,), v['result'])

        return out

    def markdown(self):
        line_tpl = "| %-12s | %s |\n"

        out = "| | **%s** |\n" % (self.filename)
        out += "|---|:--|\n"
        out += line_tpl % ("file size",
                           "%d (%s)" % (self.size, self.size_human))

        if HAS_MAGIC:
            out += line_tpl % ('file magic', self.file_magic)

        for k, v in self.hashs.items():
            out += line_tpl % (k, v)

        if self.__is_pe() and HAS_PEFILE:
            # out += line_tpl % ('pe flag', self.pe_info['image_flags'], )
            out += line_tpl % ('PE date',
                               self.timestamps['pe_file_header']['timestamp'], )

        if HAS_YARA and len(self.yara_matches) > 0:
            v = ", ".join([x.rule for x in self.yara_matches['crypto']])
            out += line_tpl % ("yara crypto", v)
            v = ", ".join([x.rule for x in self.yara_matches['case']])
            out += line_tpl % ("yara case", v)

        if HAS_VT and self.vt_report:
            total_avs = sum([v for _, v in self.vt_report.last_analysis_stats.items()])
            v = "detection %d/%d" % (self.vt_report.last_analysis_stats['malicious'],
                                     total_avs)
            out += line_tpl % ("VT ratio", v)
            out += line_tpl % ("VT names", ', '.join(self.vt_report.names))
            out += line_tpl % ("VT times_submitted", self.vt_report.times_submitted)
            out += line_tpl % ("VT unique_sources", self.vt_report.unique_sources)
            out += line_tpl % ("VT first_seen", self.vt_report.first_submission_date)
            out += line_tpl % ("VT last_seen", self.vt_report.last_submission_date)
            out += line_tpl % ("VT last_scan", self.vt_report.last_analysis_date)
            v = "[link](%s)" % (f'https://www.virustotal.com/gui/file/{self.vt_report.sha256}')
            out += line_tpl % ("VT link", v)

            av_wanted = ['Kaspersky', 'F-Secure', 'Comodo', 'Sophos',
                         'TrendMicro', 'Symantec', 'McAfee', 'Microsoft', 'ESET-NOD32']

            for k, v in self.vt_report.last_analysis_results.items():
                if v['result'] and k in av_wanted:
                    out += line_tpl % ("VT/%s" % (k,), v['result'])

        return out


def main():
    parser = argparse.ArgumentParser(
        description='Generate Markdown file info table')
    parser.add_argument('files', metavar='f', nargs='+',
                        help='files to parse')
    parser.add_argument('-m', '--markdown', action='store_true',
                        help='print in markdown')
    parser.add_argument('-vt', '--virustotal', action='store_true',
                        help='enable VT query (no upload)')

    args = parser.parse_args()
    for f in args.files:
        info = FileInfo(f)
        if args.markdown:
            print(info.markdown())
        else:
            print(info)


if __name__ == "__main__":
    main()
