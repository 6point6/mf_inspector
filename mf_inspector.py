import argparse
import os
import sys
import logging
import modules.file_inspector as file_inspector
from modules.file_inspector import EXE_KIND, DOC_KIND, PDF_KIND, SCRIPT_KIND, OTHER_KIND

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-o",
                        "--out",
                        type=str,
                        nargs='?',
                        default="results/results",
                        const="results/results",
                        help="output csv filename")
    parser.add_argument("-a",
                        "--anon",
                        help="anonymize stdout and csv output",
                        action='store_true')
    parser.add_argument("-v",
                        "--vtotal",
                        help="virus total api key file")
    parser.add_argument("-c",
                        "--clamav",
                        help="scan files with clamav",
                        action='store_true')
    parser.add_argument("-l",
                        "--log",
                        nargs='?',
                        default="INFO",
                        const="INFO",
                        help="set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
    required_args = parser.add_argument_group('required arguments')
    required_args.add_argument("-d",
                               "--dir",
                               type=str,
                               help="root directory to start analysis from",
                               required=True)

    args = parser.parse_args()

    numeric_level = getattr(logging, args.log.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % args.log)

    prog_name = os.path.splitext(os.path.basename(__file__))[0]

    logging.basicConfig(level=numeric_level,
                        handlers=[logging.FileHandler("results/{}.log".format(prog_name)),
                                  logging.StreamHandler(sys.stdout)]
                        ,format='%(asctime)s %(levelname)s - %(message)s')

    logging.info('##### LOG START - {} #####'.format(prog_name))

    # create a File obj which holds findings for each file inspected
    files_obj = file_inspector.Files()

    # inspect each file and store details in files_obj
    files_obj.create_entries(args)

    # write detailed inspection output to csv file
    files_obj.write_csv()

    # print malware score table for files with suspicious content
    files_obj.print_mal_score_table()

    logging.info('##### LOG END - {} #####'.format(os.path.basename(__file__)))
