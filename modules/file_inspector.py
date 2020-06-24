import magic
import csv
import os
import logging
import sys
import csv
import hashlib
import pyclamd
from tabulate import tabulate
import modules.pdf_inspector as pdf_inspector
import modules.doc_inspector as doc_inspector
import modules.virus_total as virus_total
from modules.pdf_inspector import inspect_pdf, extract_pdf_metadata
import time
import multiprocessing 


class HashFailed(Exception):
    pass

class CheckBinaryFailed(Exception):
    pass

# MIME File Magic for binary executables
BINARY_MAGICS = {
    "ELF": "7F454C46",
    "ELF2": "457F464C",
    "Mach-O 1": "CFFAEDFE",
    "Mach-O 1": "CFFAEDFE",
    "Mach-O 2": "FEEDFACE",
    "Mach-O 3": "FEEDFACF",
    "Mach-O 4": "CEFAEDFE",
    "Mach-O 5": "CAFEBABE",
    "DEX": "6465790A",
    "PE": "4D5A"
}

EXE_KIND = "exe"
DOC_KIND = "doc"
PDF_KIND = "pdf"
SCRIPT_KIND = "script"
OTHER_KIND = "other"

# list of valid extensions for files
PE_EXTENSIONS = [".acm", ".ax", ".cpl", ".dll", ".drv", ".efi", ".exe", ".mui", ".ocx", ".scr", ".sys", ".tsp"]
ELF_EXTENSIONS = [".axf", ".bin", ".elf", ".o", ".prx", ".puff", ".ko", ".mod" ,".so"]
MACH_O_EXTENSIONS = [".o", ".dylib", ".bundle"]
DOC_EXTENSIONS = [".doc", "dot", ".docx", ".docm", ".dotx", ".dotm", ".docb",
                  ".xls", ".xlt",".xla",".xlm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlam", ".xlsb",
                  ".ppt", ".pot", ".pps", ".ppa", ".pptx", ".potx", ".ppsx", ".ppam", ".pptm", ".potm", ".ppsm"]
PDF_EXTENSION = ".pdf"

# catergorisation mime types
FILE_KINDS = {
    EXE_KIND: [
        "application/x-dosexec", 
        "application/x-executable",
        "application/x-sharedlib", 
        "application/x-mach-binary"
    ],
    DOC_KIND: [
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document", 
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
        "application/vnd.ms-word.document.macroEnabled.12",
        "application/vnd.ms-word.template.macroEnabled.12",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        "application/vnd.ms-excel.template.macroEnabled.12",
        "application/vnd.ms-excel.addin.macroEnabled.12",
        "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.presentationml.template",
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
        "application/vnd.ms-powerpoint.addin.macroEnabled.12",
        "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
        "application/vnd.ms-powerpoint.template.macroEnabled.12"
        "application/vnd.ms-powerpoint.slideshow.macroEnabled.12"
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    ],
    PDF_KIND: ["application/pdf", 
               "application/x-pdf", 
               "application/x-bzpdf", 
               "application/x-gzpdf"
    ],
    SCRIPT_KIND: ["text/x-shellscript"],
}


# holds the following properties for a file:
#   fpath = filepath
#   fname = name of file (in anon mode it's the SHA256)
#   fkind = kind of file (e.g EXE/PDF/DOC/SCRIPT)
#   fhash = SHA256 hash of file
#   fphash = SHA256 hash of filepath
#   fmetadata = metadata extracted from file
#   fmime_type = file mime type
#   fdetails = details found in inspection
#   fmal_score = the higher the malicious score the more suspicious content found in file
#   fclamav_detect = true if clamav found a match
#   fvtotal_matches = number of virus total matches
#   valid_fmt_flag = internal flag set to False when file has an invalid format
class FileProperty:
    def __init__(self):
        self.fpath: str =  ""
        self.fname: str = ""
        self.fkind: str = ""
        self.fhash: str = ""
        self.fphash: str = ""
        self.fmetadata: str = ""
        self.fmime_type: str = ""
        self.fdetails: str = ""
        self.fmal_score: int = 0
        self.fclamav_detect: bool = False
        self.fvtotal_matches: str = "0"
        self.valid_fmt_flag: bool = True

    # check to see if the files format matches with it's mime type
    # returns a str of metadata of details
    def check_invalid_format(self, data) -> str:
        if self.valid_fmt_flag is True and data is None:
            logging.warning("Invalid file format for \"%s\" for mime type \"%s\"" % (self.fname, self.fmime_type))
            self.fdetails += "File format does not match mime type\n"
            self.fmal_score += 1
            self.valid_fmt_flag = False
            return ""
        elif data is None:
            return ""
        else:
            return data
        

    # check to see if the file extension matches with the file content
    # returns None
    def check_extension_vs_content(self) -> None:
        file_extension = self.get_file_extension(self.fpath)

        if self.fmime_type == "application/x-dosexec":
            if not file_extension:
                self.warn_no_extension(PE_EXTENSIONS)

            elif file_extension not in PE_EXTENSIONS:
                self.warn_invalid_extension(file_extension, PE_EXTENSIONS)
                
        elif self.fmime_type == "application/x-executable":
            if not file_extension:
                return
            
            elif file_extension not in ELF_EXTENSIONS:
                self.warn_invalid_extension(file_extension, ELF_EXTENSIONS)

        elif self.fmime_type == "application/x-mach-binary":
            if not file_extension:
                return

            if file_extension not in MACH_O_EXTENSIONS:
                self.warn_invalid_extension(file_extension, MACH_O_EXTENSIONS)

        elif self.fmime_type in FILE_KINDS[DOC_KIND]:
            if not file_extension:
                self.warn_no_extension(DOC_EXTENSIONS)
        
            elif file_extension not in DOC_EXTENSIONS:
                self.warn_invalid_extension(file_extension, DOC_EXTENSIONS)

        elif self.fmime_type == "application/pdf":
            if not file_extension:
                self.warn_no_extension(PDF_EXTENSION)

            elif file_extension != PDF_EXTENSION:
                self.warn_invalid_extension(file_extension, PDF_EXTENSION)

    # warn if no extension is found within file extension list for file kind
    # returns None
    def warn_no_extension(self, VALID_EXTENSIONS) -> None:
        logging.warning("The file \"%s\" of type \"%s\" has no extension" % (self.fname, self.fmime_type))
        logging.info("List of valid extensions for \"%s\": %s" %
                     (self.fname, VALID_EXTENSIONS)) 
        self.fdetails += "\nNo extension"
        self.fmal_score += 1

    # warn if the extension does not match the file mime type
    # returns None
    def warn_invalid_extension(self, invalid_extension, VALID_EXTENSIONS) -> None:
        logging.warning("The file \"%s\" of type \"%s\" has an invalid extension \"%s\"" % (self.fname, self.fmime_type, invalid_extension)) 
        logging.info("List of valid extensions for \"%s\": %s" %
                     (self.fname, VALID_EXTENSIONS)) 
        self.fdetails += "\nInvalid extension: \"" + invalid_extension + "\""
        self.fmal_score += 1

    # returns a str file extension
    @staticmethod
    def get_file_extension(file_path) -> str:
        file_extension = ""
        file_path_len = len(file_path)

        for i in range(file_path_len):
            word = file_path[file_path_len - i:]
            if word[:1] == ".":
                return word
        
        return file_extension

# The Files class deals with parsing each file found
# count = contains the total number of files found
# flist = contains a dictionary of {fpath:FileProperty} for each file
# args = contains a list of cmd args from argparse
class Files:
    def __init__(self):
        self.count: int = 0
        self.flist: dict = {}
        self.args = ()

    # populates the flist dictionary and inspects each file found
    # returns None
    def create_entries(self, args) -> None:
        self.args = args

        if not os.path.exists(self.args.dir):
            logging.error("Can't find root folder \"%s\"" % self.args.dir)

            raise FileNotFoundError

        logging.info("Walking filesystem found in \"%s\"" % self.args.dir)

        valid_file_paths = []

        for dir_path, subdirList, file_list in os.walk(self.args.dir):
            for file_name in file_list:
                file_path = os.path.join(dir_path, file_name)
                if os.path.getsize(file_path) > 0:
                    valid_file_paths.append(os.path.abspath(file_path))
        
        self.count = len(valid_file_paths)
        logging.info("Found %d files" % self.count)
       
        if self.args.clamav:
            try:
                cd = pyclamd.ClamdAgnostic()

                if cd.ping():
                    logging.info("ClamAV - Ping service success")

            except Exception as e:
                logging.error("ClamAV - Can't connect to service: %s" % (e))
                self.args.clamav = False

        with multiprocessing.Pool() as pool:
            fps = pool.map(self.create_default_fields, valid_file_paths)

        for fp in fps:
            fp.check_extension_vs_content()
            self.flist[fp.fpath] = fp
       
    # writes out a csv file containing information on files inspected 
    # returns None
    def write_csv(self) -> None:
        CSV_ROWS = ["path", "path SHA-256","file SHA-256", "file type", "metadata", "detail", "malicious score"]
 
        csv_filename = self.args.out + ".csv"
        csv_file = open(csv_filename, mode='w')
        csv_writer = csv.writer(csv_file,
                                delimiter=',',
                                quotechar='"',
                                quoting=csv.QUOTE_MINIMAL)

        csv_writer.writerow(CSV_ROWS)

        for entry in self.flist:
            fentry = self.flist[entry]
            csv_writer.writerow(
                [fentry.fname, fentry.fphash, fentry.fhash, fentry.fmime_type, fentry.fmetadata, fentry.fdetails, fentry.fmal_score])

        csv_file.close()
        
        logging.info("Wrote analysis details to: \"%s\"" % csv_filename)

        if self.args.anon:
            CSV_MAP_ROWS = ["path", "path SHA-256"]

            csv_map_filename = self.args.out + "-map" + ".csv"

            csv_map_file = open(csv_map_filename, mode='w')
            csv_map_writer = csv.writer(csv_map_file,
                                    delimiter=',',
                                    quotechar='"',
                                    quoting=csv.QUOTE_MINIMAL)
            
            csv_map_writer.writerow(CSV_MAP_ROWS)

            for entry in self.flist:
                fentry = self.flist[entry]
                csv_map_writer.writerow(
                    [fentry.fpath, fentry.fphash])

            csv_file.close()
            
            logging.info("Wrote filepath/hash map to: \"%s\"" % csv_map_filename)
    
    # returns a list of the file kind you specify, e.g (DOC_KIND)
    # returns None
    def get_file_kind_list(self, file_kind) -> None:
        file_paths = []

        for entry in self.flist:
            fentry = self.flist[entry]
            if file_kind == fentry.fkind:
                file_paths.append(fentry.fpath)
        
        return file_paths

    # prints out a formatted table containing a malicious score for each suspicious file
    # the higher the score, the more suspicious the file was deemed
    # returns None
    def print_mal_score_table(self) -> None:
        table = []

        headers = self.create_maltable_headers()

        for entry in self.flist:
            fentry = self.flist[entry]
            if fentry.fmal_score > 0:
                table.append(self.create_maltable_values(fentry))

        table.sort(key=self.get_last_key,reverse=True)
        logging.info("Printing malicious score table\n")
        logging.info("\n{}".format(tabulate(table, headers, tablefmt="grid")))


    # creates and populates default fields for FileProperty
    # returns FileProperty
    def create_default_fields(self, file_path) -> FileProperty:
        fp = FileProperty()

        fp.fpath = file_path

        try:
            fp.fhash = self.get_SHA256(file_path)
            hasher = hashlib.sha256()
            hasher.update(bytes(file_path,'utf-8'))
            fp.fphash = hasher.hexdigest()
        except Exception as e:
            logging.error("Failed to create SHA256 hash for {} - {}".format(file_path, e))

        fp.fmime_type = self.get_file_type(file_path)
        fp.fkind = self.get_file_kind(fp.fmime_type)
        
        if self.args.anon:
            fp.fname = fp.fphash
        else:
            fp.fname = file_path

        if fp.fmime_type in FILE_KINDS[EXE_KIND]:
            try:
                fp.fdetails += self.check_file_is_binary(file_path) 
            except Exception as e:
                logging.error("Failed to check if file is binary for {} - {}".format(file_path, e))
        
        elif fp.fmime_type in FILE_KINDS[PDF_KIND]:
            result = pdf_inspector.inspect_pdf(file_path, fp.fname)

            if result:
                fp.fdetails += fp.check_invalid_format(result['details'])
                fp.fmal_score += result['mal_score']
           
            if not self.args.anon:
                metadata = pdf_inspector.extract_pdf_metadata(file_path)
                fp.fmetadata += fp.check_invalid_format(metadata)

        elif fp.fmime_type in FILE_KINDS[DOC_KIND]:
            #if self.args.anon:
             #    logging.disable(level=logging.CRITICAL)

            result = doc_inspector.check_macros(file_path, fp.fname)
          
            #if self.args.anon:
             #   logging.disable(logging.NOTSET)

            if result:
                fp.fdetails +=  fp.check_invalid_format(result['details'])
                fp.fmal_score += result['mal_score']
            
            if not self.args.anon: 
                metadata = doc_inspector.extract_doc_metadata(file_path)
                fp.fmetadata += fp.check_invalid_format(metadata) 

        if self.args.clamav:
            try:
                cd = pyclamd.ClamdAgnostic()

                if cd.ping():
                    logging.debug("Scanning \"%s\" with %s" % (fp.fname,
                                                            cd.version().split()[0:2]))

                    scan_result = cd.scan_file(file_path)

                    if scan_result and scan_result.get(abs_path)[0] == "ERROR":
                        logging.error(scan_result)

                    elif scan_result:
                        f_result = "ClamAV: %s for %s" % (scan_result.get(abs_path), fp.fname)
                        fp.fmal_score += 50
                        fp.fdetails += "\n" + f_result
                        fp.fclamav_detect = True
                        logging.warning(f_result)

            except Exception as e:
                logging.error("%s")
            
        if (fp.fmal_score >= 10) and (self.args.vtotal):
            try:
                with open(self.args.vtotal, "r") as api_key_file:
                    api_key = api_key_file.readline().strip()
            except Exception as e:
                logging.error("Could not read vtotal api key file: {}\n\t- {}".format(self.args.vtotal, e))
                return fp

            if api_key:
                result = virus_total.check_hash(api_key, fp.fhash, fp.fname)
                if result:
                    fp.fdetails += result['details']
                    fp.fmal_score += result['mal_score']
                    fp.fvtotal_matches = result['vtotal_matches']

        return fp
   
    # creates headers for the malicious table depending on CLI options
    def create_maltable_headers(self) -> list:
        headers = ["File Path"]
       
        if self.args.clamav:
            headers.append("ClamAV Detected")

        if self.args.vtotal:
            headers.append("VTotal Matches")

        headers.append("Malicious Score")

        return headers
   
    # creates the values for the malicous table depending on CLI options
    def create_maltable_values(self, fentry) -> list:
        if self.args.anon:
            filename = fentry.fphash
        else: 
            filename = fentry.fpath

        column_values = [filename]

        if self.args.clamav:
            column_values.append(fentry.fclamav_detect)

        if self.args.vtotal:
            column_values.append(fentry.fvtotal_matches)

        column_values.append(fentry.fmal_score)

        return column_values

    # returns the last int item in a list
    @staticmethod
    def get_last_key(item) -> int:
        return item[len(item) - 1]

    # returns a str SHA256 hash of a file
    @staticmethod
    def get_SHA256(file_path) -> str:
        # get the file hash
        hasher = hashlib.sha256()

        with open(file_path, 'rb') as input_file:
            buffer = input_file.read()

        hasher.update(buffer)

        return hasher.hexdigest()


    # check the start of the file against the different file magics for binary files
    # returns a str of magic type
    @staticmethod
    def check_file_is_binary(file_name) -> str:
        # read first file bytes
        with open(file_name, "rb") as f:
            start_bytes = f.read(10)

        # check against all the file magics in the dict
        for key in BINARY_MAGICS:
            magic_bytes = bytes.fromhex(BINARY_MAGICS[key])
            if start_bytes[0:len(magic_bytes)] == magic_bytes:
                return key

        return ""


    # Get the file type by MIME type. Returns e.g.:
    # "application/pdf",
    # "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    # "application/x-dosexec"
    #  returns a str of mime type
    @staticmethod
    def get_file_type(file_name) -> str:
        with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
            file_type = m.id_filename(file_name)

            return file_type


    # Associates a mime types to a file kind listed in FILE_KINDS
    # returns a str of file kind
    @staticmethod
    def get_file_kind(file_type) -> str:
        for kind in FILE_KINDS:
            if file_type in FILE_KINDS[kind]:
                return kind
        
        return OTHER_KIND
