# Mass File Inspector

## About

`mf_inspector` is an open-source document static analysis tool written in Python. 

It was created to aid with the mass inspection and identification of malicious files in document stores. This came about as a direct requirement of an incident response job, when a customer suspected there may be malicious documents in a SharePoint system. So we decided to write a tool to help us find any malicious documents.

## Mf Inspector Brief Feature Overview

When run with a default configuration `mf_inspector` inspects all files contained in a folder and its subfolders. Each file's type is determined by its header magic and the type of inspection differs dependent upon this. For example, if the file is an Office document, the code will check for macros, and extract document metadata. If the file is a PDF, the code will look for potentially dangerous PDF objects such as embedded Javascript content.

Noteworthy findings are shown to the user through the Python logging module's WARNING level messages. More detailed results are also output to a CSV formatted file.

A more complete list of features is shown below:

* Inspection of Office documents; highlighting suspicious content and macros using the [oletools](https://github.com/decalage2/oletools/wiki) module
* Inspection of PDF documents; highlighting suspicious PDF objects (Javascript, OpenAction, Launch etc...)
* Highlights any executable files
* Optional lookup of file hashes with the [Virus Total API](https://developers.virustotal.com/)
* Optional scanning of files with [ClamAV](https://www.clamav.net/)
* Optional anonymous mode (prevents disclosure of sensitive information)
* Basic [multiprocessing](https://docs.python.org/3/library/multiprocessing.html) support allows for speedup on multi-core systems
* Malicious score system
* Analysis results saved to CSV formatted file

## Basic Setup And Usage

## Setup

`mf_inspector` requires python 3.6+ to run.

1) Clone the repository:

```
git clone https://github.com/6point6/mf_inspector
```

2) Change directory to the root of the repo:
```
`cd mf_inspector`
```

3) OPTIONAL: Create and activate a venv:
```
virtualenv venv
source venv/bin/activate
```

4) Install dependencies:
```
pip install -r requirements.txt
```

## Running the tool

To run `mf_inspector` with default settings, run the command: 

```
python mf_inspector.py -d /home/naka/work/mf_inspector/test_folder/`
```

*The `-d` flag is required to specify the root directory containing files for inspection.*

### Console/Log Output

`mf_inspector` uses the Python3 [logging](https://docs.python.org/3/library/logging.html) module for printing to stdout and creating log files. Using the `logging` module allows debug logs from 3rd party dependencies to be viewed by setting the logging level to DEBUG.

The log level can be specified by passing it to the `-l` flag. Below is a quick description of each log level along with the type of information produced by each level.

* **INFO** - Indicates informational messages, e.g how many files were found in total
* **WARNING** - Indicates that `mf_inspector` has found something interesting, e.g A word document contains suspicious macros
* **ERROR** - Indicates that an exception or error has occurred. e.g could not open file for reading
* **DEBUG** - Used for debugging purposes

Console output:

```
2020-06-11 09:32:03,705 INFO - ##### LOG START - mf_inspector #####
2020-06-11 09:32:03,705 INFO - Walking filesystem found in "/home/naka/work/mf_inspector/test_folder/"
2020-06-11 09:32:03,705 INFO - Found 18 files
2020-06-11 09:32:03,727 WARNING - VBA macros in "/home/naka/work/mf_inspector/test_folder/maldoc"
2020-06-11 09:32:03,740 INFO - Opening OLE file /home/naka/work/mf_inspector/test_folder/maldoc
2020-06-11 09:32:03,741 INFO - Check whether OLE file is PPT
2020-06-11 09:32:03,745 ERROR - Failed to extract pdf metadata for: /home/naka/work/mf_inspector/test_folder/pdf/bottle.pdf - EOF marker not found
2020-06-11 09:32:03,745 WARNING - Invalid file format for "/home/naka/work/mf_inspector/test_folder/pdf/bottle.pdf" for mime type "application/pdf"
2020-06-11 09:32:03,755 WARNING - Active "JavaScript" content found in PDF "/home/naka/work/mf_inspector/test_folder/pdf/bad.pdf"
2020-06-11 09:32:03,755 WARNING - Active "OpenAction" content found in PDF "/home/naka/work/mf_inspector/test_folder/pdf/bad.pdf"
2020-06-11 09:32:03,809 ERROR - Failed to parse macros for: /home/naka/work/mf_inspector/test_folder/doc/plant.docx - Error -3 while decompressing data: inval
id distance too far back
2020-06-11 09:32:03,810 ERROR - Failed to extract document metadata for: /home/naka/work/mf_inspector/test_folder/doc/plant.docx
2020-06-11 09:32:03,810 WARNING - Invalid file format for "/home/naka/work/mf_inspector/test_folder/doc/plant.docx" for mime type "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
2020-06-11 09:32:07,426 ERROR - Failed to extract pdf metadata for: /home/naka/work/mf_inspector/test_folder/pdf/encrypted.pdf - file has not been decrypted
2020-06-11 09:32:07,426 WARNING - Invalid file format for "/home/naka/work/mf_inspector/test_folder/pdf/encrypted.pdf" for mime type "application/pdf"
2020-06-11 09:32:07,965 WARNING - Found 18 suspicious items in "/home/naka/work/mf_inspector/test_folder/maldoc"
2020-06-11 09:32:07,965 WARNING - Found 4 IOCs: ['lewd.exe', 'MSVBVM60.DLL', 'user32.dll', 'VBA6.DLL'], in "/home/naka/work/mf_inspector/test_folder/maldoc"
```

### Malicious Score Table
`mf_inspector` gives each file a malicious score based on its findings. The more suspicious and/or malicious content it finds in a file, the higher the score. This score is printed in both an ASCII table at the end of console/log output, as well as the results CSV.

Below is an example of the malicious score table when the `-c` (ClamAV) and `-v` (Virus Total) flags are used:

```
+------------------------------------------------------------------------+-------------------+------------------+-------------------+
| File                                                                   | ClamAV Detected   | VTotal Matches   |   Malicious Score |
+========================================================================+===================+==================+===================+
| /home/naka/work/mf_inspector/test_folder/maldoc                        | True              | 43/60            |               249 |
+------------------------------------------------------------------------+-------------------+------------------+-------------------+
| /home/naka/work/mf_inspector/test_folder/pdf/bad.pdf                   | True              | 0                |                60 |
+------------------------------------------------------------------------+-------------------+------------------+-------------------+
| /home/naka/work/mf_inspector/test_folder/pdf/2Fs11235-017-0334-z.pdf   | False             | 0                |                 6 |
+------------------------------------------------------------------------+-------------------+------------------+-------------------+
| /home/naka/work/mf_inspector/test_folder/pdf/encrypted.pdf             | False             | 0                |                 3 |
+------------------------------------------------------------------------+-------------------+------------------+-------------------+
| /home/naka/work/mf_inspector/test_folder/info.sys                      | False             | 0                |                 1 |
+------------------------------------------------------------------------+-------------------+------------------+-------------------+
| /home/naka/work/mf_inspector/test_folder/pdf/bottle.pdf                | False             | 0                |                 1 |
+------------------------------------------------------------------------+-------------------+------------------+-------------------+
| /home/naka/work/mf_inspector/test_folder/bin/Vysor-win32-ia32.exe.file | False             | 0                |                 1 |
+------------------------------------------------------------------------+-------------------+------------------+-------------------+
| /home/naka/work/mf_inspector/test_folder/doc/plant.docx                | False             | 0                |                 1 |
+------------------------------------------------------------------------+-------------------+------------------+-------------------+
```

### CSV Output

`mf_inspector` also collects and outputs a summary of information in a CSV file, including:

* SHA-256 of the file
* File Mime Type
* File Metadata
* Findings (Macros, PDF Objects, Virus Scan Results...etc)
* Malicious Score

Below is an example of CSV output:

```csv
path,SHA-256,file type,metadata,detail,malicious score
/home/naka/work/mf_inspector/test_folder/maldoc,345b804a9416595840516674caaa65e65be57591d300beab2b6190298a9eac78,application/msword,"Author: Windows
Title: N/A
Last saved by: User
Created: 01/25/2016, 10:02:00
Modified: 01/25/2016, 11:17:00
","Macro Results
     - AutoExec - (AutoOpen) - Runs when the Word document is opened
     - Suspicious - (Open) - May open a file
     - Suspicious - (Write) - May write to a file (if combined with Open)
     - Suspicious - (Put) - May write to a file (if combined with Open)
     - Suspicious - (Binary) - May read or write a binary file (if combined with Open)
     - Suspicious - (Shell) - May run an executable file or a system command
     - Suspicious - (WScript.Shell) - May run an executable file or a system command
     - Suspicious - (Run) - May run an executable file or a system command
     - Suspicious - (Call) - May call a DLL using Excel 4 Macros (XLM/XLF)
     - Suspicious - (CreateObject) - May create an OLE object
     - Suspicious - (CallByName) - May attempt to obfuscate malicious function calls
     - Suspicious - (Chr) - May attempt to obfuscate specific strings (use option --deobf to deobfuscate)
     - Suspicious - (StrReverse) - May attempt to obfuscate specific strings (use option --deobf to deobfuscate)
     - Suspicious - (pUt) - May write to a file (if combined with Open) (obfuscation: Hex)
     - Suspicious - (run) - May run an executable file or a system command (obfuscation: Hex)
     - Suspicious - (VirtualProtect) - May inject code into another process (obfuscation: Hex)
     - Suspicious - (put) - May write to a file (if combined with Open) (obfuscation: Hex+StrReverse)
     - Suspicious - (Hex Strings) - Hex-encoded strings were detected, may be used to obfuscate strings (option --decode to see all)
     - Suspicious - (Base64 Strings) - Base64-encoded strings were detected, may be used to obfuscate strings (option --decode to see all)
     - IOC - (lewd.exe) - Executable file name
     - IOC - (MSVBVM60.DLL) - Executable file name (obfuscation: Hex)
     - IOC - (user32.dll) - Executable file name (obfuscation: Hex)
     - IOC - (VBA6.DLL) - Executable file name (obfuscation: Hex)

No extension",27
/home/naka/work/mf_inspector/test_folder/cav-linux_x64.deb,325b819b041a7b27026ba85f66ea808d0d11ad39d94bc13ae6d95802413495b6,application/vnd.debian.binary-package,,,0
/home/naka/work/mf_inspector/test_folder/info.sys,e13d65c0f1c5a37d1f5d854795ccdfec18c0b8de18a4b33a5df42a5197863071,application/x-executable,,"ELF
Invalid extension: "".sys""",1
/home/naka/work/mf_inspector/test_folder/pdf/2Fs11235-017-0334-z.pdf,4774a4ca47f89bb28cf5c19cf94c8b7868137a1d2cac27802ff385a25e566b24,application/pdf,"Author=B. B. Gupta; Title=Defending against phishing attacks: taxonomy of methods, current issues and future directions; Creator=Springer","Contains OpenAction, AcroForm, (2 instances in total)",6
```

### Anonymous Mode

An anonymous mode is available by specifying the `-a` flag. Anonymous mode prevents disclosure of sensitive information contained in file metadata and file names.

In anonymous mode, all filenames and file paths are replaced with the hash of their respective filepaths when printed to stdout, logging and the output CSV files. Additionally, metadata is not extracted from the files.

```
2020-06-10 15:18:01,702 INFO - ##### LOG START - mf_inspector #####
2020-06-10 15:18:01,702 INFO - Walking filesystem found in "/home/naka/work/mf_inspector/test_folder/"
2020-06-10 15:18:01,702 INFO - Found 18 files
2020-06-10 15:18:01,703 INFO - ClamAV - Ping service success
2020-06-10 15:18:01,752 WARNING - Active "JavaScript" content found in PDF "1aa5f45734e6200f21fa96dddd2df55f353d22e42c3b1d6653c0ddbfd5a76054"
2020-06-10 15:18:01,753 WARNING - Active "OpenAction" content found in PDF "1aa5f45734e6200f21fa96dddd2df55f353d22e42c3b1d6653c0ddbfd5a76054"
2020-06-10 15:18:01,758 WARNING - ClamAV: ('FOUND', 'Pdf.Downloader.DeepLink-6622195-0') for 1aa5f45734e6200f21fa96dddd2df55f353d22e42c3b1d6653c0ddbfd5a76054
2020-06-10 15:18:01,758 INFO - VTotal - Attempting virus total lookup of hash for: 1aa5f45734e6200f21fa96dddd2df55f353d22e42c3b1d6653c0ddbfd5a76054
2020-06-10 15:18:02,084 INFO - VTotal - No match found on hash for: 1aa5f45734e6200f21fa96dddd2df55f353d22e42c3b1d6653c0ddbfd5a76054
2020-06-10 15:18:06,121 WARNING - ClamAV: ('FOUND', 'Doc.Dropper.Fareit-572') for 345b804a9416595840516674caaa65e65be57591d300beab2b6190298a9eac78
2020-06-10 15:18:06,121 INFO - VTotal - Attempting virus total lookup of hash for: 345b804a9416595840516674caaa65e65be57591d300beab2b6190298a9eac78
2020-06-10 15:18:06,415 WARNING - VTotal - 43/60 (71 percent) of vendors identified the file as malicious
2020-06-10 15:18:08,343 WARNING - Active "OpenAction" content found in PDF "4774a4ca47f89bb28cf5c19cf94c8b7868137a1d2cac27802ff385a25e566b24"
```

A separate file, mapping a file to its hash is created when this mode is enabled. This allows the anonymized results to be passed to an analyst without disclosing sensitive information about the files and their environment.

Below is an example of a file mapping produced by anonymous mode:

```csv
path,SHA-256
/home/naka/work/mf_inspector/test_folder/maldoc,345b804a9416595840516674caaa65e65be57591d300beab2b6190298a9eac78
/home/naka/work/mf_inspector/test_folder/cav-linux_x64.deb,325b819b041a7b27026ba85f66ea808d0d11ad39d94bc13ae6d95802413495b6
/home/naka/work/mf_inspector/test_folder/info.sys,e13d65c0f1c5a37d1f5d854795ccdfec18c0b8de18a4b33a5df42a5197863071
```

### ClamAV And Virus Total

`mf_inspector` is also able to request that files be scanned by ClamAV if the the `-c` flag is supplied as a CLI parameter. This requires the `clamd` service to be installed and up and running.

If the `-v` flag is provided along with the a Virus Total API key, `mf_inspector` will send the SHA256 hashes of files deemed suspicious and report the percentage of matches, if any.

## Future

This is version 1.0 of the tool. Some of the planned features for version 2.0 are listed below:

* Support for scanning files on cloud drives (Google, Onedrive, etc...)
*
