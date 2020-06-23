#!/usr/bin/env python
# -*- coding: utf-8 -*-

from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
import olefile
import logging
import openxmllib

AUTHOR = "Author: "
TITLE = "Title: "
LAST_SAVED_BY = "Last saved by: "
CREATE_TIME = "Created: "
MODIFIED_TIME = "Modified: "
NA = "N/A"
ENCODING = "ascii"
TIME_FORMAT = "%m/%d/%Y, %H:%M:%S"

# runs functions for extracting ole or openxml metadata
# returns a str of metadata
def extract_doc_metadata(doc_path) -> str:
    try:
        if olefile.isOleFile(doc_path):
            return extract_ole_metadata(doc_path)

        else:
            return extract_openxml_metadata(doc_path)
    except Exception as e:
        logging.error("Failed to extract document metadata for: {}".format(doc_path))
        return 

# extracts metadata for openxml files
# returns a str of metadata
def extract_openxml_metadata(doc_path) -> str:
    openxml = openxmllib.openXmlDocument(path=doc_path)

    metadata = ""
    if "creator" in openxml.coreProperties:
        value  = openxml.coreProperties.get("creator")
        if value:
            metadata += AUTHOR + value + "\n"
        else:
            metadata += AUTHOR + NA + "\n"

    if "title" in openxml.coreProperties:
        value = openxml.coreProperties.get("title")
        if value:
            metadata += TITLE + value + "\n"
        else:
            metadata += TITLE + NA + "\n"
 
    if "lastModifiedBy" in openxml.coreProperties:
        value = openxml.coreProperties.get("lastModifiedBy")
        if value:
            metadata += LAST_SAVED_BY + value + "\n"
        else:
            metadata += LAST_SAVED_BY + NA + "\n"
 
    if "created" in openxml.coreProperties:
        value = openxml.coreProperties.get("created")
        if value:
            metadata += CREATE_TIME + value + "\n"
        else:
            metadata += CREATE_TIME + NA + "\n"  

    if "modified" in openxml.coreProperties:
        value = openxml.coreProperties.get("modified")
        if value:
            metadata += MODIFIED_TIME + value + "\n"
        else:
            metadata += MODIFIED_TIME + NA + "\n"  

    return metadata

# extracts metadata for ole files
# returns a str of metadata
def extract_ole_metadata(doc_path) -> str:
    metadata = ""

    ole = olefile.OleFileIO(doc_path)

    olemeta = ole.get_metadata()

    value = getattr(olemeta, "author").decode(ENCODING)
    if value:
        metadata += AUTHOR + value + "\n"
    else:
        metadata += AUTHOR + NA + "\n"

    value = getattr(olemeta, "title").decode(ENCODING)
    if value:
        metadata += TITLE + value + "\n"
    else:
        metadata += TITLE + NA + "\n"

    value = getattr(olemeta, "last_saved_by").decode(ENCODING)
    if value:
        metadata += LAST_SAVED_BY + value + "\n"
    else:
        metadata += LAST_SAVED_BY + NA + "\n"

    value = getattr(olemeta, "create_time").strftime(TIME_FORMAT)
    if value:
        metadata += CREATE_TIME + value + "\n"
    else:
        metadata += CREATE_TIME + NA + "\n"

    value = getattr(olemeta, "last_saved_time").strftime(TIME_FORMAT)
    if value:
        metadata += MODIFIED_TIME + value + "\n"
    else:
        metadata += MODIFIED_TIME + NA + "\n"

    return metadata    

# inspects openxml and ole files for macros
# returns a dict of details and mal_score
def check_macros(doc_path, filename) -> dict:
    try:

        vbaparser = VBA_Parser(doc_path)

        if not vbaparser.detect_vba_macros():
            return ""
        
        logging.warning("VBA macros in \"%s\"" % filename)
        
        details = "Macro Results\n"
        suspicious_count = 0
        suspicious_list = []
        ioc_list = []
        ioc_count = 0    
        mal_score = 0

        logging.disable(level=logging.CRITICAL)
        results = vbaparser.analyze_macros()
        logging.disable(level=logging.NOTSET)

        for kw_type, keyword, description in results:

            details += "\t - " + kw_type + " - (" + keyword + ") - " + description + "\n"

            if kw_type.lower() == "suspicious":
                suspicious_count += 1
                suspicious_list.append(keyword)

            elif kw_type.lower() == "ioc":
                ioc_count += 1
                ioc_list.append(keyword)

        if suspicious_count != 0:
            logging.warning("Found %d suspicious items in \"%s\"" %
                            (suspicious_count, filename))
            mal_score += suspicious_count

        if ioc_count != 0:
            logging.warning("Found %d IOCs: %s, in \"%s\"" % (ioc_count,
                                                             ioc_list, filename))
            mal_score += ioc_count * 2
        
        return {'details':details,'mal_score':mal_score}

    except Exception as e:
        logging.error("Failed to parse macros for: {} - {}".format(filename, e))
        return
