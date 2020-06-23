
# see https://blog.didierstevens.com/programs/pdf-tools/
# https://blog.didierstevens.com/2008/04/29/pdf-let-me-count-the-ways/
# https://www.blog.pythonlibrary.org/2018/05/03/exporting-data-from-pdfs-with-python/
# https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/analyzing-pdf-malware-part-1/

from modules.pdfid.pdfid import LoadPlugins, PDFiD, cPDFiD, PDFiD2String

from PyPDF2 import PdfFileReader
import logging

# /OpenAction /AA specifies the script or action to run automatically.
# /Names /AcroForm /Action can also specify and launch scripts or actions.
# /JavaScript specifies JavaScript to run.
# /GoTo changes the view to a specified destination within the PDF or in another PDF file.
# /Launch a program or opens a document.
# /URI accesses a resource by its URL.
# /SubmitForm /GoToR can send data to URL.
# /RichMedia can be used to embed Flash in PDF.
# /ObjStm can hide objects inside an Object Stream.
# /JavaScript > /J#61vaScript Beware on obfuscation technique with hex codes
DANGEROUS_PDF_OBJECTS = ["/OpenAction", "/AA", "/Names", "/AcroForm", "/Action", "/JavaScript", "/GoTo", "/Launch", "/URI", "/SubmitForm", "/GoToR", "/RichMedia", "/ObjStm", "/EmbeddedFile"]

# removed "JS" because of false positives
BAD_PDF_OBJECTS = ["OpenAction", "AA", "JavaScript", "Launch"]

# principle function for instpecting a PDF
# returns dict containing details and mal_score
def inspect_pdf(file_path, filename) -> dict:
    try:
        return processFile(file_path, filename)
    except Exception as e:
        logging.warning("Failed to inspect pdf: {} - {}".format(filename, e))
        return


# Extract the document metadetails
# https://www.blog.pythonlibrary.org/2018/04/10/extracting-pdf-metadata-and-text-with-python/
# returns a str of metadata
def extract_pdf_metadata(filename) -> str:
    with open(filename, 'rb') as f:
        try:
            pdf = PdfFileReader(f)
            info = pdf.getDocumentInfo()
            #number_of_pages = pdf.getNumPages()
        
            return "Author={}; Title={}; Creator={}".format(info.author, info.title, info.creator)

        except Exception as e:
            logging.error("Failed to extract pdf metadata for: {} - {}".format(filename, e))
            return

# Use pdfid to inspect PDF content
# returns a dict of details
def processFile(file_path, filename) -> dict:
    details = "Contains "
    mal_score = 0 
    # code stolen from pdfid
    global plugins
    plugins = []
    LoadPlugins('', False)

    xmlDoc = PDFiD(file_path, allNames=False, extraData=True, disarm=False, force=False)    
    total_count = 0

    # TODO replace with e.g. dumppdf -a 2Fs11235-017-0334-z.pdf
    # iterate through the elements
    for node in xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes:
        # check if any were found
        if int(node.getAttribute('Count')) > 0:

            # if it's in the bad list
            if node.getAttribute('Name') in DANGEROUS_PDF_OBJECTS:
                name = node.getAttribute('Name')
            
                if name[:1] == "/":
                    name = name[1:]

                details += "{}, ".format(name)
                total_count += int(node.getAttribute('Count'))
                mal_score += 2

                # report immediately if either of these
                if name in BAD_PDF_OBJECTS:
                    mal_score += 2
                    logging.warn("Active \"%s\" content found in PDF \"%s\"" % (name,  filename))
        
    if total_count > 0:
        details += "({} instances in total)".format(total_count)
    else:
        details += "no dangerous artefacts"

    # report any entropy outside a stream
    if xmlDoc.documentElement.getAttribute('NonStreamEntropy') != '' and float(xmlDoc.documentElement.getAttribute('NonStreamEntropy')) > 0.0:
        details += ', Entropy outside streams: %s (%10s bytes)\n' % (xmlDoc.documentElement.getAttribute('NonStreamEntropy'), xmlDoc.documentElement.getAttribute('NonStreamCount'))

    # report data after the EOF
    if xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF') != '' and int(xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF')) > 0:
        details += ', {} bytes after EOF'.format(int(xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF')))

    return {'details':details,'mal_score':mal_score}
