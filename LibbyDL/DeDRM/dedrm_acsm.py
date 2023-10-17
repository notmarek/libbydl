import io
import sys
import zipfile

from lxml import etree

from LibbyDL.DeDRM.ineptepub import decryptBook
from LibbyDL.DeDRM.libadobe import sendHTTPRequest_DL2FILE
from LibbyDL.DeDRM.libadobeFulfill import buildRights, fulfill
from loguru import logger

KEY_FOLDER = "./keys/"
DECRYPTION_KEY = f"{KEY_FOLDER}decryption.der"


def download(replyData):
    adobe_fulfill_response = etree.fromstring(replyData)
    NSMAP = {"adept": "http://ns.adobe.com/adept"}
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    adDC = lambda tag: '{%s}%s' % ('http://purl.org/dc/elements/1.1/', tag)
    download_url = adobe_fulfill_response.find(
        "./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("src"))).text
    resource_id = adobe_fulfill_response.find(
        "./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("resource"))).text
    license_token_node = adobe_fulfill_response.find(
        "./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken")))
    rights_xml_str = buildRights(license_token_node)
    if (rights_xml_str is None):
        return (False, None, None)
    book_name = None
    try:
        metadata_node = adobe_fulfill_response.find(
            "./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("metadata")))
        book_name = metadata_node.find("./%s" % (adDC("title"))).text
        author = metadata_node.find("./%s" % (adDC("creator"))).text
        book_name = f"{author} - {book_name}"
    except:
        book_name = "Book"
    temp_file = io.BytesIO()
    ret = sendHTTPRequest_DL2FILE(download_url, temp_file)
    if (ret != 200):
        return (False, None, None)
    zf = zipfile.ZipFile(temp_file, "a")
    zf.writestr("META-INF/rights.xml", rights_xml_str)
    return (True, book_name, temp_file)





def dedrm(acsm_file, out="./"):
    key = open(DECRYPTION_KEY, "rb").read()
    success, replyData = fulfill(acsm_file)  # acquiring the acsm file can be done in memory :)
    if (success is False):
        logger.error("Hey, that didn't work!")
        logger.error(replyData)
    else:
        acsm_file = acsm_file if type(acsm_file) is str else "inmemory"
        logger.debug("Downloading book '" + acsm_file + "' ...")
        success, filename, f = download(replyData)
        if success != False:
            logger.info(f"Book downloaded - {filename}.")
            res = decryptBook(key, f, out + filename + ".epub", "BytesIO object")
            if res == 0:
                logger.info("Book decrypted.")


def main():
    dedrm(sys.argv[1])


if __name__ == "__main__":
    main()
