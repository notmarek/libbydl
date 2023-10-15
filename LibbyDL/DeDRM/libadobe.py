#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Helper library with code needed for Adobe stuff.
'''

import base64
import ssl
import sys
from uuid import getnode

try:
    import urllib.request as ulib
    import urllib.error as uliberror
except:
    import urllib2 as ulib
    import urllib2 as uliberror

from datetime import datetime, timedelta

from lxml import etree

try:
    from Cryptodome import Random
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHA

except ImportError:
    # Some distros still ship Crypto
    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA

# @@CALIBRE_COMPAT_CODE@@


from LibbyDL.DeDRM.customRSA import CustomRSA

from oscrypto import keys
from oscrypto.asymmetric import dump_certificate, dump_private_key

VAR_ACS_SERVER_HTTP = "http://adeactivate.adobe.com/adept"
VAR_ACS_SERVER_HTTPS = "https://adeactivate.adobe.com/adept"
KEY_FOLDER = "./keys/"
FILE_DEVICEKEY = f"{KEY_FOLDER}devicesalt"
FILE_DEVICEXML = f"{KEY_FOLDER}device.xml"
FILE_ACTIVATIONXML = f"{KEY_FOLDER}activation.xml"

# Lists of different ADE "versions" we know about
VAR_VER_SUPP_CONFIG_NAMES = ["ADE 1.7.2", "ADE 2.0.1", "ADE 3.0.1", "ADE 4.0.3", "ADE 4.5.10", "ADE 4.5.11"]
VAR_VER_SUPP_VERSIONS = ["ADE WIN 9,0,1131,27", "2.0.1.78765", "3.0.1.91394", "4.0.3.123281",
                         "com.adobe.adobedigitaleditions.exe v4.5.10.186048",
                         "com.adobe.adobedigitaleditions.exe v4.5.11.187303"]
VAR_VER_HOBBES_VERSIONS = ["9.0.1131.27", "9.3.58046", "10.0.85385", "12.0.123217", "12.5.4.186049", "12.5.4.187298"]
VAR_VER_OS_IDENTIFIERS = ["Windows Vista", "Windows Vista", "Windows 8", "Windows 8", "Windows 8", "Windows 8"]

# "Missing" versions:
# 1.7.1, 2.0, 3.0, 4.0, 4.0.1, 4.0.2, 4.5 to 4.5.9
# 4.5.7.179634

# This is a list of ALL versions we know (and can potentially use if present in a config file).
# Must have the same length / size as the four lists above.
VAR_VER_BUILD_IDS = [1131, 78765, 91394, 123281, 186048, 187303]
# Build ID 185749 also exists, that's a different (older) variant of 4.5.10. 

# This is a list of versions that can be used for new authorizations:
VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE = [78765, 91394, 123281, 187303]

# This is a list of versions to be displayed in the version changer.
VAR_VER_ALLOWED_BUILD_IDS_SWITCH_TO = [1131, 78765, 91394, 123281, 187303]

# Versions >= this one are using HTTPS
# According to changelogs, this is implemented as of ADE 4.0.1 - no idea what build ID that is.
VAR_VER_NEED_HTTPS_BUILD_ID_LIMIT = 123281

# Versions >= this are using a different order for the XML elements in a FulfillmentNotification.
# This doesn't matter for fulfillment at all, but I want to emulate ADE as accurately as possible.
# Implemented as of ADE 4.0.0, no idea what exact build number that is.
VAR_VER_USE_DIFFERENT_NOTIFICATION_XML_ORDER = 123281

# Default build ID to use - ADE 2.0.1
VAR_VER_DEFAULT_BUILD_ID = 78765

devkey_bytes = None


def get_devkey_path():
    global FILE_DEVICEKEY
    return FILE_DEVICEKEY


def get_device_path():
    global FILE_DEVICEXML
    return FILE_DEVICEXML


def get_activation_xml_path():
    global FILE_ACTIVATIONXML
    return FILE_ACTIVATIONXML


def int_to_bytes(value, length, big_endian=True):
    # Helper function for Python2 only (big endian)
    # Python3 uses int.to_bytes()
    result = []

    for i in range(0, length):
        result.append(value >> (i * 8) & 0xff)

    if big_endian:
        result.reverse()

    return result


def get_mac_address():
    mac1 = getnode()
    mac2 = getnode()
    if (mac1 != mac2) or ((mac1 >> 40) % 2):
        if sys.version_info[0] >= 3:
            return bytes([1, 2, 3, 4, 5, 0])
        else:
            return bytearray([1, 2, 3, 4, 5, 0])

    if sys.version_info[0] >= 3:
        return mac1.to_bytes(6, byteorder='big')

    return int_to_bytes(mac1, 6)


############################################## HTTP stuff:

def sendHTTPRequest_DL2FILE(URL, outputfile):
    # type: (str, str) -> int

    headers = {
        "Accept": "*/*",
        "User-Agent": "book2png",
        # MacOS uses different User-Agent. Good thing we're emulating a Windows client.
    }
    req = ulib.Request(url=URL, headers=headers)
    handler = ulib.urlopen(req)

    chunksize = 16 * 1024

    ret_code = handler.getcode()

    loc = None
    try:
        loc = req.headers.get("Location")
    except:
        pass

    if loc is not None:
        return sendHTTPRequest_DL2FILE(loc)

    if ret_code != 200:
        return ret_code
    if type(outputfile) is str:
        with open(outputfile, "wb") as f:
            while True:
                chunk = handler.read(chunksize)
                if not chunk:
                    break
                f.write(chunk)
    else:
        while True:
            chunk = handler.read(chunksize)
            if not chunk:
                break
            outputfile.write(chunk)

    return 200


def sendHTTPRequest_getSimple(URL):
    # type: (str) -> str

    headers = {
        "Accept": "*/*",
        "User-Agent": "book2png",
        # MacOS uses different User-Agent. Good thing we're emulating a Windows client.
    }

    # Ignore SSL:
    # It appears as if lots of book distributors have either invalid or expired certs ...
    # No idea how Adobe handles that (pinning?), but we can just ignore SSL errors and continue anyways.
    # Not the best solution, but it works.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = ulib.Request(url=URL, headers=headers)
    handler = ulib.urlopen(req, context=ctx)

    content = handler.read()

    loc = None
    try:
        loc = req.headers.get("Location")
    except:
        pass

    if loc is not None:
        return sendHTTPRequest_getSimple(loc)

    return content


def sendPOSTHTTPRequest(URL, document, type, returnRC=False):
    # type: (str, bytes, str, bool) -> str

    headers = {
        "Accept": "*/*",
        "User-Agent": "book2png",
        # MacOS uses different User-Agent. Good thing we're emulating a Windows client.
        "Content-Type": type
    }

    # Ignore SSL:
    # It appears as if lots of book distributors have either invalid or expired certs ...
    # No idea how Adobe handles that (pinning?), but we can just ignore SSL errors and continue anyways.
    # Not the best solution, but it works.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Make sure URL has a protocol
    # Some vendors (see issue #22) apparently don't include "http://" in some of their URLs.
    # Python returns an error when it encounters such a URL, so just add that prefix if it's not present. 

    if not "://" in URL:
        print("Provider is using malformed URL %s, fixing." % (URL))
        URL = "http://" + URL

    req = ulib.Request(url=URL, headers=headers, data=document)
    try:
        handler = ulib.urlopen(req, context=ctx)
    except uliberror.HTTPError as err:
        # This happens with HTTP 500 and related errors.
        print("Post request caused HTTPError %d" % (err.code))
        if returnRC:
            return err.code, "Post request caused HTTPException"
        else:
            return None

    except uliberror.URLError as err:
        # This happens if the hostname cannot be resolved.
        print("Post request failed with URLError")
        if returnRC:
            return 900, "Post request failed with URLError"
        else:
            return None

    ret_code = handler.getcode()
    if (ret_code == 204 and returnRC):
        return 204, ""
    if (ret_code != 200):
        print("Post request returned something other than 200 - returned %d" % (ret_code))

    content = handler.read()

    loc = None
    try:
        loc = req.headers.get("Location")
    except:
        pass

    if loc is not None:
        return sendPOSTHTTPRequest(loc, document, type, returnRC)

    if returnRC:
        return ret_code, content

    return content


def sendHTTPRequest(URL):
    # type: (str) -> str
    return sendHTTPRequest_getSimple(URL)


def sendRequestDocu(document, URL):
    # type: (str, str) -> str
    return sendPOSTHTTPRequest(URL, document.encode("utf-8"), "application/vnd.adobe.adept+xml", False)


def sendRequestDocuRC(document, URL):
    # type: (str, str) -> str
    return sendPOSTHTTPRequest(URL, document.encode("utf-8"), "application/vnd.adobe.adept+xml", True)


######### Encryption and signing ###################


def addNonce():
    dt = datetime.utcnow()
    sec = (dt - datetime(1970, 1, 1)).total_seconds()
    Ntime = int(sec * 1000) + 62167219200000
    tmp = 0
    if sys.version_info[0] >= 3:
        final = bytearray(Ntime.to_bytes(8, 'little'))
        final.extend(tmp.to_bytes(4, 'little'))
    else:
        final = bytearray(int_to_bytes(Ntime, 8, False))
        final.extend(int_to_bytes(tmp, 4, True))
    m10m = dt + timedelta(minutes=10)
    m10m_str = m10m.strftime("%Y-%m-%dT%H:%M:%SZ")
    ret = f"""
        <adept:nonce>{base64.b64encode(final).decode("utf-8")}</adept:nonce>
        <adept:expiration>{m10m_str}</adept:expiration>
    """

    return ret


def get_cert_from_pkcs12(_pkcs12, _key):
    _, cert, _ = keys.parse_pkcs12(_pkcs12, _key)
    return dump_certificate(cert, encoding="der")


def sign_node(node):
    sha_hash = hash_node(node)
    sha_hash = sha_hash.digest()

    # print("Hash is " + sha_hash.hex())

    global devkey_bytes
    global pkcs12

    if devkey_bytes is None:
        f = open(FILE_DEVICEKEY, "rb")
        devkey_bytes = f.read()
        f.close()

    # Get private key

    try:
        activationxml = etree.parse(FILE_ACTIVATIONXML)
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        pkcs12 = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("pkcs12"))).text
    except:
        return None

    my_pkcs12 = base64.b64decode(pkcs12)
    my_priv_key, _, _ = keys.parse_pkcs12(my_pkcs12, base64.b64encode(devkey_bytes))
    my_priv_key = dump_private_key(my_priv_key, None, "der")

    # textbook RSA with that private key

    block = CustomRSA.encrypt_for_adobe_signature(my_priv_key, sha_hash)
    signature = base64.b64encode(block).decode()

    # Debug
    # print("sig is %s\n" % block.hex())

    return signature


def hash_node(node):
    hash_ctx = SHA.new()
    hash_node_ctx(node, hash_ctx)
    return hash_ctx


ASN_NONE = 0
ASN_NS_TAG = 1  # aka "BEGIN_ELEMENT"
ASN_CHILD = 2  # aka "END_ATTRIBUTES"
ASN_END_TAG = 3  # aka "END_ELEMENT"
ASN_TEXT = 4  # aka "TEXT_NODE"
ASN_ATTRIBUTE = 5  # aka "ATTRIBUTE"

debug = False


def hash_node_ctx(node, hash_ctx):
    qtag = etree.QName(node.tag)

    if (qtag.localname == "hmac" or qtag.localname == "signature"):
        if (qtag.namespace == "http://ns.adobe.com/adept"):
            # Adobe HMAC and signature are not hashed
            return
        else:
            print("Warning: Found hmac or signature node in unexpected namespace " + qtag.namespace)

    hash_do_append_tag(hash_ctx, ASN_NS_TAG)

    if qtag.namespace is None:
        hash_do_append_string(hash_ctx, "")
    else:
        hash_do_append_string(hash_ctx, qtag.namespace)
    hash_do_append_string(hash_ctx, qtag.localname)

    attrKeys = node.keys()

    # Attributes need to be sorted
    attrKeys.sort()
    # TODO Implement UTF-8 bytewise sorting:
    # "Attributes are sorted first by their namespaces and
    # then by their names; sorting is done bytewise on UTF-8
    # representations."

    for attribute in attrKeys:
        # Hash all the attributes
        hash_do_append_tag(hash_ctx, ASN_ATTRIBUTE)

        # Check for element namespace and hash that, if present:
        q_attribute = etree.QName(attribute)

        # Hash element namespace (usually "")
        # If namespace is none, use "". Else, use namespace.
        hash_do_append_string(hash_ctx, "" if q_attribute.namespace is None else q_attribute.namespace)

        # Hash (local) name and value
        hash_do_append_string(hash_ctx, q_attribute.localname)
        hash_do_append_string(hash_ctx, node.get(attribute))

    hash_do_append_tag(hash_ctx, ASN_CHILD)

    if (node.text is not None):
        # If there's raw text, hash that.

        # This code block used to just be the following:
        #   hash_do_append_tag(hash_ctx, ASN_TEXT)
        #   hash_do_append_string(hash_ctx, node.text.strip())
        # though that only works with text nodes < 0x7fff.
        # While I doubt we'll ever encounter text nodes larger than 32k in
        # this application, I want to implement the spec correctly.
        # So there's a loop going over the text, hashing 32k chunks.

        text = node.text.strip()
        textlen = len(text)
        if textlen > 0:
            done = 0
            remaining = 0
            while True:
                remaining = textlen - done
                if remaining > 0x7fff:
                    print("Warning: Hashing text node larger than 32k.")
                    print("This usually doesn't happen, and I'm not sure if this is implemented correctly.")
                    print("If you run into issues, please open a bug report.")
                    remaining = 0x7fff

                hash_do_append_tag(hash_ctx, ASN_TEXT)
                hash_do_append_string(hash_ctx, text[done:done + remaining])

                done += remaining
                if done >= textlen:
                    break

    for child in node:
        # If there's child nodes, hash these as well.
        hash_node_ctx(child, hash_ctx)

    hash_do_append_tag(hash_ctx, ASN_END_TAG)


def hash_do_append_string(hash_ctx, string):
    # type: (SHA.SHA1Hash, str) -> None

    if sys.version_info[0] >= 3:
        str_bytes = bytes(string, encoding="utf-8")
    else:
        str_bytes = bytes(string)

    length = len(str_bytes)
    len_upper = int(length / 256)
    len_lower = int(length & 0xFF)

    hash_do_append_raw_bytes(hash_ctx, [len_upper, len_lower])
    hash_do_append_raw_bytes(hash_ctx, str_bytes)


def hash_do_append_tag(hash_ctx, tag):
    # type: (SHA.SHA1Hash, int) -> None

    if (tag > 5):
        return

    hash_do_append_raw_bytes(hash_ctx, [tag])


def hash_do_append_raw_bytes(hash_ctx, data):
    # type: (SHA.SHA1Hash, bytes) -> None
    hash_ctx.update(bytearray(data))
