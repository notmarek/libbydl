import base64

from lxml import etree

from LibbyDL.DeDRM.libadobe import VAR_VER_SUPP_VERSIONS, VAR_VER_HOBBES_VERSIONS
from LibbyDL.DeDRM.libadobe import addNonce, sign_node, get_cert_from_pkcs12, sendRequestDocu
from LibbyDL.DeDRM.libadobe import get_devkey_path, get_device_path, get_activation_xml_path


def buildFulfillRequest(acsm):
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    activationxml = etree.parse(get_activation_xml_path())
    devicexml = etree.parse(get_device_path())

    user_uuid = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text
    device_uuid = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("device"))).text
    try:
        fingerprint = None
        device_type = None
        fingerprint = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("fingerprint"))).text
        device_type = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("deviceType"))).text
    except:
        pass

    if (fingerprint is None or fingerprint == "" or device_type is None or device_type == ""):
        # This should usually never happen with a proper activation, but just in case it does,
        # I'll leave this code in - it loads the fingerprint from the device data instead.
        fingerprint = devicexml.find("./%s" % (adNS("fingerprint"))).text
        device_type = devicexml.find("./%s" % (adNS("deviceType"))).text

    version = None
    clientOS = None
    clientLocale = None

    ver = devicexml.findall("./%s" % (adNS("version")))

    for f in ver:
        if f.get("name") == "hobbes":
            version = f.get("value")
        elif f.get("name") == "clientOS":
            clientOS = f.get("value")
        elif f.get("name") == "clientLocale":
            clientLocale = f.get("value")

    # Find matching client version depending on the Hobbes version. 
    # This way we don't need to store and re-load it for each fulfillment. 

    try:
        v_idx = VAR_VER_HOBBES_VERSIONS.index(version)
        clientVersion = VAR_VER_SUPP_VERSIONS[v_idx]

    except:
        # Version not present, probably the "old" 10.0.4 entry. 
        # As 10.X is in the 3.0 range, assume we're on ADE 3.0
        clientVersion = "3.0.1.91394"

    if clientVersion == "ADE WIN 9,0,1131,27":
        # Ancient ADE 1.7.2 does this request differently
        request = "<fulfill xmlns=\"http://ns.adobe.com/adept\">\n"
        request += "<user>%s</user>\n" % (user_uuid)
        request += "<device>%s</device>\n" % (device_uuid)
        request += "<deviceType>%s</deviceType>\n" % (device_type)
        request += etree.tostring(acsm, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
        request += "</fulfill>"
        return request, False

    else:
        request = ""
        request += "<?xml version=\"1.0\"?>"
        request += "<adept:fulfill xmlns:adept=\"http://ns.adobe.com/adept\">"
        request += "<adept:user>%s</adept:user>" % (user_uuid)
        request += "<adept:device>%s</adept:device>" % (device_uuid)
        request += "<adept:deviceType>%s</adept:deviceType>" % (device_type)
        request += etree.tostring(acsm, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
        request += "<adept:targetDevice>"

        request += "<adept:softwareVersion>%s</adept:softwareVersion>" % (version)
        request += "<adept:clientOS>%s</adept:clientOS>" % (clientOS)
        request += "<adept:clientLocale>%s</adept:clientLocale>" % (clientLocale)
        request += "<adept:clientVersion>%s</adept:clientVersion>" % (clientVersion)
        request += "<adept:deviceType>%s</adept:deviceType>" % (device_type)
        request += "<adept:productName>%s</adept:productName>" % ("ADOBE Digitial Editions")
        # YES, this typo ("Digitial" instead of "Digital") IS present in ADE!!
        request += "<adept:fingerprint>%s</adept:fingerprint>" % (fingerprint)

        request += "<adept:activationToken>"
        request += "<adept:user>%s</adept:user>" % (user_uuid)
        request += "<adept:device>%s</adept:device>" % (device_uuid)
        request += "</adept:activationToken>"
        request += "</adept:targetDevice>"
        request += "</adept:fulfill>"
        return request, True


def buildInitLicenseServiceRequest(authURL):
    # type: (str) -> str

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    NSMAP = {"adept": "http://ns.adobe.com/adept"}
    etree.register_namespace("adept", NSMAP["adept"])

    activationxml = etree.parse(get_activation_xml_path())
    user_uuid = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text

    ret = f"""
    <?xml version=\"1.0\"?>
        <adept:licenseServiceRequest xmlns:adept="http://ns.adobe.com/adept" identity="user">
        <adept:operatorURL>{authURL}</adept:operatorURL>
        {addNonce()}
        <adept:user>{user_uuid}</adept:user>
    </adept:licenseServiceRequest>
    """

    NSMAP = {"adept": "http://ns.adobe.com/adept"}
    etree.register_namespace("adept", NSMAP["adept"])

    req_xml = etree.fromstring(ret)

    signature = sign_node(req_xml)
    if (signature is None):
        return None

    etree.SubElement(req_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    return "<?xml version=\"1.0\"?>\n" + etree.tostring(req_xml, encoding="utf-8", pretty_print=True,
                                                        xml_declaration=False).decode("utf-8")


def getDecryptedCert(pkcs12_b64_string=None):
    if pkcs12_b64_string is None:
        activationxml = etree.parse(get_activation_xml_path())
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

        pkcs12_b64_string = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("pkcs12"))).text

    pkcs12_data = base64.b64decode(pkcs12_b64_string)

    try:
        from libadobe import devkey_bytes as devkey_adobe
    except:
        pass

    if devkey_adobe is not None:
        devkey_bytes = devkey_adobe
    else:
        f = open(get_devkey_path(), "rb")
        devkey_bytes = f.read()
        f.close()

    try:
        return get_cert_from_pkcs12(pkcs12_data, base64.b64encode(devkey_bytes))
    except:
        return None


def buildAuthRequest():
    activationxml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    my_cert = getDecryptedCert()
    if my_cert is None:
        print("Can't decrypt pkcs12 with devkey!")
        return None

    ret = "<?xml version=\"1.0\"?>\n"
    ret += "<adept:credentials xmlns:adept=\"http://ns.adobe.com/adept\">\n"
    ret += "<adept:user>%s</adept:user>\n" % (activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text)
    ret += "<adept:certificate>%s</adept:certificate>\n" % (base64.b64encode(my_cert).decode("utf-8"))
    ret += "<adept:licenseCertificate>%s</adept:licenseCertificate>\n" % (
        activationxml.find("./%s/%s" % (adNS("credentials"), adNS("licenseCertificate"))).text)
    ret += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>\n" % (
        activationxml.find("./%s/%s" % (adNS("credentials"), adNS("authenticationCertificate"))).text)
    ret += "</adept:credentials>"

    return ret


def doOperatorAuth(operatorURL):
    # type: (str) -> str

    auth_req = buildAuthRequest()

    if auth_req is None:
        return "Failed to create auth request"

    authURL = operatorURL
    if authURL.endswith("Fulfill"):
        authURL = authURL.replace("/Fulfill", "")

    replyData = sendRequestDocu(auth_req, authURL + "/Auth").decode("utf-8")

    if not "<success" in replyData:
        return "ERROR: Operator responded with %s\n" % replyData

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    NSMAP = {"adept": "http://ns.adobe.com/adept"}
    etree.register_namespace("adept", NSMAP["adept"])

    activationxml = etree.parse(get_activation_xml_path())

    activationURL = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("activationURL"))).text

    init_license_service_request = buildInitLicenseServiceRequest(authURL)

    if (init_license_service_request is None):
        return "Creating license request failed!"

    resp = sendRequestDocu(init_license_service_request, activationURL + "/InitLicenseService").decode("utf-8")
    if "<error" in resp:
        return "Looks like that failed: %s" % resp
    elif "<success" in resp:
        return None
    else:
        return "Useless response: %s" % resp


def operatorAuth(operatorURL):
    # type: (str) -> str

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    NSMAP = {"adept": "http://ns.adobe.com/adept"}
    etree.register_namespace("adept", NSMAP["adept"])

    activationxml = etree.parse(get_activation_xml_path())
    try:
        operator_url_list = activationxml.findall("./%s/%s" % (adNS("operatorURLList"), adNS("operatorURL")))

        for member in operator_url_list:
            if member.text.strip() == operatorURL:
                # print("Already authenticated to operator")
                return None
    except:
        pass

    ret = doOperatorAuth(operatorURL)
    if (ret is not None):
        return "doOperatorAuth error: %s" % ret

    # Check if list exists:
    list = activationxml.find("./%s" % (adNS("operatorURLList")))
    user_uuid = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text

    if list is None:
        x = etree.SubElement(activationxml.getroot(), etree.QName(NSMAP["adept"], "operatorURLList"), nsmap=NSMAP)
        etree.SubElement(x, etree.QName(NSMAP["adept"], "user")).text = user_uuid
        list = activationxml.find("./%s" % (adNS("operatorURLList")))
        if list is None:
            return "Err, this list should not be none right now ..."

    etree.SubElement(list, etree.QName(NSMAP["adept"], "operatorURL")).text = operatorURL

    f = open(get_activation_xml_path(), "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8"))
    f.close()

    return None


def buildRights(license_token_node):
    ret = "<?xml version=\"1.0\"?>\n"
    ret += "<adept:rights xmlns:adept=\"http://ns.adobe.com/adept\">\n"

    # Add license token
    ret += etree.tostring(license_token_node, encoding="utf-8", pretty_print=True, xml_declaration=False).decode(
        "utf-8")

    ret += "<adept:licenseServiceInfo>\n"

    NSMAP = {"adept": "http://ns.adobe.com/adept"}
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    lic_token_url = license_token_node.find("./%s" % (adNS("licenseURL"))).text

    ret += "<adept:licenseURL>%s</adept:licenseURL>\n" % lic_token_url

    # Get cert for this license URL:
    activationxml = etree.parse(get_activation_xml_path())

    try:
        licInfo = activationxml.findall("./%s/%s" % (adNS("licenseServices"), adNS("licenseServiceInfo")))

        found = False

        for member in licInfo:
            if member.find("./%s" % (adNS("licenseURL"))).text == lic_token_url:
                ret += "<adept:certificate>%s</adept:certificate>\n" % (
                    member.find("./%s" % (adNS("certificate"))).text)
                found = True
                break
    except:
        return None

    if not found:
        return None

    ret += "</adept:licenseServiceInfo>\n"
    ret += "</adept:rights>\n"

    return ret


def fulfill(acsm_file, do_notify=False, verbose_logging=False):
    acsmxml = None
    try:
        acsmxml = etree.parse(acsm_file)
    except:
        return False, "ACSM not found or invalid"

    fulfill_request, adept_ns = buildFulfillRequest(acsmxml)

    if verbose_logging:
        print("Fulfill request:")
        print(fulfill_request)

    fulfill_request_xml = etree.fromstring(fulfill_request)
    # Sign the request:
    signature = sign_node(fulfill_request_xml)
    if (signature is None):
        return False, "Signing failed!"

    NSMAP = {"adept": "http://ns.adobe.com/adept"}
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    if adept_ns:
        # "new" ADE
        etree.SubElement(fulfill_request_xml, etree.QName(NSMAP["adept"], "signature")).text = signature
    else:
        # ADE 1.7.2
        etree.SubElement(fulfill_request_xml, etree.QName("signature")).text = signature

    # Get operator URL: 
    operatorURL = None
    try:
        operatorURL = acsmxml.find("./%s" % (adNS("operatorURL"))).text.strip()
    except:
        pass

    if (operatorURL is None or len(operatorURL) == 0):
        return False, "OperatorURL missing in ACSM"

    fulfillURL = operatorURL + "/Fulfill"

    ret = operatorAuth(fulfillURL)
    if (ret is not None):
        return False, "operatorAuth error: %s" % ret

    if adept_ns:
        # "new" ADE
        fulfill_req_signed = "<?xml version=\"1.0\"?>\n" + etree.tostring(fulfill_request_xml, encoding="utf-8",
                                                                          pretty_print=True,
                                                                          xml_declaration=False).decode("utf-8")
    else:
        # ADE 1.7.2
        fulfill_req_signed = etree.tostring(fulfill_request_xml, encoding="utf-8", pretty_print=True,
                                            xml_declaration=False).decode("utf-8")

    replyData = sendRequestDocu(fulfill_req_signed, fulfillURL).decode("utf-8")

    if "<error" in replyData:
        if "E_ADEPT_DISTRIBUTOR_AUTH" in replyData:
            # This distributor *always* wants authentication, so force that again
            ret = doOperatorAuth(fulfillURL)

            if (ret is not None):
                return False, "doOperatorAuth error: %s" % ret

            replyData = sendRequestDocu(fulfill_req_signed, fulfillURL).decode("utf-8")
            if "<error" in replyData:
                return False, "Looks like there's been an error during Fulfillment even after auth: %s" % replyData
        else:
            return False, "Looks like there's been an error during Fulfillment: %s" % replyData

    return True, replyData
