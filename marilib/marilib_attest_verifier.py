import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)
from cryptography.exceptions import InvalidSignature

# TODO: add verificaiton request tag
MARI_ATTEST_VERIF_REQ_PAYLOAD_TAG  = 0xE2 
MARI_ATTEST_VERIF_RESP_PAYLOAD_TAG = 0xE3

# provisions 
freshness_threshold = 50000
node_to_key_id = {
    10635067331885412150: 1,  #1197
    6549880700996162597: 1,   #2455
    9384813031983946288: 1,   #3732
    12783125272499498932: 1,  #dongle right first, far from the battery
    16941624621023851926: 1,
    8290733575524042394: 1,   # (0x730E9A42C083C69A)
    7371531211680010965: 1,
    13534910923300025121: 1,  # (0xBBD5A9C611DA3321)
    9405667249234238580: 1,   # (0x8287A487A221DC74)
    12783125272499498932: 1,  # (0xB166C8B51AA6AFB4)
    16941624621023851926: 1,  # (0xEB1CBDD50E237596)
    7127549101271569271: 1,   # (0x62EA2424EC725377)
    6218459718522383876: 1,   # (0x564C682ACC9A2E04)
    17300894277316536379: 1,  # (0xF0191FAE600A683B) 1
    18349667659277568414: 1,  # (0xFDB6CC02C854CF1E)
    10742538141931910037: 1,  # (0x9579960F203ADE95)
    10080117882988163402: 1,  # (0x8C3BDCC588440DCA)
    16310379059002337361: 1,  # (0xE26E0464A4FE9291)
    17070677507917047193: 1,  # (0xECC4E0DBD527FC99)
    4528915915839139021: 1,   # (0x3EF06E4B72E98CCD)
    6195366612911522372: 1,   # (0x55DA7FF0F238A844)
    4968705434056800913: 1,   # (0x44E5B4534F8DBC91)
    1516123764445483797: 1,   # (0x150E3BE9B7C78815)
    12190208419773301444: 1,  # (0xA95D8A2DF55E6C44) 2
    14827384806936868169: 1,  # (0xCD9FC2F10292D689)
    6138069568830277656: 1,   # (0x554EC897971DCF18)
    18141194150150193251: 1,  # (0xFB986FD3DFD36E63)
    1514906480579722530: 1,   # (0x151148302FD6F5A2)
    222066098013904176: 1,    # (0x0314C3596BF55EB0)
    13238217859734493863: 1,  # (0xB7B971F84F29BAE7)
    14151120593296977617: 1,  # (0xC48AACFD77448F11)
    15878768268906818768: 1,  # (0xDC878301DB6B0590)
    17088954029495178868: 1,  # (0xED02BE5529D07C34)
    # new panel 2
    4535246095091600589: 1,
    18282024049680109342: 1,
    6186397710979475524: 1,
    17061008523164908697: 1,
    12204062495238679620: 1,
    10104912929888669130: 1,
    16315983330321273489: 1,
    1517215999467161621: 1,
    10770804975542656661: 1,
    4964572434155814033: 1,

    6147071094808235800: 1,    # 0x554EC897971DCF18 3
    18129363255763889763: 1,   # 0xFB986FD3DFD36E63
    13743531631566521488: 1,   # 0xBEBAD533DADE0490
    222017070478745264: 1,     # 0x0314C3596BF55EB0
    13238737890926246631: 1,   # 0xB7B971F84F29BAE7
    14162322182847631121: 1,   # 0xC48AACFD77448F11
    1518073921198814626: 1,    # 0x151148302FD6F5A2
    15890813854199514512: 1,   # 0xDC878301DB6B0590
    17078422009925368884: 1,   # 0xED02BE5529D07C34
    14816775639458305673: 1,   # 0xCD9FC2F10292D689
    1203120372995600495: 1,   # 0x109E28ECE64C36EF   4
    10900275224251529163: 1,  # 0x97DA7DD328BDBDCB
    9760237519434276206: 1,   # 0x8773544FDD51DD6E GOOD
    1270546824849070842: 1,   # 0x11A0A918B5B8E7FA
    2066724030493678213: 1,   # 0x1C8CBEB244CCFA85
    8858541606642887231: 1,   # 0x7AEFDCA81BF7AA3F GOOD 
    13010128443246486935: 1,  # 0xB4E8C68D708FDA97
    2443633552744342614: 1,   # 0x21F5E133961F7156
    10125919541451223850: 1,  # 0x8CF14B56416ED46A
    7871848721346016547: 1,   # 0x6D464E29F925B623

    1197439548868277999: 1,    # Error from 0x109E28ECE64C36EF
    7874066940684514851: 1,    # Error from 0x6D464E29F925B623
    1270201018511583226: 1,    # Error from 0x11A0A918B5B8E7FA
    10942196590525136331: 1,   # Error from 0x97DA7DD328BDBDCB
    10155981468534232170: 1,   # Error from 0x8CF14B56416ED46A
    13035887432205064855: 1,   # Error from 0xB4E8C68D708FDA97
    2447109584223957334: 1,    # Error from 0x21F5E133961F7156
    2057228802669214341: 1,    # Error from 0x1C8CBEB244CCFA85

    10579126579630216887: 1,  # (0x92D09B92D4C096B7) 1 some of the above are incorrect 
    4435060724645887717: 1,   # (0x3D8C803B29CDFEE5) 1

    9122231805034755486: 1,                         #  5
    17523113121151126954: 1,
    14463323148164541204: 1,
    15517518075359866427: 1,
    7845321561394663507: 1,
    772503970849161545: 1,
    3877172432935531829: 1,
    14196761186451925637: 1,
    7007555192569524100: 1,
    12504781739023999118: 1,

    8842980189123102603: 1,                        # 6
    5742189505021609069: 1,
    17415464592923333541: 1,
    13597184293621233890: 1,
    757517849727888837: 1,
    9495537089010934771: 1,
    9071587035449825099: 1,
    2705312135812996764: 1,
    1778551511107016044: 1,
    16457657701654763945: 1,
}

swarm_public_key_list = {
    1: bytes.fromhex('b24f6d4e5f8147af1d1cd8c26e1a510b7a0f7f0a7bcc60688955d327b99c6475')
}

swarm_reference_value_list = {
    1: bytes.fromhex("DE6CD05D50778648BDB07B4D1C6DB81E0C2DF4533A32E515E533A26E2172873B")
}

key_id_v = 5
private_key_verifier = bytes.fromhex('8ed2d03fa136f5232f957e41d368940153d580e6b5ea57b68aa8836ff9539010')
public_key_verifier = bytes.fromhex('2463f9d5e61b84689b3b19ae10a3d6b5bfd1e69a643d7061aca4d04f7fd98db9')

def mr_swarm_check_signature(signature_attester, asn_dl, version, node_id):
    # prepare sig_structure, order: asn_dl, key_id, hash, node_id
    hash_verifier = swarm_reference_value_list[version]
    key_id_to_check = node_to_key_id[node_id]
    sig_structure = cbor2.dumps([asn_dl, key_id_to_check, hash_verifier, node_id])
    
    public_key_bytes = swarm_public_key_list[key_id_to_check]
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature_attester, sig_structure)
        return True
    except InvalidSignature:
        return False

def mr_swarm_generate_verification_response(result, node_id):
    if (result):
        sig_structure_cbor = cbor2.dumps([node_id, 1, key_id_v])
    else:
        sig_structure_cbor = cbor2.dumps([node_id, 0, key_id_v])
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_verifier)
    result_signed = private_key.sign(sig_structure_cbor)
    # generate verification_response
    verification_response = cbor2.dumps([node_id, result, key_id_v, result_signed])
    return bytes([MARI_ATTEST_VERIF_RESP_PAYLOAD_TAG]) + verification_response

def mr_swarm_verification_result(verification_request):
        asn_ul, asn_offset, evidence_cbor, node_id = cbor2.loads(verification_request)
        version_attester, signature_attester = cbor2.loads(evidence_cbor)
        
        # check freshness 
        if (asn_offset > freshness_threshold):
            return mr_swarm_generate_verification_response(False, node_id)
        
        asn_dl = asn_ul - asn_offset
        if (mr_swarm_check_signature(signature_attester, asn_dl, version_attester, node_id)):
            # print(f"all checks good")
            return mr_swarm_generate_verification_response(True, node_id)
        else:
            print(f"signature checks fail")
            return mr_swarm_generate_verification_response(False, node_id)
