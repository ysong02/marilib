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
    # 10635067331885412150: 1,  #1197
    # 6549880700996162597: 1,   #2455
    # 9384813031983946288: 1,   #3732
    # 12783125272499498932: 1,  #dongle right first, far from the battery
    # 16941624621023851926: 1,
    # 8290733575524042394: 1,   # (0x730E9A42C083C69A)
    # 7371531211680010965: 1,
    # 13534910923300025121: 1,  # (0xBBD5A9C611DA3321)
    # 9405667249234238580: 1,   # (0x8287A487A221DC74)
    # 12783125272499498932: 1,  # (0xB166C8B51AA6AFB4)
    # 16941624621023851926: 1,  # (0xEB1CBDD50E237596)
    # 7127549101271569271: 1,   # (0x62EA2424EC725377)
    # 6218459718522383876: 1,   # (0x564C682ACC9A2E04)
    # 17300894277316536379: 1,  # (0xF0191FAE600A683B) 1
    # 18349667659277568414: 1,  # (0xFDB6CC02C854CF1E)
    # 10742538141931910037: 1,  # (0x9579960F203ADE95)
    # 10080117882988163402: 1,  # (0x8C3BDCC588440DCA)
    # 16310379059002337361: 1,  # (0xE26E0464A4FE9291)
    # 17070677507917047193: 1,  # (0xECC4E0DBD527FC99)
    # 4528915915839139021: 1,   # (0x3EF06E4B72E98CCD)
    # 6195366612911522372: 1,   # (0x55DA7FF0F238A844)
    # 4968705434056800913: 1,   # (0x44E5B4534F8DBC91)
    # 1516123764445483797: 1,   # (0x150E3BE9B7C78815)
    # 12190208419773301444: 1,  # (0xA95D8A2DF55E6C44) 2
    # 14827384806936868169: 1,  # (0xCD9FC2F10292D689)
    # 6138069568830277656: 1,   # (0x554EC897971DCF18)
    # 18141194150150193251: 1,  # (0xFB986FD3DFD36E63)
    # 1514906480579722530: 1,   # (0x151148302FD6F5A2)
    # 222066098013904176: 1,    # (0x0314C3596BF55EB0)
    # 13238217859734493863: 1,  # (0xB7B971F84F29BAE7)
    # 14151120593296977617: 1,  # (0xC48AACFD77448F11)
    # 15878768268906818768: 1,  # (0xDC878301DB6B0590)
    # 17088954029495178868: 1,  # (0xED02BE5529D07C34)
    # # new panel 2
    # 4535246095091600589: 1,
    # 18282024049680109342: 1,
    # 6186397710979475524: 1,
    # 17061008523164908697: 1,
    # 12204062495238679620: 1,
    # 10104912929888669130: 1,
    # 16315983330321273489: 1,
    # 1517215999467161621: 1,
    # 10770804975542656661: 1,
    # 4964572434155814033: 1,

    # 6147071094808235800: 1,    # 0x554EC897971DCF18 3
    # 18129363255763889763: 1,   # 0xFB986FD3DFD36E63
    # 13743531631566521488: 1,   # 0xBEBAD533DADE0490
    # 222017070478745264: 1,     # 0x0314C3596BF55EB0
    # 13238737890926246631: 1,   # 0xB7B971F84F29BAE7
    # 14162322182847631121: 1,   # 0xC48AACFD77448F11
    # 1518073921198814626: 1,    # 0x151148302FD6F5A2
    # 15890813854199514512: 1,   # 0xDC878301DB6B0590
    # 17078422009925368884: 1,   # 0xED02BE5529D07C34
    # 14816775639458305673: 1,   # 0xCD9FC2F10292D689
    # 1203120372995600495: 1,   # 0x109E28ECE64C36EF   4
    # 10900275224251529163: 1,  # 0x97DA7DD328BDBDCB
    # 9760237519434276206: 1,   # 0x8773544FDD51DD6E GOOD
    # 1270546824849070842: 1,   # 0x11A0A918B5B8E7FA
    # 2066724030493678213: 1,   # 0x1C8CBEB244CCFA85
    # 8858541606642887231: 1,   # 0x7AEFDCA81BF7AA3F GOOD 
    # 13010128443246486935: 1,  # 0xB4E8C68D708FDA97
    # 2443633552744342614: 1,   # 0x21F5E133961F7156
    # 10125919541451223850: 1,  # 0x8CF14B56416ED46A
    # 7871848721346016547: 1,   # 0x6D464E29F925B623

    # 1197439548868277999: 1,    # Error from 0x109E28ECE64C36EF
    # 7874066940684514851: 1,    # Error from 0x6D464E29F925B623
    # 1270201018511583226: 1,    # Error from 0x11A0A918B5B8E7FA
    # 10942196590525136331: 1,   # Error from 0x97DA7DD328BDBDCB
    # 10155981468534232170: 1,   # Error from 0x8CF14B56416ED46A
    # 13035887432205064855: 1,   # Error from 0xB4E8C68D708FDA97
    # 2447109584223957334: 1,    # Error from 0x21F5E133961F7156
    # 2057228802669214341: 1,    # Error from 0x1C8CBEB244CCFA85

    # 10579126579630216887: 1,  # (0x92D09B92D4C096B7) 1 some of the above are incorrect 
    # 4435060724645887717: 1,   # (0x3D8C803B29CDFEE5) 1

    # 9122231805034755486: 1,                         #  5
    # 17523113121151126954: 1,
    # 14463323148164541204: 1,
    # 15517518075359866427: 1,
    # 7845321561394663507: 1,
    # 772503970849161545: 1,
    # 3877172432935531829: 1,
    # 14196761186451925637: 1,
    # 7007555192569524100: 1,
    # 12504781739023999118: 1,

    # 8842980189123102603: 1,                        # 6
    # 5742189505021609069: 1,
    # 17415464592923333541: 1,
    # 13597184293621233890: 1,
    # 757517849727888837: 1,
    # 9495537089010934771: 1,
    # 9071587035449825099: 1,
    # 2705312135812996764: 1,
    # 1778551511107016044: 1,
    # 16457657701654763945: 1,

    # 14193911199080158358: 1,                       # 7
    # 1428653616930061679: 1,
    # 4804756443257577771: 1,
    # 4069553385350186289: 1,
    # 4538613935378570705: 1,
    # 290613705585048861: 1,
    # 13863185446001756760: 1,
    # 8837149420054786412: 1,
    # 3804590617224444076: 1,
    # 8139805595507600600: 1,

    # 7730071371180956200: 1,                        # 8
    # 16127416564797214844: 1,
    # 8544674852416843267: 1,
    # 14113211747357002690: 1,
    # 13358438416158191478: 1,
    # 1200267980526027546: 1,
    # 4682655469536753804: 1,
    # 16391899799279107721: 1,
    # 1910487909431134609: 1,
    # 3085959759843368591: 1,

    # 5352132833747793410: 1,                         # 9
    # 4950591723554081781: 1,
    # 3999074352131152368: 1,
    # 12153651532506386410: 1,
    # 1716145910896022733: 1,
    # 13492424256566235443: 1,
    # 5357554977619529541: 1,
    # 1660238667965822880: 1,
    # 6288607723976526495: 1,
    # 7367040521582137003: 1,

    # 908074433760392524: 1,                          # 10
    # 6380797444942874011: 1,
    # 10644610208182336420: 1,
    # 15915799285157323609: 1,
    # 255702529193880352: 1,
    # 14424080674466698729: 1,
    # 11147986264824215373: 1,
    # 15839523330310852146: 1,
    # 16102404654330069753: 1,
    # 1573165271076572958: 1,


    13874166616717188652: 1,  # (0xC08AF1078802DE2C)   1 HKUST-GZ
    8186629004225792610: 1,   # (0x719CBFB468C9CA62)
    3906168502809380684: 1,   # (0x36357F8EBAC5C74C)
    3095576435735888948: 1,   # (0x2AF5B25E031B8434)
    6428426347528121527: 1,   # (0x59365BB42D2CECB7)
    3361456247254043448: 1,   # (0x2EA64AA5A9984B38)
    10033474232818838344: 1,  # (0x8B3E0FA7B633AB48)
    3263261579593580272: 1,   # (0x2D496F1DFCDAFEF0)
    513781969368411336: 1,    # (0x072151FAA0346CC8)
    10941147854857191867: 1,  # (0x97D6C4015BCA41BB)

    10126770676659675522: 1,  # (0x8C898446C8246182)   2
    7351360745470258035: 1,   # (0x660547A619816B73)
    16641247389858144168: 1,  # (0xE6F19654FBE41FA8)
    1990553339572374254: 1,   # (0x1B9FDDB747ADCAEE)
    7957594840214081541: 1,   # (0x6E6F0E5895711005)
    11900704798903567545: 1,  # (0xA527CBF6436F04B9)
    4957842541309655575: 1,   # (0x44CDCB860714FA17)
    16032927973902048732: 1,  # (0xDE80670BD1DADDDC)
    16324815443117225550: 1,  # (0xE28D652726D0364E)
    1686363574742387506: 1,   # (0x17672ABC8AAD8B32)

    10896228316892928209: 1,  # (0x97372DEC6BF498D1)   3
    6064236488234425401: 1,   # (0x54287EF4D32CDC39)
    1078264596510987464: 1,   # (0x0EF6C3F008EAD4C8)
    17854659141208254058: 1,  # (0xF7C87DE41166266A)
    3358698974228049492: 1,   # (0x2E9C7EEC0254EE54)
    7703385134065415724: 1,   # (0x6AE7EBF713FE762C)
    12836902676947680721: 1,  # (0xB225D6F8CBBA3DD1)
    7659251789898165592: 1,   # (0x6A4B20EC2627AD58)
    12629387792415388202: 1,  # (0xAF449948A992F22A)
    4006172968565079804: 1,   # (0x3798C916DC17FEFC)

    394770418479112264: 1,    # (0x057A819AA147A048)   4
    12738166641591938078: 1,  # (0xB0C70F1221D16C1E)
    5660493397277149844: 1,   # (0x4E8E1CC116260A94)
    13191103055992335950: 1,  # (0xB710365707FE2E4E)
    4424411691868378104: 1,   # (0x3D66AAFE01E653F8)
    6636719319122802089: 1,   # (0x5C1A5D0ED24975A9)
    18348726789699635168: 1,  # (0xFEA3C5CCACBD87E0)
    18287221923020589863: 1,  # (0xFDC94372FA60CB27)
    8548044473100935643: 1,   # (0x76A0C128A76C21DB)
    15748440969134227483: 1,  # (0xDA8DB39F6374401B)

    5550715607111091744: 1,   # (0x4D081A6F8B12C620)  5
    11288923317230805561: 1,  # (0x9CAA4FF21C2AA239)
    10000475105574281710: 1,  # (0x8AC8D31FACE461EE)
    7220205309768812297: 1,   # (0x643352799628C709)
    9796146078779748998: 1,   # (0x87F2E6F4D980B286)
    16902329549159346147: 1,  # (0xEA91232C2E3B2FE3)
    2478638716752796669: 1,   # (0x2265E4C7CE949BFD)
    3108685858521393447: 1,   # (0x2B2445515B72A927)
    3071303670506872289: 1,   # (0x2A9F766A75EA5DE1)
    15453425370964372363: 1,  # (0xD675987FC7572B8B)

    18184083964644582375: 1,  # (0xFC5AD805BE8463E7)   6
    558986701793784439: 1,    # (0x07C1EB719295F277)
    2438209733951134901: 1,   # (0x21D642D5B80E9CB5)
    5927193027621425626: 1,   # (0x52419EA7AE8C11DA)
    14768935725642363933: 1,  # (0xCCF5CCCB157D341D)
    462292615918392122: 1,    # (0x066A64AF521A133A)
    9805369443736741590: 1,   # (0x8813AB8ED965E6D6)
    6402681418521357833: 1,   # (0x58DAE4D3C8F5AE09)
    5847975248777668139: 1,   # (0x51282E813EAB662B)
    11628685617686478835: 1,  # (0xA16163F536E57FF3)

    7802813368982931096: 1,   # (0x6C49296B02E58698)   7
    12301885306490468925: 1,  # (0xAAB9138210F63A3D)
    7823857367865929748: 1,   # (0x6C93ECD2D0F8B014)
    3335645650137219190: 1,   # (0x2E4A980BB9018076)
    14419584049225429659: 1,  # (0xC81CA74B66F8729B)
    8548506920618104376: 1,   # (0x76A265C09B691638)
    16274162305343945406: 1,  # (0xE1D970647B13FABE)
    13146271155413563144: 1,  # (0xB670EFF6C363B708)
    7124472235469961562: 1,   # (0x62DF35C04751F95A)
    15109228702932978320: 1,  # (0xD1AEC3740474CA90)

    1096046317588094865: 1,   # (0x0F35F05199369F91)  8
    15870544541657573583: 1,  # (0xDC3F802CC583A8CF)
    6748242700524121764: 1,   # (0x5DA692FB7EDCEEA4)
    15995421074808367419: 1,  # (0xDDFB26B85CBFE93B)
    10989487998813562904: 1,  # (0x9882811C30B36818)
    15732988498151541046: 1,  # (0xDA56CDAE9FA10936)
    16409326051841558490: 1,  # (0xE3B9A31A939447DA)
    9667119807840389804: 1,   # (0x8628823F23780AAC)
    12081993950225115836: 1,  # (0xA7ABDD7C0D962ABC)
    5185684659417273543: 1,   # (0x47F740B909C254C7)

    12414315807662374467: 1,  # (0xAC488274053B7E43)   9
    5184610846111626337: 1,   # (0x47F37018651EF461)
    14913337736269138361: 1,  # (0xCEF6D1A829C009B9)
    1969681574824310823: 1,   # (0x1B55B6F4DC08F827)
    13061892814881934529: 1,  # (0xB5452A4F6D43CCC1)
    3105698224142301267: 1,   # (0x2B19A81485903853)
    2536570872367613248: 1,   # (0x2333B5C4E3130540)
    15261355614428289152: 1,  # (0xD3CB3A12BCE95880)
    1023437170275287992: 1,   # (0x0E33FAAF183083B8)
    10254852887011013936: 1,  # (0x8E508E5E422E3530)
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

def mr_swarm_verification_result_edhoc(payload):
    """Verify attestation evidence received via EDHOC EAD4.

    payload[0] == 0xE4; payload[1:] is CBOR [asn_dl, evidence_cbor, node_id, attestation_binder]
    evidence_cbor is CBOR [fw_version, key_id, signature]
    signature covers CBOR [asn_dl, key_id, hash_firmware, node_id, attestation_binder]
    Returns True if verification passes.
    """
    asn_dl, evidence_cbor, node_id, attestation_binder = cbor2.loads(payload[1:])
    fw_version, key_id, signature = cbor2.loads(evidence_cbor)

    hash_ref = swarm_reference_value_list.get(key_id)
    if hash_ref is None:
        print(f"[VERIFIER] Unknown key_id={key_id} for node=0x{node_id:016X}")
        return False

    public_key_bytes = swarm_public_key_list.get(key_id)
    if public_key_bytes is None:
        print(f"[VERIFIER] No public key for key_id={key_id}")
        return False

    sig_structure = cbor2.dumps([asn_dl, key_id, hash_ref, node_id, attestation_binder])
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(bytes(signature), sig_structure)
        print(f"[VERIFIER] Attestation PASSED for node=0x{node_id:016X}, fw_version={fw_version}, asn_dl={asn_dl}")
        return True
    except InvalidSignature:
        print(f"[VERIFIER] Attestation FAILED for node=0x{node_id:016X}")
        return False


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

# def mr_swarm_generate_verification_response(result, asn_ul, node_id):
#     if (result):
#         sig_structure_cbor = cbor2.dumps([node_id, 1, key_id_v, asn_ul])
#     else:
#         sig_structure_cbor = cbor2.dumps([node_id, 0, key_id_v, asn_ul])
#     private_key = Ed25519PrivateKey.from_private_bytes(private_key_verifier)
#     result_signed = private_key.sign(sig_structure_cbor)
#     # generate verification_response
#     verification_response = cbor2.dumps([node_id, result, key_id_v, asn_ul, result_signed])
#     return bytes([MARI_ATTEST_VERIF_RESP_PAYLOAD_TAG]) + verification_response

# def mr_swarm_verification_result(verification_request):
#         asn_ul, asn_offset, evidence_cbor, node_id = cbor2.loads(verification_request)
#         version_attester, signature_attester = cbor2.loads(evidence_cbor)
        
#         # check freshness 
#         if (asn_offset > freshness_threshold):
#             #return mr_swarm_generate_verification_response(False, asn_ul, node_id)
#             # temporary for test
#             return mr_swarm_generate_verification_response(True, asn_ul, node_id)
        
#         asn_dl = asn_ul - asn_offset
#         if (mr_swarm_check_signature(signature_attester, asn_dl, version_attester, node_id)):
#             # print(f"all checks good")
#             return mr_swarm_generate_verification_response(True, asn_ul, node_id)
#         else:
#             print(f"signature checks fail")
#             #return mr_swarm_generate_verification_response(False, asn_ul, node_id)
#             # temporary for test
#             return mr_swarm_generate_verification_response(True, asn_ul, node_id)

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
            #return mr_swarm_generate_verification_response(False, asn_ul, node_id)
            # temporary for test
            return mr_swarm_generate_verification_response(True, node_id)
        
        asn_dl = asn_ul - asn_offset
        if (mr_swarm_check_signature(signature_attester, asn_dl, version_attester, node_id)):
            # print(f"all checks good")
            return mr_swarm_generate_verification_response(True, node_id)
        else:
            print(f"signature checks fail")
            #return mr_swarm_generate_verification_response(False, asn_ul, node_id)
            # temporary for test
            return mr_swarm_generate_verification_response(True, node_id)
