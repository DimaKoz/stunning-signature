/*

The MIT License (MIT)

Copyright (c) 2018  Dmitrii Kozhevin <kozhevin.dima@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the “Software”), to deal in the Software without
restriction, including without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

#include "pkcs7_helper.h"

/*PKCS7 structure
*contentInfo : SEQUENCE
*	contentType : ObjectIdentifier  {data|signedData|envelopedData|signedAndEnvelopedData|digestedData|encryptedData}
* 	content		#Content is determined by contentType
*
*contentInfo : SEQUENCE
*	contentType : ObjectIdentifier  {data}
*	content : OCTETSTRING
*
*contentInfo : SEQUENCE
*	contentType : ObjectIdentifier  {signedData}
*	content[optional] : SEQUENCE 							#CERT.RSA Belongs to signedData type
*		version : INTEGER
*		digestAlgorithms : SET : DigestAlgorithmIdentifier  #Message digest algorithm
*		contentInfo : SEQUENCE   							#
*		certificates[optional] : SEQUENCE 					#Certificate information
*			tbsCertificate : SEQUENCE #
*				version : INTEGER
*				serialNumber : INTEGER  					#The serial number of the certificate, uniquely determined by the certificate issuer and serial number
*				signature ： SEQUENCE : AlgorithmIdentifier
*				issuer : SET 								#Certificate issuer
*				validity : SEQUENCE    						#The validity of the certificate
*				subject : SET                               #Subject of certificate
*				subjectPublicKeyInfo : SEQUENCE 			#Public key related information, including encryption algorithm and public key
*				issuerUniqueID[optional] : BITSTRING
*				subjectUniqueID[optional] : BITSTRING
*				extensions[optional] : SEQUENCE  			#certificate extended information
*			signatureAlgorithm : AlgorithmIdentifier 		#Signature algorithms
*			signatureValue : BITSTRING 						#This is the digital signature of the tbsCertificate section to prevent the tbsCertificate content from being modified
*		crls[optional] : SET 								#Certificate revocation list
*		signerInfos : SET
*			signerInfo : SEQUENCE							#Signer information
*				version : INTEGER
*				issuerAndSerialNumber : SEQUENCE 			#The issuer and serial number of the certificate
*				digestAlgorithmId : SEQUENCE : DigestAlgorithmIdentifier #Message digest algorithm
*				authenticatedAttributes[optional]
*				digestEncryptionAlgorithmId : SEQUENCE 		#Signature algorithm
*				encryptedDigest : OCTETSTRING   			#Private key encrypted data
*				unauthenticatedAttributes[optional]
*
*Each item is saved in the form of{tag，length，content}
*/

static uint32_t m_pos = 0;
static size_t m_length = 0;
static struct element *head = NULL;
static struct element *tail = NULL;


/**
 * Calculate the number of bytes occupied by length according to lenbyte.
 * 1) The most significant bit of the byte is 1, then the length of the low 7-bit number of bytes;
 * 2) The highest bit is 0, then lenbyte represents the length
 */
static uint32_t pkcs7HelperLenNum(unsigned char lenbyte) {
    uint32_t num = 1;
    if (lenbyte & 0x80) {
        num += lenbyte & 0x7f;
    }
    return num;
}


/**
 * Calculate length information based on lenbyte，
 * The algorithm is lenbyte the highest bit is 1，
 * Then lenbyte & 0x7F represent the length of the byte length,
 * Subsequent bytes are stored in big-endian mode. The highest bit is 0， Lenbyte directly represents the length
 *
 * 1) If 0x82 0x34 0x45 0x22 .... 0x82 is lenbyte,
 * The high level is 1, 0x82 & 0x7F == 2,
 * Then the following two bytes are the length information stored at the high end. The length information is 0x3445
   2)If lenbyte == 0x34, the highest bit is 0, then the length information is 0x34
*/
static uint32_t pkcs7HelperGetLength(unsigned char *certrsa, unsigned char lenbyte, int offset) {
    int32_t len = 0, num;
    unsigned char tmp;
    if (lenbyte & 0x80) {
        num = lenbyte & 0x7f;
        if (num < 0 || num > 4) {
            NSV_LOGW("its too long !\n");
            return 0;
        }
        while (num) {
            len <<= 8;
            tmp = certrsa[offset++];
            len += (tmp & 0xff);
            num--;
        }
    } else {
        len = lenbyte & 0xff;
    }
    assert(len >= 0);
    return (uint32_t) len;
}

/**
 * Each element has a corresponding element.
 */
int32_t pkcs7HelperCreateElement(unsigned char *certrsa, unsigned char tag, char *name, int level) {
    unsigned char get_tag = certrsa[m_pos++];
    if (get_tag != tag) {
        m_pos--;
        return -1;
    }
    unsigned char lenbyte = certrsa[m_pos];
    int len = pkcs7HelperGetLength(certrsa, lenbyte, m_pos + 1);
    m_pos += pkcs7HelperLenNum(lenbyte);

    element *node = (element *) calloc(1, sizeof(element));
    node->tag = get_tag;
    strcpy(node->name, name);
    node->begin = m_pos;
    node->len = len;
    node->level = level;
    node->next = NULL;

    if (head == NULL) {
        head = tail = node;
    } else {
        tail->next = node;
        tail = node;
    }
    return len;
}

/**
 * Parse certificate information
 */
bool pkcs7HelperParseCertificate(unsigned char *certrsa, int level) {
    char *names[] = {
            "tbsCertificate",
            "version",
            "serialNumber",
            "signature",
            "issuer",
            "validity",
            "subject",
            "subjectPublicKeyInfo",
            "issuerUniqueID-[optional]",
            "subjectUniqueID-[optional]",
            "extensions-[optional]",
            "signatureAlgorithm",
            "signatureValue"};
    int len = 0;
    unsigned char tag;

    len = pkcs7HelperCreateElement(certrsa, TAG_SEQUENCE, names[0], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    //version
    tag = certrsa[m_pos];
    if (((tag & 0xc0) == 0x80) && ((tag & 0x1f) == 0)) {
        m_pos += 1;
        m_pos += pkcs7HelperLenNum(certrsa[m_pos]);
        len = pkcs7HelperCreateElement(certrsa, TAG_INTEGER, names[1], level + 1);
        if (len == -1 || m_pos + len > m_length) {
            return false;
        }
        m_pos += len;
    }

    for (int i = 2; i < 11; i++) {
        switch (i) {
            case 2:
                tag = TAG_INTEGER;
                break;
            case 8:
                tag = 0xA1;
                break;
            case 9:
                tag = 0xA2;
                break;
            case 10:
                tag = 0xA3;
                break;
            default:
                tag = TAG_SEQUENCE;
        }
        len = pkcs7HelperCreateElement(certrsa, tag, names[i], level + 1);
        if (i < 8 && len == -1) {
            return false;
        }
        if (len != -1)
            m_pos += len;
    }
    //signatureAlgorithm
    len = pkcs7HelperCreateElement(certrsa, TAG_SEQUENCE, names[11], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    m_pos += len;
    //signatureValue
    len = pkcs7HelperCreateElement(certrsa, TAG_BITSTRING, names[12], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    m_pos += len;
    return true;
}

/**
 * Resolve signer information
 */
bool pkcs7HelperParseSignerInfo(unsigned char *certrsa, int level) {
    char *names[] = {
            "version",
            "issuerAndSerialNumber",
            "digestAlgorithmId",
            "authenticatedAttributes-[optional]",
            "digestEncryptionAlgorithmId",
            "encryptedDigest",
            "unauthenticatedAttributes-[optional]"};
    int len;
    unsigned char tag;
    for (int i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        switch (i) {
            case 0:
                tag = TAG_INTEGER;
                break;
            case 3:
                tag = 0xA0;
                break;
            case 5:
                tag = TAG_OCTETSTRING;
                break;
            case 6:
                tag = 0xA1;
                break;
            default:
                tag = TAG_SEQUENCE;

        }
        len = pkcs7HelperCreateElement(certrsa, tag, names[i], level);
        if (len == -1 || m_pos + len > m_length) {
            if (i == 3 || i == 6)
                continue;
            return false;
        }
        m_pos += len;
    }
    return m_pos == m_length ? true : false;
}

bool pkcs7HelperParseContent(unsigned char *certrsa, int level) {

    char *names[] = {"version",
                     "DigestAlgorithms",
                     "contentInfo",
                     "certificates-[optional]",
                     "crls-[optional]",
                     "signerInfos",
                     "signerInfo"};

    unsigned char tag;
    int len = 0;
    //version
    len = pkcs7HelperCreateElement(certrsa, TAG_INTEGER, names[0], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    m_pos += len;
    //DigestAlgorithms
    len = pkcs7HelperCreateElement(certrsa, TAG_SET, names[1], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    m_pos += len;
    //contentInfo
    len = pkcs7HelperCreateElement(certrsa, TAG_SEQUENCE, names[2], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    m_pos += len;
    //certificates-[optional]
    tag = certrsa[m_pos];
    if (tag == TAG_OPTIONAL) {
        m_pos++;
        m_pos += pkcs7HelperLenNum(certrsa[m_pos]);
        len = pkcs7HelperCreateElement(certrsa, TAG_SEQUENCE, names[3], level);
        if (len == -1 || m_pos + len > m_length) {
            return false;
        }
        bool ret = pkcs7HelperParseCertificate(certrsa, level + 1);
        if (ret == false) {
            return ret;
        }
    }
    //crls-[optional]
    tag = certrsa[m_pos];
    if (tag == 0xA1) {
        m_pos++;
        m_pos += pkcs7HelperLenNum(certrsa[m_pos]);
        len = pkcs7HelperCreateElement(certrsa, TAG_SEQUENCE, names[4], level);
        if (len == -1 || m_pos + len > m_length) {
            return false;
        }
        m_pos += len;
    }
    //signerInfos
    tag = certrsa[m_pos];
    if (tag != TAG_SET) {
        return false;
    }
    len = pkcs7HelperCreateElement(certrsa, TAG_SET, names[5], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    //signerInfo
    len = pkcs7HelperCreateElement(certrsa, TAG_SEQUENCE, names[6], level + 1);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    return pkcs7HelperParseSignerInfo(certrsa, level + 2);
}

/**
 *Finds the element in pkcs7 by name, returns NULL if it is not found.
 *name:
 *begin: beginning of the search
 */
static element *pkcs7HelperGetElement(const char *name, element *begin) {
    if (begin == NULL)
        begin = head;
    element *p = begin;
    while (p != NULL) {
        if (strncmp(p->name, name, strlen(name)) == 0) {
            return p;
        }

        p = p->next;
    }
    NSV_LOGW("not found the \"%s\"\n", name);
    return p;
}

static bool pkcs7HelperParse(unsigned char *certrsa, size_t length) {
    unsigned char tag, lenbyte;
    int len = 0;
    int level = 0;
    m_pos = 0;
    m_length = length;

    tag = certrsa[m_pos++];
    if (tag != TAG_SEQUENCE) {
        NSV_LOGE("the Tag indicated an ASN.1 not found!\n");
        return false;
    }
    lenbyte = certrsa[m_pos];
    len = pkcs7HelperGetLength(certrsa, lenbyte, m_pos + 1);
    m_pos += pkcs7HelperLenNum(lenbyte);
    if (m_pos + len > m_length)
        return false;
    //contentType
    len = pkcs7HelperCreateElement(certrsa, TAG_OBJECTID, "contentType", level);
    if (len == -1) {
        NSV_LOGE("not found the ContentType!\n");
        return false;
    }
    m_pos += len;
    //optional
    tag = certrsa[m_pos++];
    lenbyte = certrsa[m_pos];
    m_pos += pkcs7HelperLenNum(lenbyte);
    //content-[optional]
    len = pkcs7HelperCreateElement(certrsa, TAG_SEQUENCE, "content-[optional]", level);
    if (len == -1) {
        NSV_LOGI("not found the content!\n");
        return false;
    }
    return pkcs7HelperParseContent(certrsa, level + 1);
}

#ifndef NDEBUG

static void pkcs7HelperPrint() {
    NSV_LOGI("-----------------------------------------------------------------------\n");
    NSV_LOGI(" name                                          offset        length\n");
    NSV_LOGI(" ======================================== =============== =============\n");
    element *p = head;
    const size_t PRINT_BUF_SIZE = 256;
    char buf[PRINT_BUF_SIZE] = "";
    while (p != NULL) {
        for (int i = 0; i < p->level; i++) {
            sprintf(buf, "%s    ", buf);
        }
        sprintf(buf, "%s %s", buf, p->name);

        for (int i = 0; i < 40 - strlen(p->name) - 4 * p->level; i++) {
            sprintf(buf, "%s ", buf);
        }
        sprintf(buf, "%s%6d(0x%02x)", buf, p->begin, p->begin);
        int num = 0;
        int size = p->begin;
        while (size) {
            num += 1;
            size >>= 4;
        }
        if (num < 2) num = 2;
        for (int i = 0; i < 8 - num; i++) {
            sprintf(buf, "%s ", buf);
        }
        sprintf(buf, "%s%4d(0x%02x)", buf, (int) p->len, (unsigned int) p->len);
        NSV_LOGI("%s", buf);
        memset(buf, 0, PRINT_BUF_SIZE);
        p = p->next;
    }
    NSV_LOGI("-----------------------------------------------------------------------\n");
}


#endif //NDEBUG

/**
 * Convert length information to ASN.1 length format
 * len <= 0x7f       1
 * len >= 0x80       1 + Non-zero bytes
 */
static size_t pkcs7HelperGetNumFromLen(size_t len) {
    size_t num = 0;
    size_t tmp = len;
    while (tmp) {
        num++;
        tmp >>= 8;
    }
    if ((num == 1 && len >= 0x80) || (num > 1))
        num += 1;
    return num;
}


/**
 *Each element element is a {tag, length, data} triple, tag and length are saved by tag and len, and data is saved by [begin, begin+len].
 *
 *This function calculates the offset from the data position to the tag position
 */
size_t pkcs7HelperGetTagOffset(element *p, unsigned char *certrsa) {
    if (p == NULL)
        return 0;
    size_t offset = pkcs7HelperGetNumFromLen(p->len);
    if (certrsa[p->begin - offset - 1] == p->tag)
        return offset + 1;
    else
        return 0;
}

unsigned char *pkcs7HelperGetSignature(unsigned char *certrsa, size_t len_in, size_t *len_out) {
    if (!pkcs7HelperParse(certrsa, len_in)) {
        NSV_LOGE("Can't parse\n");
    } else {
#ifndef NDEBUG
        pkcs7HelperPrint();
#endif //NDEBUG
        element *p_cert = pkcs7HelperGetElement("certificates-[optional]", head);
        if (!p_cert) {
            return NULL;
        }
        size_t offset = pkcs7HelperGetTagOffset(p_cert, certrsa);
        if (offset == 0) {
            printf("get offset error!\n");
            return NULL;
        }
        *len_out = p_cert->len + offset;
        return certrsa + p_cert->begin - offset;
    }

    return NULL;
}

void pkcs7HelperFree() {
    element *p = head;
    while (p != NULL) {
        head = p->next;
        free(p);
        p = head;
    }
    head = NULL;
}