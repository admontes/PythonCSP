#define PY_SSIZE_T_CLEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CSP_WinDef.h>
#include <CSP_WinCrypt.h>
#include <WinCryptEx.h>
#include <Python.h>

#define TYPE_DER (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

static PyObject *getContent(PyObject *self, PyObject *args)
{
    BYTE *mem_tbs = NULL;
    size_t mem_len = 0;

    /* Parse arguments */
    if (!PyArg_ParseTuple(args, "y#", &mem_tbs, &mem_len))
    {
        return NULL;
    }

    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(
            &hCryptProv,
            NULL,
            NULL,                 // Используется провайдер по умолчанию
            PROV_GOST_2012_256,   // Необходимо для зашифрования и подписи
            CRYPT_VERIFYCONTEXT)) // Никакие флаги не нужны
    {
        PyErr_Format(PyExc_RuntimeError, "Cryptographic context could not be acquired (error 0x%x)", GetLastError());
        return NULL;
    }

    // Откроем сообщение для декодирования
    HCRYPTMSG hMsg = CryptMsgOpenToDecode(
        TYPE_DER,                        // Encoding type
        CMSG_CRYPT_RELEASE_CONTEXT_FLAG, // Flags
        0,                               // Use the default message type
        hCryptProv,                      // Cryptographic provider
        NULL,                            // Recipient information
        NULL);                           // Stream information
    if (!hMsg)
    {
        CryptReleaseContext(hCryptProv, 0);
        PyErr_Format(PyExc_RuntimeError, "OpenToDecode failed (error 0x%x)", GetLastError());
        return NULL;
    }

    // Поместим в сообщение проверяемые данные
    BOOL bResult = CryptMsgUpdate(
        hMsg,    // Handle to the message
        mem_tbs, // Pointer to the encoded blob
        mem_len, // Size of the encoded blob
        TRUE);   // Last call
    // free(mem_tbs);
    if (!bResult)
    {
        CryptReleaseContext(hCryptProv, 0);
        CryptMsgClose(hMsg);
        PyErr_Format(PyExc_RuntimeError, "Decode MsgUpdate failed(error 0x%x)", GetLastError());
        return NULL;
    }

    //--------------------------------------------------------------------
    // Определим длину подписанных данных
    DWORD cbDecoded;
    bResult = CryptMsgGetParam(
        hMsg,               // Handle to the message
        CMSG_CONTENT_PARAM, // Parameter type
        // p.s. CMSG_CERT_PARAM для извлечения сертификата, если понадобится проверка подписи
        0,           // Signed Index
        NULL,        // Address for returned info
        &cbDecoded); // Size of the returned info
    if (!bResult)
    {
        CryptReleaseContext(hCryptProv, 0);
        CryptMsgClose(hMsg);
        PyErr_Format(PyExc_RuntimeError, "Decode CMSG_CONTENT_PARAM failed (error 0x%x)", GetLastError());
        return NULL;
    }

    //--------------------------------------------------------------------
    // Вернем подписанные данные
    BYTE *pbDecoded = (BYTE *)malloc(cbDecoded);
    // std::vector<BYTE> pbDecoded(cbDecoded);
    bResult = CryptMsgGetParam(
        hMsg,               // Handle to the message
        CMSG_CONTENT_PARAM, // Parameter type
        0,                  // Signer Index
        pbDecoded,          // Address for returned info
        &cbDecoded);        // Size of the returned info
    if (!bResult)
    {
        CryptReleaseContext(hCryptProv, 0);
        CryptMsgClose(hMsg);
        PyErr_Format(PyExc_RuntimeError, "The message param (CMSG_CONTENT_PARAM) dont return. (error 0x%x)", GetLastError());
        free(pbDecoded);
        return NULL;
    }

    DWORD stringSize;
    CryptBinaryToString(pbDecoded, cbDecoded, CRYPT_STRING_BINARY, NULL, &stringSize);

    char res[stringSize];
    CryptBinaryToString(pbDecoded, cbDecoded, CRYPT_STRING_BINARY, res, &stringSize);
    free(pbDecoded);
    CryptReleaseContext(hCryptProv, 0);
    CryptMsgClose(hMsg);

    return PyBytes_FromStringAndSize(res, stringSize);
}

char *GetHashAlgorithm(IN char *keyOid)
{
    if (strcmp(keyOid, szOID_CP_GOST_R3410EL) == 0)
    {
        return szOID_CP_GOST_R3411;
    }
    else if (strcmp(keyOid, szOID_CP_GOST_R3410_12_256) == 0)
    {
        return szOID_CP_GOST_R3411_12_256;
    }
    else if (strcmp(keyOid, szOID_CP_GOST_R3410_12_512) == 0)
    {
        return szOID_CP_GOST_R3411_12_512;
    }
    return NULL;
}

static PyObject *sign(PyObject *self, PyObject *args)
{
    const char *certificateSubjectKey;
    BYTE *mem_tbs = NULL;
    size_t mem_len = 0;

    /* Parse arguments */
    if (!PyArg_ParseTuple(args, "y#s", &mem_tbs, &mem_len, &certificateSubjectKey))
    {
        return NULL;
    }

    PCCERT_CONTEXT pCertContext = NULL; // Контекст сертификата
    HCERTSTORE hStoreHandle = 0;        // Дескриптор хранилища сертификатов
    CRYPT_SIGN_MESSAGE_PARA SigParams;

    // Открытие системного хранилища сертификатов.
    hStoreHandle = CertOpenSystemStore(0, "MY");
    if (!hStoreHandle)
    {
        PyErr_Format(PyExc_RuntimeError, "CertOpenSystemStore failed. (error 0x%x)", GetLastError());
        return NULL;
    }

    pCertContext = CertFindCertificateInStore(hStoreHandle, TYPE_DER, 0, CERT_FIND_SUBJECT_STR, certificateSubjectKey, NULL);
    if (!pCertContext)
    {
        CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
        PyErr_Format(PyExc_RuntimeError, "Certificate not finded. (error 0x%x)", GetLastError());
        return NULL;
    }

    ZeroMemory(&SigParams, sizeof(CRYPT_SIGN_MESSAGE_PARA));
    SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType = TYPE_DER;
    SigParams.pSigningCert = pCertContext;
    SigParams.HashAlgorithm.pszObjId = GetHashAlgorithm(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
    SigParams.HashAlgorithm.Parameters.cbData = 0;
    SigParams.HashAlgorithm.Parameters.pbData = NULL;
    SigParams.cMsgCert = 0;
    SigParams.rgpMsgCert = NULL;
    SigParams.cAuthAttr = 0;
    SigParams.dwInnerContentType = 0;
    SigParams.cMsgCrl = 0;
    SigParams.cUnauthAttr = 0;
    SigParams.dwFlags = 0;
    SigParams.dwFlags = CRYPT_MESSAGE_SILENT_KEYSET_FLAG;
    SigParams.pvHashAuxInfo = NULL;
    SigParams.rgAuthAttr = NULL;
    SigParams.pvHashAuxInfo = NULL; /* not used*/

    // Определение длины подписанного сообщения
    const BYTE *pbMessageBuffers[] = {mem_tbs};
    DWORD cbMessageSizes[] = {mem_len};
    DWORD signedLen = 0;
    if (!CryptSignMessage(&SigParams, FALSE, 1, pbMessageBuffers, cbMessageSizes, NULL, &signedLen))
    {
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
        PyErr_Format(PyExc_RuntimeError, "Dont find length of signed message. (error 0x%x)", GetLastError());
        return NULL;
    }

    // Подпись сообщения
    BYTE *signedMsg = (BYTE *)malloc(signedLen);
    if (!CryptSignMessage(&SigParams, FALSE, 1, pbMessageBuffers, cbMessageSizes, signedMsg, &signedLen))
    {
        free(signedMsg);
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
        PyErr_Format(PyExc_RuntimeError, "Sign is failed. (error 0x%x)", GetLastError());
        return NULL;
    }

    DWORD stringSize;
    CryptBinaryToString(signedMsg, signedLen, CRYPT_STRING_BINARY, NULL, &stringSize);
    char res[stringSize];
    CryptBinaryToString(signedMsg, signedLen, CRYPT_STRING_BINARY, res, &stringSize);

    free(signedMsg);
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);

    return PyBytes_FromStringAndSize(res, stringSize);
}

static PyMethodDef Methods[] = {
    {"get_content", getContent, METH_VARARGS},
    {"sign", sign, METH_VARARGS},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef PythonCSP = {
    PyModuleDef_HEAD_INIT,
    "PythonCSP",
    "Python interface for CryptoPro function",
    -1,
    Methods};

PyMODINIT_FUNC PyInit_PythonCSP(void)
{
    return PyModule_Create(&PythonCSP);
};