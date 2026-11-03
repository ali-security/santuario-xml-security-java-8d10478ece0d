/*
 * Copyright  2013 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.xml.security.test.encryption;

import java.security.Key;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.xml.security.encryption.CipherData;
import org.apache.xml.security.encryption.CipherReference;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLCipherInput;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.implementations.EncryptedKeyResolver;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.IdResolver;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Regression tests for CVE-2013-4517: when secure validation is enabled on
 * an XMLCipher, Document Type Definitions must not be processed while
 * decrypting, so that a crafted DTD ("billion laughs" style entity
 * expansion) can not be used for a denial of service attack.
 *
 * The encrypted octets are referenced by a CipherReference whose transforms
 * parse an attacker supplied document: the octets are only obtained by
 * expanding the entities declared in its DTD.
 */
public class SecureValidationDecryptTest extends TestCase {

    static {
        org.apache.xml.security.Init.init();
    }

    /** AES-128 encryption (IV + cipher text) of PLAINTEXT with DATA_KEY */
    private static final String CIPHER_VALUE =
        "YmNkZWZnaGlqa2xtbm9wcRrPXjQ1hvhDFT+EdesMAPE4F6vlT+y0HPXe0+nAGLQ8";

    private static final String PLAINTEXT = "A test encrypted secret";

    private static final String DATA_KEY = "abcdefghijklmnop";

    private static final String KEY_ENCRYPTION_KEY = "0123456789abcdef";

    private static final String SECRET = "top secret";

    public SecureValidationDecryptTest(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(SecureValidationDecryptTest.class);
    }

    public static void main(String[] args) {
        String[] testCaseName = { "-noloading",
                                  SecureValidationDecryptTest.class.getName() };

        junit.textui.TestRunner.main(testCaseName);
    }

    /**
     * The CipherReference of an EncryptedData is dereferenced by
     * XMLCipherInput.
     */
    public void testCipherInputSecureValidation() throws Exception {
        Document doc = createCipherReferenceDocument();
        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.DECRYPT_MODE, dataKey());
        EncryptedData encryptedData =
            cipher.loadEncryptedData(doc, getEncryptedData(doc));

        // without secure validation the DTD is processed (backwards
        // compatible behaviour)
        XMLCipherInput input = new XMLCipherInput(encryptedData);
        assertFalse(input.isSecureValidation());
        assertTrue(Arrays.equals(Base64.decode(CIPHER_VALUE), input.getBytes()));

        input = new XMLCipherInput(encryptedData);
        input.setSecureValidation(true);
        assertTrue(input.isSecureValidation());
        try {
            input.getBytes();
            fail("DTD must be rejected when secure validation is enabled");
        } catch (XMLEncryptionException ex) {
            assertTrue(ex.getMessage(), isCausedByDocType(ex));
        }
    }

    /**
     * XMLCipher.decryptToByteArray of an EncryptedData with a
     * CipherReference.
     */
    public void testDecryptToByteArraySecureValidation() throws Exception {
        Element encryptedData =
            getEncryptedData(createCipherReferenceDocument());

        XMLCipher cipher = XMLCipher.getInstance();
        assertFalse(cipher.isSecureValidation());
        cipher.init(XMLCipher.DECRYPT_MODE, dataKey());
        byte[] decrypted = cipher.decryptToByteArray(encryptedData);
        assertEquals(PLAINTEXT, new String(decrypted, "ASCII"));

        cipher = XMLCipher.getInstance();
        cipher.setSecureValidation(true);
        assertTrue(cipher.isSecureValidation());
        cipher.init(XMLCipher.DECRYPT_MODE, dataKey());
        try {
            cipher.decryptToByteArray(encryptedData);
            fail("DTD must be rejected when secure validation is enabled");
        } catch (XMLEncryptionException ex) {
            assertTrue(ex.getMessage(), isCausedByDocType(ex));
        }
    }

    /**
     * XMLCipher.decryptKey of an EncryptedKey with a CipherReference.
     */
    public void testDecryptKeySecureValidation() throws Exception {
        Document doc = createEncryptedKeyDocument();
        Element encryptedKeyElement = getEncryptedKey(doc);

        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.UNWRAP_MODE, keyEncryptionKey());
        EncryptedKey encryptedKey =
            cipher.loadEncryptedKey(doc, encryptedKeyElement);
        Key key = cipher.decryptKey(encryptedKey, XMLCipher.AES_128);
        assertTrue(Arrays.equals(dataKey().getEncoded(), key.getEncoded()));

        cipher = XMLCipher.getInstance();
        cipher.setSecureValidation(true);
        cipher.init(XMLCipher.UNWRAP_MODE, keyEncryptionKey());
        encryptedKey = cipher.loadEncryptedKey(doc, encryptedKeyElement);
        try {
            cipher.decryptKey(encryptedKey, XMLCipher.AES_128);
            fail("DTD must be rejected when secure validation is enabled");
        } catch (XMLEncryptionException ex) {
            assertTrue(ex.getMessage(), isCausedByDocType(ex));
        }

        // the resolver used for EncryptedKeys found in a KeyInfo
        EncryptedKeyResolver resolver =
            new EncryptedKeyResolver(XMLCipher.AES_128, keyEncryptionKey());
        assertFalse(resolver.isSecureValidation());
        key = resolver.engineLookupAndResolveSecretKey
            (encryptedKeyElement, null, null);
        assertNotNull(key);
        assertTrue(Arrays.equals(dataKey().getEncoded(), key.getEncoded()));

        resolver =
            new EncryptedKeyResolver(XMLCipher.AES_128, keyEncryptionKey());
        resolver.setSecureValidation(true);
        assertTrue(resolver.isSecureValidation());
        assertNull(resolver.engineLookupAndResolveSecretKey
            (encryptedKeyElement, null, null));
    }

    /**
     * XMLCipher.doFinal of an EncryptedData whose key is an EncryptedKey
     * (with a CipherReference) in its KeyInfo, decrypted with a KEK.
     */
    public void testDoFinalEncryptedKeySecureValidation() throws Exception {
        Document doc = createEncryptedKeyDocument();
        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128);
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        cipher.setKEK(keyEncryptionKey());
        cipher.doFinal(doc, getEncryptedData(doc));
        assertSecretDecrypted(doc);

        doc = createEncryptedKeyDocument();
        cipher = XMLCipher.getInstance(XMLCipher.AES_128);
        cipher.setSecureValidation(true);
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        cipher.setKEK(keyEncryptionKey());
        try {
            cipher.doFinal(doc, getEncryptedData(doc));
            fail("DTD must be rejected when secure validation is enabled");
        } catch (XMLEncryptionException ex) {
            // the key could not be resolved
        }
        assertEquals(0, doc.getElementsByTagName("Secret").getLength());
    }

    /**
     * Secure validation does not prevent the encryption and decryption of
     * documents without a DTD.
     */
    public void testSecureValidationRoundTrip() throws Exception {
        Document doc = newDocument();
        Element secret = createSecretDocument(doc);

        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128);
        cipher.setSecureValidation(true);
        cipher.init(XMLCipher.ENCRYPT_MODE, dataKey());
        cipher.doFinal(doc, secret);
        assertEquals(0, doc.getElementsByTagName("Secret").getLength());

        cipher = XMLCipher.getInstance(XMLCipher.AES_128);
        cipher.setSecureValidation(true);
        cipher.init(XMLCipher.DECRYPT_MODE, dataKey());
        cipher.doFinal(doc, getEncryptedData(doc));
        assertSecretDecrypted(doc);
    }

    /**
     * Returns a document whose only purpose is to carry the given encrypted
     * octets (base64 encoded) in the entities of its DTD.
     */
    private static String dtdDocument(String cipherValue) {
        int half = cipherValue.length() / 2;
        return "<!DOCTYPE CipherText [\n"
            + "  <!ENTITY part1 \"" + cipherValue.substring(0, half) + "\">\n"
            + "  <!ENTITY part2 \"" + cipherValue.substring(half) + "\">\n"
            + "  <!ENTITY cipherValue \"&part1;&part2;\">\n"
            + "]>\n"
            + "<CipherText>&cipherValue;</CipherText>";
    }

    /**
     * Adds an element containing the base64 encoded DTD document and
     * the transforms which turn it into the encrypted octets: Base64 decode
     * the DTD document, canonicalize it (parses the document and expands
     * the entities), select its text and Base64 decode it.
     */
    private static void addCipherText(XMLCipher cipher, Document doc,
        CipherReference cipherReference, String id, String cipherValue)
        throws Exception {

        org.apache.xml.security.encryption.Transforms xencTransforms =
            cipher.createTransforms(doc);
        cipherReference.setTransforms(xencTransforms);
        Transforms dsTransforms = xencTransforms.getDSTransforms();
        dsTransforms.addTransform(Transforms.TRANSFORM_BASE64_DECODE);
        dsTransforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        XPathContainer xpc = new XPathContainer(doc);
        xpc.setXPath("self::text()");
        dsTransforms.addTransform(Transforms.TRANSFORM_XPATH,
                                  xpc.getElementPlusReturns());
        dsTransforms.addTransform(Transforms.TRANSFORM_BASE64_DECODE);

        Element cipherText = doc.createElementNS(null, "CipherText");
        cipherText.setAttributeNS(null, "Id", id);
        IdResolver.registerElementById(cipherText, id);
        cipherText.appendChild(doc.createTextNode
            (Base64.encode(dtdDocument(cipherValue).getBytes("UTF-8"))));
        doc.getDocumentElement().appendChild(cipherText);
    }

    /**
     * An EncryptedData whose encrypted octets (CIPHER_VALUE) are only
     * obtained by expanding the entities of a DTD.
     */
    private Document createCipherReferenceDocument() throws Exception {
        Document doc = newDocument();
        doc.appendChild(doc.createElementNS(null, "EncryptedDoc"));

        XMLCipher cipher = XMLCipher.getInstance();
        EncryptedData encryptedData =
            cipher.createEncryptedData(CipherData.REFERENCE_TYPE,
                                       "#CipherTextId");
        encryptedData.setEncryptionMethod
            (cipher.createEncryptionMethod(XMLCipher.AES_128));
        addCipherText(cipher, doc,
                      encryptedData.getCipherData().getCipherReference(),
                      "CipherTextId", CIPHER_VALUE);
        doc.getDocumentElement().insertBefore
            (cipher.martial(doc, encryptedData),
             doc.getDocumentElement().getFirstChild());
        return doc;
    }

    /**
     * An encrypted Secret element, the data key is wrapped in an
     * EncryptedKey in the KeyInfo of the EncryptedData. The wrapped key is
     * only obtained by expanding the entities of a DTD.
     */
    private Document createEncryptedKeyDocument() throws Exception {
        Document doc = newDocument();
        Element secret = createSecretDocument(doc);

        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.AES_128_KeyWrap);
        keyCipher.init(XMLCipher.WRAP_MODE, keyEncryptionKey());
        String wrappedKey = keyCipher.encryptKey(doc, dataKey())
            .getCipherData().getCipherValue().getValue();

        EncryptedKey encryptedKey =
            keyCipher.createEncryptedKey(CipherData.REFERENCE_TYPE,
                                         "#EncryptedKeyValue");
        encryptedKey.setEncryptionMethod
            (keyCipher.createEncryptionMethod(XMLCipher.AES_128_KeyWrap));
        addCipherText(keyCipher, doc,
                      encryptedKey.getCipherData().getCipherReference(),
                      "EncryptedKeyValue", wrappedKey);
        Element encryptedKeyElement = keyCipher.martial(doc, encryptedKey);

        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128);
        cipher.init(XMLCipher.ENCRYPT_MODE, dataKey());
        EncryptedData builder = cipher.getEncryptedData();
        KeyInfo keyInfo = builder.getKeyInfo();
        if (keyInfo == null) {
            keyInfo = new KeyInfo(doc);
            builder.setKeyInfo(keyInfo);
        }
        keyInfo.addUnknownElement(encryptedKeyElement);
        cipher.doFinal(doc, secret);
        return doc;
    }

    private static Element createSecretDocument(Document doc) {
        Element root = doc.createElementNS(null, "Root");
        doc.appendChild(root);
        Element secret = doc.createElementNS(null, "Secret");
        secret.appendChild(doc.createTextNode(SECRET));
        root.appendChild(secret);
        return secret;
    }

    private static void assertSecretDecrypted(Document doc) {
        assertEquals(0, doc.getElementsByTagNameNS
            (EncryptionConstants.EncryptionSpecNS,
             EncryptionConstants._TAG_ENCRYPTEDDATA).getLength());
        NodeList secrets = doc.getElementsByTagName("Secret");
        assertEquals(1, secrets.getLength());
        assertEquals(SECRET, secrets.item(0).getFirstChild().getNodeValue());
    }

    private static Element getEncryptedData(Document doc) {
        return (Element) doc.getElementsByTagNameNS
            (EncryptionConstants.EncryptionSpecNS,
             EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
    }

    private static Element getEncryptedKey(Document doc) {
        return (Element) doc.getElementsByTagNameNS
            (EncryptionConstants.EncryptionSpecNS,
             EncryptionConstants._TAG_ENCRYPTEDKEY).item(0);
    }

    private static Document newDocument() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().newDocument();
    }

    private static Key dataKey() throws Exception {
        return new SecretKeySpec(DATA_KEY.getBytes("ASCII"), "AES");
    }

    private static Key keyEncryptionKey() throws Exception {
        return new SecretKeySpec(KEY_ENCRYPTION_KEY.getBytes("ASCII"), "AES");
    }

    private static boolean isCausedByDocType(Throwable t) {
        for (int i = 0; t != null && i < 32; i++) {
            String msg = t.getMessage();
            if (msg != null && msg.indexOf("DOCTYPE") != -1) {
                return true;
            }
            Throwable next = null;
            if (t instanceof XMLSecurityException) {
                next = ((XMLSecurityException) t).getOriginalException();
            } else if (t instanceof SAXException) {
                next = ((SAXException) t).getException();
            }
            if (next == null) {
                next = t.getCause();
            }
            if (next == t) {
                break;
            }
            t = next;
        }
        return false;
    }
}
