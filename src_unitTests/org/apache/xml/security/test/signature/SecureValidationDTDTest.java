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
package org.apache.xml.security.test.signature;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.RetrievalMethod;
import org.apache.xml.security.keys.keyresolver.implementations.RetrievalMethodResolver;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.IdResolver;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * Regression tests for CVE-2013-4517: Document Type Definitions must not be
 * processed when secure validation is enabled, so that a crafted DTD
 * ("billion laughs" style entity expansion) referenced from a signature can
 * not be used for a denial of service attack.
 */
public class SecureValidationDTDTest extends TestCase {

    static {
        org.apache.xml.security.Init.init();
    }

    /**
     * A small "billion laughs" document: the lol2 entity expands to 100
     * times "lol". A real attack simply uses more levels.
     */
    private static final String DTD_DOCUMENT =
        "<!DOCTYPE lolz [\n"
        + "  <!ENTITY lol \"lol\">\n"
        + "  <!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n"
        + "  <!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\">\n"
        + "]>\n"
        + "<lolz>&lol2;</lolz>";

    private static final String EXPANDED_LOL2;

    static {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 100; i++) {
            sb.append("lol");
        }
        EXPANDED_LOL2 = sb.toString();
    }

    private DocumentBuilder db;

    public SecureValidationDTDTest(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(SecureValidationDTDTest.class);
    }

    public static void main(String[] args) {
        String[] testCaseName = { "-noloading",
                                  SecureValidationDTDTest.class.getName() };

        junit.textui.TestRunner.main(testCaseName);
    }

    protected void setUp() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        db = dbf.newDocumentBuilder();
    }

    /**
     * Canonicalizer.canonicalize(byte[]) parses the input octets.
     */
    public void testCanonicalizerSecureValidation() throws Exception {
        Canonicalizer c14n =
            Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        assertFalse(c14n.isSecureValidation());

        // without secure validation the DTD is processed (backwards
        // compatible behaviour)
        String result =
            new String(c14n.canonicalize(DTD_DOCUMENT.getBytes("UTF-8")), "UTF-8");
        assertEquals("<lolz>" + EXPANDED_LOL2 + "</lolz>", result);

        c14n =
            Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        c14n.setSecureValidation(true);
        assertTrue(c14n.isSecureValidation());
        try {
            c14n.canonicalize(DTD_DOCUMENT.getBytes("UTF-8"));
            fail("DTD must be rejected when secure validation is enabled");
        } catch (SAXException ex) {
            assertTrue(ex.getMessage(), isCausedByDocType(ex));
        }
    }

    /**
     * A c14n Transform applied to an octet stream parses the octets
     * (CanonicalizerSpi.engineCanonicalize).
     */
    public void testC14NTransformSecureValidation() throws Exception {
        Document doc = db.newDocument();

        Transform transform =
            Transform.getInstance(doc, Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        assertFalse(transform.isSecureValidation());
        XMLSignatureInput output = transform.performTransform
            (new XMLSignatureInput(DTD_DOCUMENT.getBytes("UTF-8")));
        assertEquals("<lolz>" + EXPANDED_LOL2 + "</lolz>",
                     new String(output.getBytes(), "UTF-8"));
        assertFalse(output.isSecureValidation());

        // secure validation enabled on the Transform
        transform =
            Transform.getInstance(doc, Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        transform.setSecureValidation(true);
        assertTrue(transform.isSecureValidation());
        try {
            transform.performTransform
                (new XMLSignatureInput(DTD_DOCUMENT.getBytes("UTF-8")));
            fail("DTD must be rejected when secure validation is enabled");
        } catch (XMLSecurityException ex) {
            assertTrue(ex.toString(), isCausedByDocType(ex));
        }

        // secure validation enabled on the input
        String[] algorithms = {
            Transforms.TRANSFORM_C14N_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N_WITH_COMMENTS,
            Transforms.TRANSFORM_C14N11_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N11_WITH_COMMENTS,
            Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS
        };
        for (int i = 0; i < algorithms.length; i++) {
            transform = Transform.getInstance(doc, algorithms[i]);
            XMLSignatureInput input =
                new XMLSignatureInput(DTD_DOCUMENT.getBytes("UTF-8"));
            input.setSecureValidation(true);
            try {
                transform.performTransform(input);
                fail("DTD must be rejected by " + algorithms[i]
                     + " when secure validation is enabled");
            } catch (XMLSecurityException ex) {
                assertTrue(algorithms[i] + ": " + ex, isCausedByDocType(ex));
            }
        }
    }

    /**
     * Converting an octet stream into a node-set (for instance for an XPath
     * Transform) parses the octets.
     */
    public void testXMLSignatureInputSecureValidation() throws Exception {
        XMLSignatureInput input =
            new XMLSignatureInput(DTD_DOCUMENT.getBytes("UTF-8"));
        assertFalse(input.isSecureValidation());
        assertFalse(input.getNodeSet().isEmpty());

        input = new XMLSignatureInput(DTD_DOCUMENT.getBytes("UTF-8"));
        input.setSecureValidation(true);
        assertTrue(input.isSecureValidation());
        try {
            input.getNodeSet();
            fail("DTD must be rejected when secure validation is enabled");
        } catch (SAXException ex) {
            // expected
        }
    }

    /**
     * A signed Reference which Base64 decodes a ds:Object into a document
     * with a DTD and then canonicalizes it.
     */
    public void testSignatureSecureValidation() throws Exception {
        Document doc = db.newDocument();
        XMLSignature sig =
            new XMLSignature(doc, null, XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        doc.appendChild(sig.getElement());

        ObjectContainer object = new ObjectContainer(doc);
        object.setId("dtd-object");
        object.appendChild(doc.createTextNode
            (Base64.encode(DTD_DOCUMENT.getBytes("UTF-8"))));
        sig.appendObject(object);

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_BASE64_DECODE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        sig.addDocument("#dtd-object", transforms,
                        Constants.ALGO_ID_DIGEST_SHA1);

        SecretKey key = sig.createSecretKey("secret".getBytes("ASCII"));
        sig.sign(key);

        // without secure validation the signature validates
        XMLSignature signature = new XMLSignature(sig.getElement(), "");
        assertTrue(signature.checkSignatureValue(key));
        signature = new XMLSignature(sig.getElement(), "", false);
        assertTrue(signature.checkSignatureValue(key));
        assertFalse(signature.getSignedInfo().isSecureValidation());

        // with secure validation the DTD is rejected
        signature = new XMLSignature(sig.getElement(), "", true);
        assertTrue(signature.getSignedInfo().isSecureValidation());
        try {
            signature.checkSignatureValue(key);
            fail("DTD must be rejected when secure validation is enabled");
        } catch (XMLSecurityException ex) {
            assertTrue(ex.toString(), isCausedByDocType(ex));
        }
    }

    /**
     * A ds:RetrievalMethod which Base64 decodes a ds:Object into an X509Data
     * document with a DTD (RetrievalMethodResolver parses the octets).
     */
    public void testRetrievalMethodSecureValidation() throws Exception {
        X509Certificate cert = getCertificate();
        Element sigElement =
            createRetrievalMethodSignature(x509Data(cert, true), false);

        // without secure validation the DTD is processed: the certificate is
        // only available through the "cert" entity (backwards compatible
        // behaviour)
        XMLSignature signature = new XMLSignature(sigElement, "");
        assertEquals(cert, signature.getKeyInfo().getX509Certificate());
        assertEquals(cert.getPublicKey(),
                     signature.getKeyInfo().getPublicKey());
        signature = new XMLSignature(sigElement, "", false);
        assertEquals(cert, signature.getKeyInfo().getX509Certificate());
        assertEquals(cert.getPublicKey(),
                     signature.getKeyInfo().getPublicKey());

        // with secure validation the DTD is rejected, nothing is resolved
        signature = new XMLSignature(sigElement, "", true);
        assertNull(signature.getKeyInfo().getX509Certificate());
        assertNull(signature.getKeyInfo().getPublicKey());

        KeyInfo keyInfo = new XMLSignature(sigElement, "").getKeyInfo();
        keyInfo.setSecureValidation(true);
        assertNull(keyInfo.getX509Certificate());
        assertNull(keyInfo.getPublicKey());

        // the same directly through the (shared) resolver
        Element rm = signature.getKeyInfo().itemRetrievalMethod(0).getElement();
        RetrievalMethodResolver resolver = new RetrievalMethodResolver();
        assertEquals(cert,
            resolver.engineLookupResolveX509Certificate(rm, "", null));
        assertEquals(cert,
            resolver.engineLookupResolveX509Certificate(rm, "", null, false));
        assertNull
            (resolver.engineLookupResolveX509Certificate(rm, "", null, true));
        assertEquals(cert.getPublicKey(),
            resolver.engineLookupAndResolvePublicKey(rm, "", null));
        assertEquals(cert.getPublicKey(),
            resolver.engineLookupAndResolvePublicKey(rm, "", null, false));
        assertNull
            (resolver.engineLookupAndResolvePublicKey(rm, "", null, true));
        // the flag is not kept by the resolver
        assertEquals(cert,
            resolver.engineLookupResolveX509Certificate(rm, "", null));

        // secure validation only rejects the DTD: the same X509Data without
        // a DTD is still resolved
        sigElement =
            createRetrievalMethodSignature(x509Data(cert, false), false);
        signature = new XMLSignature(sigElement, "", true);
        assertEquals(cert, signature.getKeyInfo().getX509Certificate());
        assertEquals(cert.getPublicKey(),
                     signature.getKeyInfo().getPublicKey());
    }

    /**
     * A ds:RetrievalMethod pointing to another ds:RetrievalMethod which
     * Base64 decodes a ds:Object into an X509Data document with a DTD. The
     * second one would be resolved by the library wide KeyResolvers without
     * secure validation.
     */
    public void testNestedRetrievalMethodSecureValidation() throws Exception {
        X509Certificate cert = getCertificate();
        Element sigElement =
            createRetrievalMethodSignature(x509Data(cert, true), true);

        // without secure validation the DTD is processed
        XMLSignature signature = new XMLSignature(sigElement, "");
        assertEquals(cert, signature.getKeyInfo().getX509Certificate());
        assertEquals(cert.getPublicKey(),
                     signature.getKeyInfo().getPublicKey());

        // with secure validation it is rejected
        signature = new XMLSignature(sigElement, "", true);
        assertNull(signature.getKeyInfo().getX509Certificate());
        assertNull(signature.getKeyInfo().getPublicKey());
    }

    /**
     * Returns an X509Data document containing the certificate. With a DTD
     * the certificate is only available through the expansion of an entity.
     */
    private static String x509Data(X509Certificate cert, boolean withDTD)
        throws Exception {
        String base64Cert = Base64.encode(cert.getEncoded());
        if (!withDTD) {
            return "<X509Data xmlns=\"" + Constants.SignatureSpecNS + "\">"
                + "<X509Certificate>" + base64Cert + "</X509Certificate>"
                + "</X509Data>";
        }
        return "<!DOCTYPE X509Data [\n"
            + "  <!ENTITY lol \"lol\">\n"
            + "  <!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n"
            + "  <!ENTITY cert \"" + base64Cert + "\">\n"
            + "]>\n"
            + "<X509Data xmlns=\"" + Constants.SignatureSpecNS + "\">"
            + "<X509Certificate>&cert;</X509Certificate>"
            + "</X509Data>";
    }

    /**
     * Creates a signature whose ds:KeyInfo contains a ds:RetrievalMethod
     * that Base64 decodes a ds:Object containing the given X509Data
     * document. If nested is true, the ds:RetrievalMethod of the ds:KeyInfo
     * points to that ds:RetrievalMethod instead.
     */
    private Element createRetrievalMethodSignature(String x509Data,
        boolean nested) throws Exception {
        Document doc = db.newDocument();
        XMLSignature sig =
            new XMLSignature(doc, null, XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        doc.appendChild(sig.getElement());

        ObjectContainer object = new ObjectContainer(doc);
        object.setId("x509-object");
        object.appendChild(doc.createTextNode
            (Base64.encode(x509Data.getBytes("UTF-8"))));
        sig.appendObject(object);

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_BASE64_DECODE);
        RetrievalMethod rm = new RetrievalMethod
            (doc, "#x509-object", transforms, RetrievalMethod.TYPE_X509);
        if (nested) {
            ObjectContainer rmObject = new ObjectContainer(doc);
            rmObject.appendChild(rm.getElement());
            sig.appendObject(rmObject);
            IdResolver.registerElementById(rm.getElement(), "nested-rm");
            rm = new RetrievalMethod
                (doc, "#nested-rm", null, RetrievalMethod.TYPE_X509);
        }
        sig.getKeyInfo().add(rm);

        sig.addDocument("#x509-object", null, Constants.ALGO_ID_DIGEST_SHA1);
        sig.sign(sig.createSecretKey("secret".getBytes("ASCII")));
        return sig.getElement();
    }

    private static X509Certificate getCertificate() throws Exception {
        String keystoreFile =
            "data/org/apache/xml/security/samples/input/keystore.jks";
        String basedir = System.getProperty("basedir");
        if (basedir != null && !"".equals(basedir)) {
            keystoreFile = basedir + "/" + keystoreFile;
        }
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(keystoreFile);
        try {
            ks.load(fis, "xmlsecurity".toCharArray());
        } finally {
            fis.close();
        }
        return (X509Certificate) ks.getCertificate("test");
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
