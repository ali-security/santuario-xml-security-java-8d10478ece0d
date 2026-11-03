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
package javax.xml.crypto.test.dsig;

import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.RetrievalMethod;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.jcp.xml.dsig.internal.dom.DOMRetrievalMethod;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import junit.framework.TestCase;

import javax.xml.crypto.test.KeySelectors;

/**
 * Regression tests for CVE-2013-4517: Document Type Definitions must not be
 * processed by the JSR 105 implementation when the
 * <code>org.apache.jcp.xml.dsig.secureValidation</code> property is set, so
 * that a crafted DTD ("billion laughs" style entity expansion) referenced
 * from a signature can not be used for a denial of service attack.
 */
public class SecureValidationDTDTest extends TestCase {

    static {
        Security.insertProviderAt
            (new org.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    private static final String SECURE_VALIDATION =
        "org.apache.jcp.xml.dsig.secureValidation";

    /**
     * A small "billion laughs" document: the lol2 entity expands to 100
     * times "lol". A real attack simply uses more levels.
     */
    private static final String DTD_DOCUMENT =
        "<!DOCTYPE X509Data [\n"
        + "  <!ENTITY lol \"lol\">\n"
        + "  <!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n"
        + "  <!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\">\n"
        + "]>\n"
        + "<X509Data xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
        + "<X509SubjectName>&lol2;</X509SubjectName></X509Data>";

    private XMLSignatureFactory fac;
    private KeyInfoFactory kifac;
    private DocumentBuilder db;
    private SecretKey key;

    public SecureValidationDTDTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        fac = XMLSignatureFactory.getInstance
            ("DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI());
        kifac = fac.getKeyInfoFactory();
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        db = dbf.newDocumentBuilder();
        key = new SecretKeySpec("secret".getBytes("ASCII"), "HmacSHA1");
    }

    /**
     * A signed Reference which Base64 decodes a ds:Object into a document
     * with a DTD and then canonicalizes it.
     */
    public void testReferenceSecureValidation() throws Exception {
        Element sigElement = createSignature();

        // without secure validation the DTD is processed and the signature
        // validates (backwards compatible behaviour)
        DOMValidateContext dvc = newValidateContext(sigElement);
        XMLSignature sig = fac.unmarshalXMLSignature(dvc);
        assertTrue(sig.validate(dvc));

        dvc = newValidateContext(sigElement);
        dvc.setProperty(SECURE_VALIDATION, Boolean.FALSE);
        sig = fac.unmarshalXMLSignature(dvc);
        assertTrue(sig.validate(dvc));

        dvc = newValidateContext(sigElement);
        dvc.setProperty(SECURE_VALIDATION, Boolean.TRUE);
        sig = fac.unmarshalXMLSignature(dvc);
        try {
            sig.validate(dvc);
            fail("DTD must be rejected when " + SECURE_VALIDATION + " is set");
        } catch (XMLSignatureException ex) {
            assertTrue(ex.toString(), isCausedByDocType(ex));
        }
    }

    /**
     * A RetrievalMethod which Base64 decodes a ds:Object into an X509Data
     * document with a DTD.
     */
    public void testRetrievalMethodSecureValidation() throws Exception {
        Element sigElement = createSignature();

        // without secure validation the DTD is processed
        DOMValidateContext dvc = newValidateContext(sigElement);
        XMLSignature sig = fac.unmarshalXMLSignature(dvc);
        DOMRetrievalMethod rm =
            (DOMRetrievalMethod) sig.getKeyInfo().getContent().get(0);
        XMLStructure xs = rm.dereferenceAsXMLStructure(dvc);
        assertTrue(xs instanceof X509Data);
        String subjectName = (String) ((X509Data) xs).getContent().get(0);
        assertTrue(subjectName, subjectName.startsWith("lol"));

        dvc = newValidateContext(sigElement);
        dvc.setProperty(SECURE_VALIDATION, Boolean.TRUE);
        sig = fac.unmarshalXMLSignature(dvc);
        rm = (DOMRetrievalMethod) sig.getKeyInfo().getContent().get(0);
        try {
            rm.dereferenceAsXMLStructure(dvc);
            fail("DTD must be rejected when secure validation is enabled");
        } catch (URIReferenceException ex) {
            assertTrue(ex.toString(), isCausedByDocType(ex));
        }
    }

    private DOMValidateContext newValidateContext(Element sigElement) {
        return new DOMValidateContext
            (new KeySelectors.SecretKeySelector(key), sigElement);
    }

    private Element createSignature() throws Exception {
        Document doc = db.newDocument();
        Element envelope = doc.createElementNS
            ("http://example.org/envelope", "Envelope");
        envelope.setAttributeNS
            (Constants.NamespaceSpecNS, "xmlns", "http://example.org/envelope");
        doc.appendChild(envelope);

        // a ds:Object with a Base64 encoded document containing a DTD
        XMLObject obj = fac.newXMLObject(Collections.singletonList
            (new DOMStructure(doc.createTextNode
                (Base64.encode(DTD_DOCUMENT.getBytes("UTF-8"))))),
            "object", null, null);

        List transforms = new ArrayList();
        transforms.add
            (fac.newTransform(Transform.BASE64, (TransformParameterSpec) null));
        transforms.add(fac.newTransform
            (CanonicalizationMethod.INCLUSIVE, (TransformParameterSpec) null));
        Reference ref = fac.newReference
            ("#object", fac.newDigestMethod(DigestMethod.SHA1, null),
             transforms, null, null);

        SignedInfo si = fac.newSignedInfo
            (fac.newCanonicalizationMethod
                (CanonicalizationMethod.INCLUSIVE,
                 (C14NMethodParameterSpec) null),
             fac.newSignatureMethod(SignatureMethod.HMAC_SHA1, null),
             Collections.singletonList(ref));

        RetrievalMethod rm = kifac.newRetrievalMethod
            ("#object", X509Data.TYPE, Collections.singletonList
                (fac.newTransform
                    (Transform.BASE64, (TransformParameterSpec) null)));
        KeyInfo ki = kifac.newKeyInfo(Collections.singletonList(rm));

        XMLSignature sig = fac.newXMLSignature
            (si, ki, Collections.singletonList(obj), null, null);
        sig.sign(new DOMSignContext(key, envelope));

        Element sigElement = (Element) envelope.getElementsByTagNameNS
            (XMLSignature.XMLNS, "Signature").item(0);
        assertNotNull(sigElement);
        return sigElement;
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
