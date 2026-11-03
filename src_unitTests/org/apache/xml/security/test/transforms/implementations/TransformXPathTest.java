/*
 * Copyright  1999-2009 The Apache Software Foundation.
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
package org.apache.xml.security.test.transforms.implementations;

import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.xml.security.exceptions.XMLSecurityRuntimeException;
import org.apache.xml.security.signature.NodeFilter;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 * Errors raised while applying an XPath Transform must not disclose the
 * content of the transformed document (which may be a local file selected
 * by an attacker, e.g. through a RetrievalMethod) in the exception message.
 * See CVE-2021-40690.
 */
public class TransformXPathTest extends TestCase {

    private static final String SECRET = "TOPSECRETDOCUMENTCONTENT";

    private static final String SECRET_XML =
        "<root><data>" + SECRET + "</data></root>";

    public static Test suite() {
        return new TestSuite(TransformXPathTest.class);
    }

    public TransformXPathTest(String name) {
        super(name);
    }

    public static void main(String[] args) {

        String[] testCaseName = { "-noloading",
                                TransformXPathTest.class.getName() };
        junit.textui.TestRunner.main(testCaseName);
    }

    /**
     * An XPath expression that only fails (at evaluation time) on text nodes,
     * so the error is raised while the secret text node is the current node.
     */
    public void testXPathEvaluationErrorDoesNotLeakNodeContent()
        throws Exception {

        Transforms transforms =
            createXPathTransforms("not(self::text()) or ext:leak()");
        XMLSignatureInput output = transforms.performTransforms(
            new XMLSignatureInput(getDocument(SECRET_XML)));
        try {
            output.getBytes();
            fail("Expected an XMLSecurityRuntimeException");
        } catch (XMLSecurityRuntimeException ex) {
            assertNoLeak(ex);
            assertEquals("signature.Transform.XPathError", ex.getMsgID());
            assertEquals("Error evaluating XPath expression", ex.getMessage());
        }
    }

    /**
     * The XPath node filter must not include the current node in the
     * exception it raises when the expression cannot be evaluated.
     */
    public void testXPathNodeFilterErrorDoesNotLeakNodeContent()
        throws Exception {

        Document secretDoc = getDocument(SECRET_XML);
        Node secretNode =
            secretDoc.getDocumentElement().getFirstChild().getFirstChild();
        assertEquals(SECRET, secretNode.getNodeValue());

        Transforms transforms = createXPathTransforms("self::text()[");
        XMLSignatureInput output =
            transforms.performTransforms(new XMLSignatureInput(secretDoc));
        NodeFilter filter = (NodeFilter) output.getNodeFilters().get(0);
        try {
            filter.isNodeInclude(secretNode);
            fail("Expected an XMLSecurityRuntimeException");
        } catch (XMLSecurityRuntimeException ex) {
            assertNoLeak(ex);
            assertEquals("signature.Transform.XPathError", ex.getMsgID());
        }
    }

    /**
     * Converting a non-wellformed octet stream to a node-set for the XPath
     * Transform must not chain the parser error, which discloses its content.
     */
    public void testNodeSetConversionErrorDoesNotLeakContent()
        throws Exception {

        Transforms transforms = createXPathTransforms("self::node()");
        XMLSignatureInput input = new XMLSignatureInput(
            ("<root>&" + SECRET + ";</root>").getBytes("UTF-8"));
        try {
            transforms.performTransforms(input);
            fail("Expected an XMLSecurityRuntimeException");
        } catch (XMLSecurityRuntimeException ex) {
            assertNoLeak(ex);
            assertEquals("signature.XMLSignatureInput.nodesetReference",
                         ex.getMsgID());
        }
    }

    private static Transforms createXPathTransforms(String xpath)
        throws Exception {

        Document doc = getDocument(
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>");
        Transforms transforms = new Transforms(doc);
        XPathContainer xc = new XPathContainer(doc);
        xc.setXPathNamespaceContext("xmlns:ext", "http://www.example.org/ext");
        xc.setXPath(xpath);
        transforms.addTransform(Transforms.TRANSFORM_XPATH, xc.getElement());
        return transforms;
    }

    private static Document getDocument(String xml) throws Exception {
        DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
        dfactory.setNamespaceAware(true);
        DocumentBuilder db = dfactory.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
    }

    private static void assertNoLeak(XMLSecurityRuntimeException ex) {
        StringWriter sw = new StringWriter();
        ex.printStackTrace(new PrintWriter(sw));
        String reported = ex.getMessage() + "\n" + ex.toString() + "\n"
            + sw.toString();
        assertTrue("Exception discloses document content: " + reported,
                   reported.indexOf(SECRET) == -1);
    }

    static {
        org.apache.xml.security.Init.init();
    }
}
