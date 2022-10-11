/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.extension.elytron.tls.subsystem;


import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.jboss.as.controller.RunningMode;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.subsystem.test.AbstractSubsystemBaseTest;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.as.subsystem.test.KernelServicesBuilder;
import org.jboss.dmr.ModelNode;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Verifies that attributes that allow expressions resolve them correctly.
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class ResolveExpressionAttributesTestCase extends AbstractSubsystemBaseTest {

    private ModelNode serverModel;

    public ResolveExpressionAttributesTestCase() {
        super(ElytronTlsExtension.SUBSYSTEM_NAME, new ElytronTlsExtension());
    }

    @Before
    public void init() throws Exception {
        KernelServicesBuilder builder = createKernelServicesBuilder(createAdditionalInitialization())
                .setSubsystemXml(getSubsystemXml());
        KernelServices kernelServices = builder.build();
        Assert.assertTrue("Subsystem boot failed!", kernelServices.isSuccessfulBoot());
        ModelNode rootModel = kernelServices.readWholeModel();
        serverModel =  rootModel.require(ModelDescriptionConstants.SUBSYSTEM).require(ElytronTlsExtension.SUBSYSTEM_NAME);
    }

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("elytron-tls-expressions.xml");
    }

    @Override
    protected AdditionalInitialization createAdditionalInitialization() {
        // Our use of the expression=encryption resource requires kernel capability setup that TestEnvironment provides
        return new TestEnvironment(RunningMode.ADMIN_ONLY);
    }

    @Test
    public void testExpressionAttributesResolved() {
        testCertificateAuthorityAccount();
        testCertificateAuthority();
        testCredentialStore();
        // testCustomComponent();
        testElytronTlsDefinition();
        // testFilteringKeyStoreDefinition();
        testKeyStore();
        // testLdapKeyStore();
        testProvider();
        // testSaslServer();
        testTLSComponents();
    }

    private void testCertificateAuthorityAccount() {
        ModelNode caAccount = serverModel.get(Constants.CERTIFICATE_AUTHORITY_ACCOUNT).get("MyCA");
        assertEquals(Arrays.asList("https://www.test.com"), getValue(caAccount, Constants.CONTACT_URLS, true));
        assertEquals("LetsEncrypt", getValue(caAccount, Constants.CERTIFICATE_AUTHORITY));
        assertEquals("server", getValue(caAccount, Constants.ALIAS));
    }

    private void testCertificateAuthority() {
        ModelNode ca = serverModel.get(Constants.CERTIFICATE_AUTHORITY).get("testCA");
        assertEquals("https://www.test.com", getValue(ca, Constants.STAGING_URL));
        assertEquals("https://www.test.com", getValue(ca, Constants.URL));
    }

    private void testCredentialStore() {
        // Credential Stores
        ModelNode cs = serverModel.get(Constants.CREDENTIAL_STORE).get("test1");
        assertEquals("test1.store", getValue(cs, Constants.LOCATION));
        assertEquals("JCEKS", getValue(cs, Constants.TYPE));
        assertEquals("provider", getValue(cs, Constants.PROVIDER_NAME));
        cs = cs.get(Constants.IMPLEMENTATION_PROPERTIES);
        assertEquals("JCEKS", getValue(cs, "keyStoreType"));
        cs = serverModel.get(Constants.CREDENTIAL_STORE).get("test4");
        assertEquals("test1.store", getValue(cs, Constants.PATH));

        // Secret Credential Store
        cs = serverModel.get(Constants.SECRET_KEY_CREDENTIAL_STORE).get("test3");
        assertEquals("false", getValue(cs, Constants.CREATE));
        assertEquals("false", getValue(cs, Constants.POPULATE));
        assertEquals("192", getValue(cs, Constants.KEY_SIZE));
        assertEquals("test3", getValue(cs, Constants.DEFAULT_ALIAS));
    }

    private void testCustomComponent() {
        // TODO: is there a different custom component that could go here?
        // Using custom permission mapper as example
        ModelNode mapper = serverModel.get(Constants.CUSTOM_PERMISSION_MAPPER).get("MyPermissionMapper");
        assertEquals("value", getValue(mapper.get(Constants.CONFIGURATION), "test"));
    }

    private void testElytronTlsDefinition() {
        assertEquals(Arrays.asList("test"), getValue(serverModel, Constants.DISALLOWED_PROVIDERS, true));
        // assertEquals("false", getValue(serverModel, Constants.REGISTER_JASPI_FACTORY));
    }

    private void testFilteringKeyStoreDefinition() {
        ModelNode keystore = serverModel.get(Constants.FILTERING_KEY_STORE).get("FilteringKeyStore");
        assertEquals("NONE:+firefly", getValue(keystore, Constants.ALIAS_FILTER));
    }

    private void testJaspiConfiguration() {
        ModelNode jaspi = serverModel.get(Constants.JASPI_CONFIGURATION).get("test");
        assertEquals("HttpServlet", getValue(jaspi, Constants.LAYER));
        assertEquals("default /test", getValue(jaspi, Constants.APPLICATION_CONTEXT));
        assertEquals("Test Definition", getValue(jaspi, Constants.DESCRIPTION));

        ModelNode testModule = jaspi.get(Constants.SERVER_AUTH_MODULES).get(0);
        assertEquals("REQUISITE", getValue(testModule, Constants.FLAG));

        ModelNode options = testModule.get(Constants.OPTIONS);
        assertEquals("b", getValue(options, "a"));
    }

    private void testKeyStore() {
        ModelNode keystore = serverModel.get(Constants.KEY_STORE).get("jks_store");
        assertEquals("jks", getValue(keystore, Constants.TYPE));
        assertEquals("SunJSSE", getValue(keystore, Constants.PROVIDER_NAME));
        assertEquals("one,two,three", getValue(keystore, Constants.ALIAS_FILTER));
        assertEquals("true", getValue(keystore, Constants.REQUIRED));
    }

    private void testLdapKeyStore() {
        ModelNode keystore = serverModel.get(Constants.LDAP_KEY_STORE).get("LdapKeyStore");

        // search
        assertEquals("dc=elytron,dc=wildfly,dc=org", getValue(keystore, Constants.SEARCH_PATH));
        assertEquals("true", getValue(keystore, Constants.SEARCH_RECURSIVE));
        assertEquals("1000", getValue(keystore, Constants.SEARCH_TIME_LIMIT));
        assertEquals("(&(objectClass=inetOrgPerson)(sn={0}))", getValue(keystore, Constants.FILTER_ALIAS));
        assertEquals("(&(objectClass=inetOrgPerson)(usercertificate={0}))", getValue(keystore, Constants.FILTER_CERTIFICATE));
        assertEquals("(sn=serenity*)", getValue(keystore, Constants.FILTER_ITERATE));

        // attribute mapping
        assertEquals("sn", getValue(keystore, Constants.ALIAS_ATTRIBUTE));
        assertEquals("usercertificate", getValue(keystore, Constants.CERTIFICATE_ATTRIBUTE));
        assertEquals("X.509", getValue(keystore, Constants.CERTIFICATE_TYPE));
        assertEquals("userSMIMECertificate", getValue(keystore, Constants.CERTIFICATE_CHAIN_ATTRIBUTE));
        assertEquals("PKCS7", getValue(keystore, Constants.CERTIFICATE_CHAIN_ENCODING));
        assertEquals("userPKCS12", getValue(keystore, Constants.KEY_ATTRIBUTE));
        assertEquals("PKCS12", getValue(keystore, Constants.KEY_TYPE));

        // new item template
        ModelNode template = keystore.get(Constants.NEW_ITEM_TEMPLATE);
        assertEquals("ou=keystore,dc=elytron,dc=wildfly,dc=org", getValue(template, Constants.NEW_ITEM_PATH));
        assertEquals("cn", getValue(template, Constants.NEW_ITEM_RDN));
        assertEquals("objectClass", getValue(template.get(Constants.NEW_ITEM_ATTRIBUTES).get(0), Constants.NAME));
        assertEquals(Arrays.asList("top", "inetOrgPerson"), getValue(template.get(Constants.NEW_ITEM_ATTRIBUTES).get(0), Constants.VALUE, true));
    }


    private void testProvider() {
        ModelNode provider = serverModel.get(Constants.PROVIDER_LOADER).get("openssl");
        assertEquals("val", getValue(provider.get(Constants.CONFIGURATION), "prop"));
        provider = serverModel.get(Constants.PROVIDER_LOADER).get("elytron");
        assertEquals("arg", getValue(provider, Constants.ARGUMENT));
    }

    private void testSaslServer() {
        ModelNode factory = serverModel.get(Constants.SASL_AUTHENTICATION_FACTORY).get("SaslAuthenticationDefinition").get(Constants.MECHANISM_CONFIGURATIONS).get(0);
        assertEquals("PLAIN", getValue(factory, Constants.MECHANISM_NAME));
        assertEquals("host", getValue(factory, Constants.HOST_NAME));
        assertEquals("protocol", getValue(factory, Constants.PROTOCOL));
    }

    private void testTLSComponents() {
        // SSL Context
        ModelNode context = serverModel.get(Constants.SERVER_SSL_CONTEXT).get("server");
        assertEquals(Arrays.asList("TLSv1.2"), getValue(context, Constants.PROTOCOLS, true));
        assertEquals("true", getValue(context, Constants.WANT_CLIENT_AUTH));
        assertEquals("true", getValue(context, Constants.NEED_CLIENT_AUTH));
        assertEquals("true", getValue(context, Constants.AUTHENTICATION_OPTIONAL));
        assertEquals("false", getValue(context, Constants.USE_CIPHER_SUITES_ORDER));
        assertEquals("false", getValue(context, Constants.WRAP));
        assertEquals("first", getValue(context, Constants.PROVIDER_NAME));
        assertEquals("DEFAULT", getValue(context, Constants.CIPHER_SUITE_FILTER));
        assertEquals("name", getValue(context, Constants.CIPHER_SUITE_NAMES));
        assertEquals("10", getValue(context, Constants.MAXIMUM_SESSION_CACHE_SIZE));
        assertEquals("120", getValue(context, Constants.SESSION_TIMEOUT));

        // Trust Managers
        ModelNode tm = serverModel.get(Constants.TRUST_MANAGER).get("trust-with-ocsp").get(Constants.OCSP);
        assertEquals("http://localhost/ocsp", getValue(tm, Constants.RESPONDER));
        assertEquals("jceks_store", getValue(tm, Constants.RESPONDER_KEYSTORE));
        assertEquals("responder-alias", getValue(tm, Constants.RESPONDER_CERTIFICATE));

        tm = serverModel.get(Constants.TRUST_MANAGER).get("trust-with-crl").get(Constants.CERTIFICATE_REVOCATION_LIST);
        assertEquals("crl.pem", getValue(tm, Constants.PATH));
        assertEquals("2", getValue(tm, Constants.MAXIMUM_CERT_PATH));

        // Key Managers
        ModelNode keyManager = serverModel.get(Constants.KEY_MANAGER).get("serverKey2");
        assertEquals("SunX509", getValue(keyManager, Constants.ALGORITHM));
        assertEquals("one,two,three", getValue(keyManager, Constants.ALIAS_FILTER));
        assertEquals("localhost", getValue(keyManager, Constants.GENERATE_SELF_SIGNED_CERTIFICATE_HOST));
    }

    private Object getValue(ModelNode node, String attributeName) {
        return getValue(node, attributeName, false);
    }

    private Object getValue(ModelNode node, String attributeName, boolean isList) {
        ModelNode result = node.get(attributeName).resolve();
        if (! isList) {
            return result.asString();
        }
        List<String> results = new ArrayList<>();
        for (ModelNode n : result.asList()) {
            results.add(n.asString());
        }
        return results;
    }
}
