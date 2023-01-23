/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.extension.elytron.tls;

import java.io.IOException;
import java.util.List;

import org.jboss.as.subsystem.test.AbstractSubsystemBaseTest;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Tests all management expects for subsystem, parsing, marshaling, model definition and other
 * Here is an example that allows you a fine grained controller over what is tested and how. So it can give you ideas what can be done and tested.
 * If you have no need for advanced testing of subsystem you look at {@link ElytronTlsSubsystem1_0TestCase} that tests same stuff but most of the code
 * is hidden inside of test harness
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class SubsystemParsingTestCase extends AbstractSubsystemBaseTest {

    public SubsystemParsingTestCase() {
        super(ElytronTlsExtension.SUBSYSTEM_NAME, new ElytronTlsExtension());
    }

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("elytron-tls-subsystem-1.0.xml");
    }

    @Test
    public void testParseAndMarshalModel_TLS() throws Exception {
        standardSubsystemTest("tls.xml");
    }

    @Test
    public void testParseAndMarshalModel_ProviderLoader() throws Exception {
        standardSubsystemTest("providers.xml");
    }

    @Test
    public void testDisallowedProviders() throws Exception {
        KernelServices services = standardSubsystemTest("providers.xml", true);
        List<ModelNode> disallowedProviders = services.readWholeModel().get("subsystem", "elytron-tls", "disallowed-providers").asList();
        Assert.assertNotNull(disallowedProviders);
        Assert.assertEquals(3, disallowedProviders.size());
    }

    @Ignore("to be determined if needed")
    @Test
    public void testParseAndMarshalModel_Sasl() throws Exception {
        standardSubsystemTest("sasl.xml");
    }

    @Test
    public void testParseAndMarshalModel_SecurityProperties() throws Exception {
        standardSubsystemTest("security-properties.xml");
    }

    @Test
    public void testParseAndMarshalModel_CredentialStores() throws Exception {
        standardSubsystemTest("credential-stores.xml");
    }

    @Ignore("to be determined if needed")
    @Test
    public void testParseAndMarshalModel_JASPI() throws Exception {
        standardSubsystemTest("jaspi.xml");
    }

    @Override
    protected AdditionalInitialization createAdditionalInitialization() {
        return AdditionalInitialization.MANAGEMENT;
    }


}
