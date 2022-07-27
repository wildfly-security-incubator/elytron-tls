/*
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.extension.elytron.tls.subsystem;

import java.io.IOException;
import java.util.List;

import org.jboss.as.subsystem.test.AbstractSubsystemBaseTest;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:kabir.khan@jboss.com">Kabir Khan</a>
 */
public class ElytronTlsSubsystemTestCase extends AbstractSubsystemBaseTest {

    public ElytronTlsSubsystemTestCase() {
        super(ElytronTlsExtension.SUBSYSTEM_NAME, new ElytronTlsExtension());
    }

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("elytron-tls-subsystem-test.xml");
    }

    @Override
    protected String getSubsystemXsdPath() {
        return ElytronTlsExtension.getCurrentXsdPath();
    }

    @Test
    public void testParseAndMarshalModel_TLS() throws Exception {
        standardSubsystemTest("tls.xml");
    }

    @Test
    public void testDisallowedProviders() throws Exception {
        KernelServices services = standardSubsystemTest("providers.xml", true);
        List<ModelNode> disallowedProviders = services.readWholeModel().get("subsystem", "elytron-tls", "disallowed-providers").asList();
        Assert.assertNotNull(disallowedProviders);
        Assert.assertEquals(3, disallowedProviders.size());
    }

    protected AdditionalInitialization createAdditionalInitialization() {
        // Our use of the expression=encryption resource requires kernel capability setup that TestEnvironment provides
        return TestEnvironment.asAdmin();
    }

}
