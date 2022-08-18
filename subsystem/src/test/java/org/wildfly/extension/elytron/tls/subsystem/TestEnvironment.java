/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2016 Red Hat, Inc. and/or its affiliates.
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

import org.jboss.as.controller.capability.registry.RuntimeCapabilityRegistry;
import org.jboss.as.controller.extension.ExtensionRegistry;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.subsystem.test.AdditionalInitialization;

class TestEnvironment {
    // TODO: Re-add LDAP configuration

    /**
     * Creates an {@link AdditionalInitialization} with the Weld {@link org.jboss.as.controller.capability.RuntimeCapability capability},
     * operating in {@link org.jboss.as.controller.RunningMode#ADMIN_ONLY RunningMode.ADMIN_ONLY}.
     *
     * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
     */
    static AdditionalInitialization asAdmin() {
        return AdditionalInitialization.withCapabilities(ElytronTlsExtension.WELD_CAPABILITY_NAME);
    }

    /**
     * Creates an {@link AdditionalInitialization} with the Weld {@link org.jboss.as.controller.capability.RuntimeCapability capability},
     * operating in {@link org.jboss.as.controller.RunningMode#NORMAL RunningMode.NORMAL}.
     *
     * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
     */
    static AdditionalInitialization asNormal() {
        return new AdditionalInitialization() {
            @Override
            protected void initializeExtraSubystemsAndModel(ExtensionRegistry extensionRegistry, Resource rootResource,
                                                            ManagementResourceRegistration rootRegistration, RuntimeCapabilityRegistry capabilityRegistry) {
                super.initializeExtraSubystemsAndModel(extensionRegistry, rootResource, rootRegistration, capabilityRegistry);
                registerCapabilities(capabilityRegistry, ElytronTlsExtension.WELD_CAPABILITY_NAME);
            }
        };
    }
}
