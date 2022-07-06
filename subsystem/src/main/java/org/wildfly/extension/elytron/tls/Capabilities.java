/*
 * Copyright 2023 Red Hat, Inc.
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

package org.wildfly.extension.elytron.tls;

import static org.wildfly.extension.elytron.common.ElytronCommonDefinitions.commonRequirements;
import static org.wildfly.extension.elytron.tls.ElytronTlsExtension.BASE_SERVICE_NAME;

import java.util.function.Consumer;

import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.msc.service.ServiceBuilder;
import org.wildfly.extension.elytron.common.ElytronCommonCapabilities;

/**
 * The capabilities provided by and required by this subsystem.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
class Capabilities extends ElytronCommonCapabilities {

    static final String ELYTRON_TLS_CAPABILITY = CAPABILITY_BASE + "elytron";

    // This has to be at this position, and must not be a lambda, to avoid an init circularity problem on IBM
    @SuppressWarnings("Convert2Lambda")
    static Consumer<ServiceBuilder> COMMON_REQUIREMENTS = new Consumer<ServiceBuilder>() {
        @Override
        // unchecked because ServiceBuilder is a raw type
        @SuppressWarnings("unchecked")
        public void accept(ServiceBuilder serviceBuilder) {
            commonRequirements(BASE_SERVICE_NAME, serviceBuilder, true, true);
        }
    };

    static final RuntimeCapability<Consumer<ServiceBuilder>> ELYTRON_TLS_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(ELYTRON_TLS_CAPABILITY, COMMON_REQUIREMENTS).build();
}
