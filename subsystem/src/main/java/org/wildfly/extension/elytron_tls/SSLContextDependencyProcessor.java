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

package org.wildfly.extension.elytron_tls;

import javax.net.ssl.SSLContext;

import org.jboss.as.server.deployment.DeploymentPhaseContext;
import org.jboss.as.server.deployment.DeploymentUnitProcessor;

/**
 * A simple {@link DeploymentUnitProcessor} to ensure deployments wait until the default {@link SSLContext} has been registered.
 *
 * @implNote This implementation should mirror the same class in {@code org.wildfly.core:wildfly-elytron-integration}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class SSLContextDependencyProcessor implements DeploymentUnitProcessor {

    /**
     * @see org.jboss.as.server.deployment.DeploymentUnitProcessor#deploy(org.jboss.as.server.deployment.DeploymentPhaseContext)
     */
    @Override
    public void deploy(DeploymentPhaseContext phaseContext) {
        phaseContext.addDeploymentDependency(DefaultSSLContextService.SERVICE_NAME, ElytronTlsExtension.SSL_CONTEXT_KEY);
    }

}
