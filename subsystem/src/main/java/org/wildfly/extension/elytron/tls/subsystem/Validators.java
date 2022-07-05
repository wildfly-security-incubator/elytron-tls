/*
 * Copyright 2022 Red Hat, Inc.
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

import static org.wildfly.extension.elytron.tls.subsystem._private.ElytronTLSLogger.LOGGER;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.operations.validation.ModelTypeValidator;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.wildfly.security.ssl.CipherSuiteSelector;

public class Validators {

    static class CipherSuiteFilterValidator extends ModelTypeValidator {

        CipherSuiteFilterValidator() {
            super(ModelType.STRING, true, true, false);
        }

        @Override
        public void validateParameter(String parameterName, ModelNode value) throws OperationFailedException {
            super.validateParameter(parameterName, value);
            if (value.isDefined()) {
                try {
                    CipherSuiteSelector.fromString(value.asString());
                } catch (IllegalArgumentException e) {
                    throw LOGGER.invalidCipherSuiteFilter(e, e.getLocalizedMessage());
                }
            }
        }
    }
    static class CipherSuiteNamesValidator extends ModelTypeValidator {

        CipherSuiteNamesValidator() {
            super(ModelType.STRING, true, true, false);
        }

        @Override
        public void validateParameter(String parameterName, ModelNode value) throws OperationFailedException {
            super.validateParameter(parameterName, value);
            if (value.isDefined()) {
                try {
                    CipherSuiteSelector.fromNamesString(value.asString());
                } catch (IllegalArgumentException e) {
                    throw LOGGER.invalidCipherSuiteNames(e, e.getLocalizedMessage());
                }
            }
        }
    }
}
