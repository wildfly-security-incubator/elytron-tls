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

import org.wildfly.extension.elytron.common.ElytronCommonConstants;

/**
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
interface Constants extends ElytronCommonConstants {
    String ELYTRON_SECURITY = "elytron-security";
    String KEY_MANAGER_ALIAS_FILTER = "key-manager-alias-filter";
    String KEY_MANAGER_PROVIDER_NAME = "key-manager-provider-name";
    String KEY_MANAGER_PROVIDERS = "key-manager-providers";
    String KEY_STORE_CONFIGURATION = "key-store-configuration";
    String SSL_CONTEXT_REGISTRATION = "ssl-context-registration";
    String TRUST_MANAGER_ALIAS_FILTER = "trust-manager-alias-filter";
    String TRUST_MANAGER_PROVIDER_NAME = "trust-manager-provider-name";
    String TRUST_MANAGER_PROVIDERS = "trust-manager-providers";
    String TRUST_STORE = "trust-store";
    String TRUST_STORE_CONFIGURATION = "trust-store-configuration";
}

