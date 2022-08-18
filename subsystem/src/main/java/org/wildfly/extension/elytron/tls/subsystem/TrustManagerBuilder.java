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

import java.security.KeyStore;

import javax.net.ssl.TrustManager;

import org.wildfly.common.function.ExceptionSupplier;

public class TrustManagerBuilder {
    private ExceptionSupplier<KeyStore, Exception> keyStoreSupplier;
    private String keyStoreReferenceName;
    private String aliasFilter;
    private String algorithm;
    private int maximumCertPath;
    private boolean onlyLeafCert;
    private boolean softFail;
    private String providerName;

    private String ocspResponder;
    private boolean preferCrls;
    private String responderCertificate;
    private ExceptionSupplier<KeyStore, Exception> responderKeyStore;


    public TrustManagerBuilder() {

    }

    public TrustManager build() {


        return null;
    }

}
