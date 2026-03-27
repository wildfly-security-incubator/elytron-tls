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

package org.wildfly.extension.elytron.tls;

interface Constants {
    String ACCOUNT_KEY = "account-key";
    String ACTIVE_SESSION_COUNT = "active-session-count";
    String ADD_ALIAS = "add-alias";
    String AGREE_TO_TERMS_OF_SERVICE = "agree-to-terms-of-service";
    String AGGREGATE_PROVIDERS = "aggregate-providers";
    String ALIAS = "alias";
    String ALIAS_ATTRIBUTE = "alias-attribute";
    String ALIAS_FILTER = "alias-filter";
    String ALGORITHM = "algorithm";
    String APPLICATION_BUFFER_SIZE = "application-buffer-size";
    String APPLICATION_CONTEXT = "application-context";
    String ARGUMENT = "argument";
    String AUTHENTICATION_OPTIONAL = "authentication-optional";

    String CAA_IDENTITIES = "caa-identities";
    String CERTIFICATE = "certificate";
    String CERTIFICATE_ATTRIBUTE = "certificate-attribute";
    String CERTIFICATE_AUTHORITY = "certificate-authority";
    String CERTIFICATE_AUTHORITIES = "certificate-authorities";
    String CERTIFICATE_AUTHORITY_ACCOUNT = "certificate-authority-account";
    String CERTIFICATE_AUTHORITY_ACCOUNTS = "certificate-authority-accounts";
    String CERTIFICATE_CHAIN = "certificate-chain";
    String CERTIFICATE_CHAIN_ATTRIBUTE = "certificate-chain-attribute";
    String CERTIFICATE_CHAIN_ENCODING = "certificate-chain-encoding";
    String CERTIFICATE_TYPE = "certificate-type";
    String CERTIFICATE_REVOCATION_LIST = "certificate-revocation-list";
    String CERTIFICATE_REVOCATION_LISTS = "certificate-revocation-lists";
    String CHANGE_ACCOUNT_KEY = "change-account-key";
    String CHANGE_ALIAS = "change-alias";
    String CIPHER_SUITE = "cipher-suite";
    String CIPHER_SUITE_FILTER = "cipher-suite-filter";
    String CIPHER_SUITE_NAMES = "cipher-suite-names";
    String CLASS_LOADING = "class-loading";
    String CLASS_NAME = "class-name";
    String CLASS_NAMES = "class-names";
    String CLEAR_TEXT = "clear-text";
    String CLIENT_SSL_CONTEXT = "client-ssl-context";
    String CLIENT_SSL_CONTEXTS = "client-ssl-contexts";
    String CONFIGURATION = "configuration";
    String CONTACT_URLS = "contact-urls";
    String CREATE = "create";
    String CREATE_ACCOUNT = "create-account";
    String CREATE_EXPRESSION = "create-expression";
    String CREATION_DATE = "creation-date";
    String CREATION_TIME = "creation-time";
    String CREDENTIAL_STORE = "credential-store";
    String CREDENTIAL_STORES = "credential-stores";
    String CRITICAL = "critical";
    String CUSTOM_PERMISSION_MAPPER = "custom-permission-mapper";

    String DAYS_TO_EXPIRY = "days-to-expiry";
    String DEACTIVATE_ACCOUNT = "deactivate-account";
    String DEFAULT_ALIAS = "default-alias";
    String DEFAULT_RESOLVER = "default-resolver";
    String DEFAULT_SSL_CONTEXT = "default-ssl-context";
    String DESCRIPTION = "description";
    String DISALLOWED_PROVIDERS = "disallowed-providers";
    String DISTINGUISHED_NAME = "distinguished-name";
    String DOMAIN_NAMES = "domain-names";

    String ENCODED = "encoded";
    String ENCRYPTION = "encryption";
    String ENTRY_TYPE = "entry-type";
    String EXPIRATION = "expiration";
    String EXPORT_CERTIFICATE = "export-certificate";
    String EXPORT_SECRET_KEY = "export-secret-key";
    String EXPRESSION = "expression";
    String EXPRESSION_RESOLVER = "expression-resolver";
    String EXTERNAL_ACCOUNT_REQUIRED = "external-account-required";
    String EXTENSION = "extension";
    String EXTENSIONS = "extensions";

    String FILE = "file";
    String FILTER_ALIAS = "filter-alias";
    String FILTER_CERTIFICATE = "filter-certificate";
    String FILTER_ITERATE = "filter-iterate";
    String FILTERING_KEY_STORE = "filtering-key-store";
    String FINAL_PROVIDERS = "final-providers";
    String FLAG = "flag";
    String FORMAT = "format";

    String GENERATE_CERTIFICATE_SIGNING_REQUEST = "generate-certificate-signing-request";
    String GENERATE_KEY_PAIR = "generate-key-pair";
    String GENERATE_SECRET_KEY = "generate-secret-key";
    String GENERATE_SELF_SIGNED_CERTIFICATE_HOST = "generate-self-signed-certificate-host";
    String GET_METADATA = "get-metadata";

    String HOST_NAME = "host-name";

    String IMPLEMENTATION = "implementation";
    String IMPLEMENTATION_PROPERTIES = "implementation-properties";
    String IMPORT_CERTIFICATE = "import-certificate";
    String IMPORT_SECRET_KEY = "import-secret-key";
    String INDEX = "index";
    String INFO = "info";
    String INIT = "init";
    String INITIAL_PROVIDERS = "initial-providers";
    String INVALIDATE = "invalidate";
    String ISSUER = "issuer";

    String JASPI_CONFIGURATION = "jaspi-configuration";

    String KEY = "key";
    String KEY_ATTRIBUTE = "key-attribute";
    String KEY_TYPE = "key-type";
    String KEY_MANAGER = "key-manager";
    String KEY_MANAGER_OBJECT = "key-manager-object";
    String KEY_MANAGERS = "key-managers";
    String KEY_SIZE = "key-size";
    String KEY_STORE = "key-store";
    String KEY_STORE_OBJECT = "key-store-object";
    String KEY_STORES = "key-stores";

    String LAST_ACCESSED_TIME = "last-accessed-time";
    String LAYER = "layer";
    String LDAP_KEY_STORE = "ldap-key-store";
    String LOAD = "load";
    String LOAD_SERVICES = "load-services";
    String LOADED_PROVIDER = "loaded-provider";
    String LOADED_PROVIDERS = "loaded-providers";
    String LOCAL_CERTIFICATES = "local-certificates";
    String LOCAL_PRINCIPAL = "local-principal";
    String LOCATION = "location";

    String MAXIMUM_CERT_PATH = "maximum-cert-path";
    String MAXIMUM_SESSION_CACHE_SIZE = "maximum-session-cache-size";
    String MECHANISM_CONFIGURATIONS = "mechanism-configurations";
    String MECHANISM_NAME = "mechanism-name";
    String MODIFIABLE = "modifiable";
    String MODIFIABLE_KEY_STORE = "modifiable-key-store";
    String MODIFIED = "modified";
    String MODULE = "module";

    String NAME = "name";
    String NEED_CLIENT_AUTH = "need-client-auth";
    String NEW_ALIAS = "new-alias";
    String NEW_ITEM_ATTRIBUTES = "new-item-attributes";
    String NEW_ITEM_TEMPLATE = "new-item-template";
    String NEW_ITEM_PATH = "new-item-path";
    String NEW_ITEM_RDN = "new-item-rdn";
    String NOT_AFTER = "not-after";
    String NOT_BEFORE = "not-before";

    String OBTAIN_CERTIFICATE = "obtain-certificate";
    String OCSP = "ocsp";
    String ONLY_LEAF_CERT = "only-leaf-cert";
    String OPERATIONS = "operations";
    String OTHER_PROVIDERS = "other-providers";
    String OPTIONS = "options";
    String OR = "or";

    String PACKET_BUFFER_SIZE = "packet-buffer-size";
    String PATH = "path";
    String PEER_CERTIFICATES = "peer-certificates";
    String PEER_HOST = "peer-host";
    String PEER_PORT = "peer-port";
    String PEER_PRINCIPAL = "peer-principal";
    String PEM = "pem";
    String POPULATE = "populate";
    String PREFER_CRLS = "prefer-crls";
    String PREFIX = "prefix";
    String PROPERTY = "property";
    String PROPERTY_LIST = "property-list";
    String PROTOCOL = "protocol";
    String PROTOCOLS = "protocols";
    String PROVIDER = "provider";
    String PROVIDER_LOADER = "provider-loader";
    String PROVIDER_NAME = "provider-name";
    String PROVIDER_REGISTRATION = "provider-registration";
    String PROVIDERS = "providers";
    String PUBLIC_KEY = "public-key";

    String READ_ALIAS = "read-alias";
    String READ_ALIASES = "read-aliases";
    String REASON = "reason";
    String RECURSIVE = "recursive";
    String RELATIVE_TO = "relative-to";
    String RELOAD = "reload";
    String RELOAD_CERTIFICATE_REVOCATION_LIST = "reload-certificate-revocation-list";
    String REMOVE_ALIAS = "remove-alias";
    String REQUIRED = "required";
    String RESOLVER = "resolver";
    String RESOLVERS = "resolvers";
    String RESPONDER = "responder";
    String RESPONDER_CERTIFICATE = "responder-certificate";
    String RESPONDER_KEYSTORE = "responder-keystore";
    String RESPONDER_KEYSTORE_OBJECT = "responder-keystore-object";
    String REVOKE_CERTIFICATE = "revoke-certificate";

    String SASL_AUTHENTICATION_FACTORY = "sasl-authentication-factory";
    String SEARCH_PATH = "search-path";
    String SEARCH_RECURSIVE = "search-recursive";
    String SEARCH_TIME_LIMIT = "search-time-limit";
    String SECURITY_PROPERTIES = "security-properties";
    String SECURITY_PROPERTY = "security-property";
    String SECRET_KEY = "secret-key";
    String SECRET_KEY_CREDENTIAL_STORE = "secret-key-credential-store";
    String SECRET_VALUE = "secret-value";
    String SERIAL_NUMBER = "serial-number";
    String SERVER_AUTH_MODULES = "server-auth-modules";
    String SERVER_SSL_CONTEXT = "server-ssl-context";
    String SERVER_SSL_CONTEXTS = "server-ssl-contexts";
    String SERVER_SSL_SNI_CONTEXT = "server-ssl-sni-context";
    String SERVER_SSL_SNI_CONTEXTS = "server-ssl-sni-contexts";
    String SESSION_TIMEOUT = "session-timeout";
    String SET_SECRET = "set-secret";
    String SERVICE = "service";
    String SERVICES = "services";
    String SHA_1_DIGEST = "sha-1-digest";
    String SHA_256_DIGEST = "sha-256-digest";
    String SHOULD_RENEW_CERTIFICATE = "should-renew-certificate";
    String SIGNATURE = "signature";
    String SIGNATURE_ALGORITHM = "signature-algorithm";
    String SIZE = "size";
    String SSL_CONTEXT_REGISTRATION = "ssl-context-registration";
    String SSL_SESSION = "ssl-session";
    String SOFT_FAIL = "soft-fail";
    String STAGING = "staging";
    String STAGING_URL = "staging-url";
    String STATE = "state";
    String STORE = "store";
    String SUBJECT = "subject";
    String SYNCHRONIZED = "synchronized";

    String TERMS_OF_SERVICE = "terms-of-service";
    String TLS = "tls";
    String TRUST_CACERTS = "trust-cacerts";
    String TRUST_MANAGER = "trust-manager";
    String TRUST_MANAGER_OBJECT = "trust-manager-object";
    String TRUST_MANAGERS = "trust-managers";
    String TYPE = "type";

    String UPDATE_ACCOUNT = "update-account";
    String URL = "url";
    String USE_CIPHER_SUITES_ORDER = "use-cipher-suites-order";

    String VALID = "valid";
    String VALIDATE = "validate";
    String VALIDITY = "validity";
    String VALUE = "value";
    String VERBOSE = "verbose";
    String VERSION = "version";

    String WANT_CLIENT_AUTH = "want-client-auth";
    String WEBSITE = "website";
    String WRAP = "wrap";
}

