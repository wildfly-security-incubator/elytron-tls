/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import static org.wildfly.extension.elytron.tls.ClassLoadingAttributeDefinitions.CLASS_NAMES;
import static org.wildfly.extension.elytron.tls.ClassLoadingAttributeDefinitions.MODULE;

import java.security.Provider;
import java.security.Provider.Service;

import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectListAttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;

/**
 * Class to contain the attribute definition for the runtime representation of a security provider.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ProviderAttributeDefinition {

    private static final SimpleAttributeDefinition NAME = new SimpleAttributeDefinitionBuilder(Constants.NAME, ModelType.STRING).build();

    private static final SimpleAttributeDefinition INFO = new SimpleAttributeDefinitionBuilder(Constants.INFO, ModelType.STRING).build();

    private static final SimpleAttributeDefinition VERSION = new SimpleAttributeDefinitionBuilder(Constants.VERSION, ModelType.DOUBLE).build();

    static final ObjectTypeAttributeDefinition LOADED_PROVIDER = new ObjectTypeAttributeDefinition.Builder(Constants.LOADED_PROVIDER, NAME, INFO, VERSION)
        .setStorageRuntime()
        .setRequired(false)
        .build();

    /*
     * Service Attributes and Full Definition.
     */

    private static final SimpleAttributeDefinition TYPE = new SimpleAttributeDefinitionBuilder(Constants.TYPE, ModelType.STRING).build();

    private static final SimpleAttributeDefinition ALGORITHM = new SimpleAttributeDefinitionBuilder(Constants.ALGORITHM, ModelType.STRING).build();

    private static final SimpleAttributeDefinition CLASS_NAME = new SimpleAttributeDefinitionBuilder(Constants.CLASS_NAME, ModelType.STRING)
        .setAllowExpression(false)
        .build();

    private static final ObjectTypeAttributeDefinition SERVICE = new ObjectTypeAttributeDefinition.Builder(Constants.SERVICE, TYPE, ALGORITHM, CLASS_NAME)
        .setRequired(true)
        .build();

    private static final ObjectListAttributeDefinition SERVICES = new ObjectListAttributeDefinition.Builder(Constants.SERVICES, SERVICE)
        .build();

    private static final ObjectTypeAttributeDefinition FULL_PROVIDER = new ObjectTypeAttributeDefinition.Builder(Constants.PROVIDER, NAME, INFO, VERSION, SERVICES)
        .setRequired(false)
        .build();

    static final ObjectListAttributeDefinition LOADED_PROVIDERS = new ObjectListAttributeDefinition.Builder(Constants.LOADED_PROVIDERS, FULL_PROVIDER)
        .setStorageRuntime()
        .setRequired(false)
        .build();

    /*
     *  Provider Configuration Attributes
     */

    private static final SimpleAttributeDefinition INDEX = new SimpleAttributeDefinitionBuilder(Constants.INDEX, ModelType.INT)
        .build();

    private static final SimpleAttributeDefinition LOAD_SERVICES = new SimpleAttributeDefinitionBuilder(Constants.LOAD_SERVICES, ModelType.BOOLEAN)
        .setAttributeGroup(Constants.CLASS_LOADING)
        .setAllowExpression(true)
        .setRequired(false)
        .setDefaultValue(ModelNode.FALSE)
        .build();

    private static final SimpleAttributeDefinition PROPERTY_NAME = new SimpleAttributeDefinitionBuilder(Constants.NAME, ModelType.STRING, false)
        .setAllowExpression(true)
        .setMinSize(1)
        .build();

    private static final SimpleAttributeDefinition VALUE = new SimpleAttributeDefinitionBuilder(Constants.VALUE, ModelType.STRING, false)
        .setAllowExpression(true)
        .setMinSize(1)
        .build();

    private static final AttributeDefinition[] PROPERTY_ATTRIBUTES = { PROPERTY_NAME, VALUE };

    private static final ObjectTypeAttributeDefinition PROPERTY = new ObjectTypeAttributeDefinition.Builder(Constants.PROPERTY, PROPERTY_ATTRIBUTES)
        .build();

    private static final AttributeDefinition[] INDEXED_PROPERTY_ATTRIBUTES = combine(INDEX, PROPERTY_ATTRIBUTES);

    private static final ObjectTypeAttributeDefinition INDEXED_PROPERTY = new ObjectTypeAttributeDefinition.Builder(Constants.PROPERTY, INDEXED_PROPERTY_ATTRIBUTES)
        .build();

    private static final ObjectListAttributeDefinition PROPERTY_LIST = new ObjectListAttributeDefinition.Builder(Constants.PROPERTY_LIST, PROPERTY)
        .setAttributeGroup(Constants.CONFIGURATION)
        .setAlternatives(Constants.PATH)
        .setAllowDuplicates(true)
        .setRequired(false)
        .build();

    private static final ObjectListAttributeDefinition INDEXED_PROPERTY_LIST = new ObjectListAttributeDefinition.Builder(Constants.PROPERTY_LIST, INDEXED_PROPERTY)
        .setAttributeGroup(Constants.CONFIGURATION)
        .setAlternatives(Constants.PATH)
        .setAllowDuplicates(true)
        .setRequired(false)
        .build();

    private static final SimpleAttributeDefinition PATH = new SimpleAttributeDefinitionBuilder(Constants.PATH, FileAttributeDefinitions.PATH)
        .setAttributeGroup(Constants.CONFIGURATION)
        .setAlternatives(Constants.PROPERTY_LIST)
        .build();

    private static final SimpleAttributeDefinition RELATIVE_TO = new SimpleAttributeDefinitionBuilder(Constants.RELATIVE_TO, FileAttributeDefinitions.RELATIVE_TO)
        .setAttributeGroup(Constants.CONFIGURATION)
        .build();

    private static final AttributeDefinition[] PROVIDER_ATTRIBUTES = { MODULE, LOAD_SERVICES, CLASS_NAMES, PATH, RELATIVE_TO };

    private static final ObjectTypeAttributeDefinition PROVIDER = new ObjectTypeAttributeDefinition.Builder(Constants.PROVIDER, combine(null, PROVIDER_ATTRIBUTES, PROPERTY_LIST))
        .build();

    private static final ObjectTypeAttributeDefinition INDEXED_PROVIDER = new ObjectTypeAttributeDefinition.Builder(Constants.PROVIDER, combine(INDEX, PROVIDER_ATTRIBUTES, INDEXED_PROPERTY_LIST))
        .build();

    static final ObjectListAttributeDefinition PROVIDERS = new ObjectListAttributeDefinition.Builder(Constants.PROVIDERS, PROVIDER)
        .setRequired(false)
        .build();

    static final ObjectListAttributeDefinition INDEXED_PROVIDERS = new ObjectListAttributeDefinition.Builder(Constants.PROVIDERS, INDEXED_PROVIDER)
        .setRequired(false)
        .build();


    private ProviderAttributeDefinition() {
    }

    /**
     * Populate the supplied response {@link ModelNode} with information about the supplied {@link Provider}
     *
     * @param response the response to populate.
     * @param provider the {@link Provider} to use when populating the response.
     */
    static void populateProvider(final ModelNode response, final Provider provider, final boolean includeServices) {
        response.get(Constants.NAME).set(provider.getName());
        response.get(Constants.INFO).set(provider.getInfo());
        response.get(Constants.VERSION).set(provider.getVersion());

        if (includeServices) {
            addServices(response, provider);
        }
    }

    /**
     * Populate the supplied response {@link ModelNode} with information about each {@link Provider} in the included array.
     *
     * @param response the response to populate.
     * @param providers the array or {@link Provider} instances to use to populate the response.
     */
    static void populateProviders(final ModelNode response, final Provider[] providers) {
        for (Provider current : providers) {
            ModelNode providerModel = new ModelNode();
            populateProvider(providerModel, current, true);
            response.add(providerModel);
        }
    }

    private static void addServices(final ModelNode providerModel, final Provider provider) {
        ModelNode servicesModel = providerModel.get(Constants.SERVICES);

        for (Service current : provider.getServices()) {
            ModelNode serviceModel = new ModelNode();
            serviceModel.get(Constants.TYPE).set(current.getType());
            serviceModel.get(Constants.ALGORITHM).set(current.getAlgorithm());
            serviceModel.get(Constants.CLASS_NAME).set(current.getClassName());

            servicesModel.add(serviceModel);
        }

    }

    private static AttributeDefinition[] combine(AttributeDefinition first, AttributeDefinition[] remaining, AttributeDefinition... more) {
        AttributeDefinition[] response = new AttributeDefinition[(first == null ? 0 : 1) + remaining.length + more.length];
        int pos = 0;
        if (first != null) {
            response[pos++] = first;
        }
        System.arraycopy(remaining, 0, response, pos, remaining.length);
        pos += remaining.length;
        System.arraycopy(more, 0, response, pos, more.length);
        return response;
    }

}
