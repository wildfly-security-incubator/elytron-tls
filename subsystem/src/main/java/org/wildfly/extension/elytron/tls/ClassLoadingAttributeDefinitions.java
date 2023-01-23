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

import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.StringListAttributeDefinition;
import org.jboss.dmr.ModelType;
import org.jboss.modules.Module;
import org.jboss.modules.ModuleIdentifier;
import org.jboss.modules.ModuleLoadException;

/**
 * The common attribute definitions for specifying classes to be loaded by the subsystem.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ClassLoadingAttributeDefinitions {

    static final SimpleAttributeDefinition MODULE = new SimpleAttributeDefinitionBuilder(Constants.MODULE, ModelType.STRING, true)
        .setAttributeGroup(Constants.CLASS_LOADING)
        .setAllowExpression(false)
        .setMinSize(1)
        .setRestartAllServices()
        .build();

    static final SimpleAttributeDefinition CLASS_NAME = new SimpleAttributeDefinitionBuilder(Constants.CLASS_NAME, ModelType.STRING, false)
        .setAttributeGroup(Constants.CLASS_LOADING)
        .setAllowExpression(false)
        .setMinSize(1)
        .setRestartAllServices()
        .build();

    static final StringListAttributeDefinition CLASS_NAMES = new StringListAttributeDefinition.Builder(Constants.CLASS_NAMES)
        .setAttributeGroup(Constants.CLASS_LOADING)
        .setAllowExpression(false)
        .setRequired(false)
        .setRestartAllServices()
        .build();

    static ClassLoader resolveClassLoader(String module) throws ModuleLoadException {
        Module current = Module.getCallerModule();
        if (module != null && current != null) {
            ModuleIdentifier mi = ModuleIdentifier.fromString(module);
            current = current.getModule(mi);
        }

        return current != null ? current.getClassLoader() : ClassLoadingAttributeDefinitions.class.getClassLoader();
    }

}
