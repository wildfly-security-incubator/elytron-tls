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

/**
 * Captures a {@link Service} object to make it available to runtime operations. Derived from 
 * {@link org.jboss.as.clustering.controller.FunctionExecutor}
 * 
 * @param <I> the class used to identify service objects in the collection 
 * @param <T> class of the object provided by the service at runtime
 * @param object the object provided by the Service
 * @param objectId an identifier for the object, such as a string or class
 * @implSpec Create public classes to set the object, and getters/setters for {@code objectId} 
 * @implSpec Use the method name {@code execute} to indicate operations applied with the value
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public abstract class RuntimeServiceObject<I, T> {
    protected T object = null;
    protected I objectId = null;
}
