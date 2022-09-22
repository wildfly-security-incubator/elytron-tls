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

import java.util.function.Consumer;

import org.wildfly.common.function.ExceptionFunction;

/**
 * Captures a {@link Service} value or instance to make available to runtime operations.
 * Derived from {@link org.jboss.as.clustering.controller.ServiceValueCaptor<T>}.
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class ElytronTlsRuntimeServiceObject<T> implements Consumer<T> {

    private T value = null;

    public Class<?> getRuntimeClass()  {
        return value.getClass();
    }

    @Override
    public synchronized void accept(T acceptedValue) {
        value = acceptedValue;
    }

    public synchronized <R, E extends Exception> R execute(ExceptionFunction<T, R, E> function) throws E {
        return value != null ? function.apply(value) : null;
    }
}
