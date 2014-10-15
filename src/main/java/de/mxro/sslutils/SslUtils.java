package de.mxro.sslutils;

import java.util.IdentityHashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;

import de.mxro.sslutils.internal.SslContextFactory;

public class SslUtils {

    public static Map<SslKeyStoreData, SSLContext> cache;

    static {
        cache = new IdentityHashMap<SslKeyStoreData, SSLContext>();
    }

    public static SSLContext createContextForCertificate(final SslKeyStoreData keyStoreData) {
        if (cache.containsKey(keyStoreData)) {
            return cache.get(keyStoreData);
        }

        final SSLContext newContext = SslContextFactory.getServerContext(keyStoreData);

        cache.put(keyStoreData, newContext);

        return newContext;
    }

}
