package org.mozilla.jss.ssl.javax;

import java.security.*;

import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11PrivKey;

public class JSSContext extends SSLContextSpi {
    public static Logger logger = LoggerFactory.getLogger(JSSContext.class);

    PK11Cert cert = null;
    PK11PrivKey key = null;

    public void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
        logger.debug("JSSContext: engineInit(" + km + ", " + tm + ", " + sr + ")");

        throw new KeyManagementException("Multiple KeyManagers are not supported by the JSS SSLContext implementation");
    }

    public SSLEngine engineCreateSSLEngine() {
        logger.debug("JSSContext: engineCreateSSLEngine()");

        return new JSSEngine();
    }

    public SSLEngine engineCreateSSLEngine(String host, int port) {
        logger.debug("JSSContext: engineCreateSSLEngine(" + host + ", " + port + ")");

        return new JSSEngine(host, port);
    }

    public SSLSessionContext engineGetClientSessionContext() {
        logger.debug("JSSContext: engineGetClientSessionContext() - not implemented");
        return null;
    }

    public SSLSessionContext engineGetServerSessionContext() {
        logger.debug("JSSContext: engineGetServerSessionContext() - not implemented");
        return null;
    }

    public SSLServerSocketFactory engineGetServerSocketFactory() {
        logger.debug("JSSContext: engineGetServerSocketFactory() - not implemented");
        return null;
    }

    public SSLSocketFactory engineGetSocketFactory() {
        logger.debug("JSSContext: engineGetSocketFactory() - not implemented");
        return null;
    }
}
