package org.mozilla.jss.ssl.javax;

import java.security.SecureRandom;
import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;

public class JSSContext extends SSLContext {
    public static Logger logger = LoggerFactory.getLogger(JSSContext.class);

    PK11Cert cert = null;
    PK11PrivKey key = null;

    public JSSContext() {}
    public JSSContext(String alias) {
        findKeys(alias);
    }

    public static SSLContext getDefault() {
        return new JSSContext();
    }

    public void init(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
        logger.debug("JSSContext: engineInit(" + km + ", " + tm + ", " + sr + ")");

        throw new KeyManagementException("Multiple KeyManagers are not supported by the JSS SSLContext implementation");
    }

    public void findKeys(String alias) {
        CryptoManager cm = CryptoManager.getInstance();
        cert = cm.findCertByNickname(alias);
        key = cm.findPrivKeyByCert(cert);
    }

    public SSLEngine createSSLEngine() {
        logger.debug("JSSContext: engineCreateSSLEngine()");

        JSSEngine ret = new JSSEngine();
        if (cert != null && key != null) {
            ret.setKeyMaterials(cert, key);
        }

        return ret;
    }

    public SSLEngine createSSLEngine(String host, int port) {
        logger.debug("JSSContext: engineCreateSSLEngine(" + host + ", " + port + ")");

        JSSEngine ret = new JSSEngine(host, port);
        if (cert != null && key != null) {
            ret.setKeyMaterials(cert, key);
        }

        return ret;
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

    public getProvider() {
        // We hard code our provider since it is the only supported Provider
        // for use with our SSLEngine (JSSEngine).
        return Security.getProvider("Mozilla-JSS");
    }
}
