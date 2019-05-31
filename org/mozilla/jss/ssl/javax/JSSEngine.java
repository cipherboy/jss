import java.lang.Runnable;
import java.util.ArrayList;

import java.nio.ByteBuffer;

import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mozilla.jss.nss.*;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.pkcs11.*;

public class JSSEngine extends javax.net.ssl.SSLEngine {
    public static Logger logger = LoggerFactory.getLogger(JSSEngine.class);

    private static int BUFFER_SIZE = 2048;

    private boolean is_client = false;
    private String peer_info = null;
    private BufferProxy read_buf = null;
    private BufferProxy write_buf = null;
    private PRFDProxy ssl_fd = null;

    private PK11Cert cert = null;
    private PK11PrivKey key = null;

    public boolean need_client_auth = false;
    public boolean want_client_auth = false;

    public SSLEngineResult.HandshakeStatus handshake_state = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

    public JSSEngine() {
        super();

        peer_info = "";
        logger.debug("JSSEngine: constructor()");
    }

    public JSSEngine(String peerHost, int peerPort) {
        super(peerHost, peerPort);

        peer_info = peerHost + ":" + peerPort;
        logger.debug("JSSEngine: constructor(" + peerHost + ", " + peerPort + ")");
    }

    public JSSEngine(String peerHost, int peerPort, PK11Cert localCert, PK11PrivKey localKey) {
        super(peerHost, peerPort);

        peer_info = peerHost + ":" + peerHost;
        cert = localCert;
        key = localKey;

        logger.debug("JSSEngine: constructor(" + peerHost + ", " + peerPort + ", " + localCert + ", " + localKey + ")");
    }

    private void init() {
        logger.debug("JSSEngine: init()");
        read_buf = Buffer.Create(BUFFER_SIZE);
        write_buf = Buffer.Create(BUFFER_SIZE);
        ssl_fd = PR.NewBufferPRFD(read_buf, write_buf, peer_info.getBytes());

        if (is_client) {
            initClient();
        } else {
            initServer();
        }
    }

    private void initClient() {
        PRFDProxy model = SSL.ImportFD(null, PR.NewTCPSocket());
        ssl_fd = SSL.ImportFD(model, ssl_fd);
        PR.Close(model);
    }

    private void initServer() {
        PRFDProxy model = SSL.ImportFD(null, PR.NewTCPSocket());
        ssl_fd = SSL.ImportFD(model, ssl_fd);
        PR.Close(model);

        if (cert == null || key == null) {
            throw new IllegalArgumentException("JSSEngine: must be initialized with server certificate and key!");
        }

        SSL.ConfigSecureServer(ssl_fd, cert, key, 1);
        SSL.ConfigServerSessionIDCache(1, 100, 100, null);
    }

    public void beginHandshake() {
        logger.debug("JSSEngine: beginHandshake()");
        if (ssl_fd == null) {
            init();
        }

        if (is_client) {
            // Update handshake status; client initiates connection, so we
            // need to wrap first.
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
        } else {
            // Update handshake status; client initiates connection, so wait
            // for unwrap on the server end.
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        }

        SSL.ResetHandshake(ssl_fd, is_client);
    }

    public void closeInbound() {
        logger.debug("JSSEngine: closeInbound()");

        PR.Shutdown(ssl_fd, PR.SHUTDOWN_RCV);
    }

    public void closeOutbound() {
        logger.debug("JSSEngine: closeOutbound()");

        PR.Shutdown(ssl_fd, PR.SHUTDOWN_SEND);
    }

    public Runnable getDelegatedTask() {
        logger.debug("JSSEngine: getDelegatedTask()");
        return null;
    }

    public String[] getEnabledCipherSuites() {
        logger.debug("JSSEngine: getEnabledCipherSuites()");

        ArrayList<String> enabledCiphers = new ArrayList<String>();
        for (SSLCipher cipher : SSLCipher.values()) {
            try {
                if (SSL.CipherPrefGet(ssl_fd, cipher.getID())) {
                    enabledCiphers.add(cipher.name());
                }
            } catch (Exception e) {
                // Do nothing -- this shouldn't happen as SSLCipher should be
                // synced with NSS. However, we won't throw an exception as
                // doing so would break this loop.
            }
        }
        return enabledCiphers.toArray(new String[0]);
    }

    public String[] getEnabledProtocols() {
        logger.debug("JSSEngine: getEnabledProtocols()");

        ArrayList<String> enabledProtocols = new ArrayList<String>();

        SSLVersionRange vrange = null;
        try {
            vrange = SSL.VersionRangeGet(ssl_fd);
        } catch (Exception e) {
            // This shouldn't happen unless the PRFDProxy is null.
            throw new RuntimeException("Unexpected failure: " + e.getMessage(), e);
        }

        if (vrange == null) {
            // Again; this shouldn't happen as the vrange should always
            // be created by VersionRangeGet(...).
            throw new RuntimeException("JSSEngine.getEnabledProtocols() - null protocol range; this shouldn't happen");
        }

        for (SSLVersion v: SSLVersion.values()) {
            if (vrange.getMinVersion().ordinal() <= v.ordinal() && v.ordinal() <= vrange.getMaxVersion().ordinal()) {
                // We've designated the second alias as the standard Java name
                // for the protocol. However if one isn't provided, fall back
                // to the first alias. It currently is the case that all
                // elements in SSLVersion have two aliases.

                if (v.aliases().length >= 2) {
                    enabledProtocols.add(v.aliases()[1]);
                } else {
                    enabledProtocols.add(v.aliases()[0]);
                }
            }
        }

        return enabledProtocols.toArray(new String[0]);
    }

    public boolean getEnableSessionCreation() {
        logger.debug("JSSEngine: getEnableSessionCreation() - not implemented");
        return false;
    }

    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        logger.debug("JSSEngine: getHandshakeStatus()");
        return handshake_state;
    }

    public boolean getNeedClientAuth() {
        logger.debug("JSSEngine: getNeedClientAuth()");
        return need_client_auth;
    }

    public SSLSession getSession() {
        logger.debug("JSSEngine: getSession() - not implemented");
        return null;
    }

    public String[] getSupportedCipherSuites() {
        logger.debug("JSSEngine: getSupportedCipherSuites() - not implemented");
        return null;
    }

    public String[] getSupportedProtocols() {
        logger.debug("JSSEngine: getSupportedProtocols() - not implemented");
        return null;
    }

    public boolean getUseClientMode() {
        logger.debug("JSSEngine: getUseClientMode()");
        return is_client;
    }

    public boolean getWantClientAuth() {
        logger.debug("JSSEngine: getWantClientAuth()");
        return want_client_auth;
    }

    public boolean isInboundDone() {
        logger.debug("JSSEngine: isInboundDone() - not implemented");
        return false;
    }

    public boolean isOutboundDone() {
        logger.debug("JSSEngine: isOutboundDone() - not implemented");
        return false;
    }

    public void setEnabledCipherSuites(String[] suites) {
        logger.debug("JSSEngine: setEnabledCipherSuites(");
        for (String suite : suites) {
            logger.debug("\t" + suite + ",");
        }
        logger.debug(")");

        // We need to disable the suite if it isn't present in the list of
        // suites above. Be lazy about it for the time being and disable all
        // cipher suites first.
        for (SSLCipher suite : SSLCipher.values()) {
            SSL.CipherPrefSet(ssl_fd, suite.getID(), false);
        }

        // Only enable these particular suites.
        for (String suite_name : suites) {
            try {
                SSLCipher suite = SSLCipher.valueOf(suite_name);
                if (suite != null) {
                    SSL.CipherPrefSet(ssl_fd, suite.getID(), true);
                }
            } catch (Exception e) {
                // The most common case would be if they pass an invalid
                // cipher name. We might as well tell them about it...
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    }

    /**
     * Set the range of SSL protocols supported by this SSLEngine instance.
     *
     * Note that this enables all protocols in the range of min(protocols) to
     * max(protocols), inclusive due to the underlying call to NSS's
     * SSL_VersionRangeSet(...).
     */
    public void setEnabledProtocols(String[] protocols) throws IllegalArgumentException {
        logger.debug("JSSEngine: setEnabledProtocols(");
        for (String protocol : protocols) {
            logger.debug("\t" + protocol + ",");
        }
        logger.debug(")");

        if (protocols == null || protocols.length == 0) {
            throw new IllegalArgumentException("setEnabledProtocols(): protocols must be not null and non-empty!");
        }

        try {
            SSLVersion min_version = SSLVersion.findByAlias(protocols[0]);
            SSLVersion max_version = SSLVersion.findByAlias(protocols[0]);

            for (String protocol : protocols) {
                SSLVersion version = SSLVersion.findByAlias(protocol);
                if (min_version.ordinal() > version.ordinal()) {
                    min_version = version;
                }

                if (max_version.ordinal() < version.ordinal()) {
                    max_version = version;
                }

                // We should bound this range by crypto-policies in the
                // future to match the current behavior.
                SSLVersionRange vrange = SSLVersionRange(min_version, max_version);
                SSL.VersionRangeSet(ssl_fd, vrange);
            }
        } catch (Exception e) {
            // The most common case would be if they pass an invalid protocol
            // version. We might as well tell them about it...
            throw new IllegalArgumentException("setEnabledProtocols(): unknown protocol: " + e.getMessage(), e);
        }
    }

    public void setEnableSessionCreation(boolean flag) {
        logger.debug("JSSEngine: setEnableSessionCreation(" + flag + ") - not implemented");
    }

    public void setNeedClientAuth(boolean need) {
        logger.debug("JSSEngine: setNeedClientAuth(" + need + ")");
        need_client_auth = need;
    }

    public void setUseClientMode(boolean mode) throws IllegalArgumentException {
        logger.debug("JSSEngine: setUseClientMode(" + mode + ")");
        if (ssl_fd != null) {
            throw new IllegalArgumentException("Cannot change client mode after beginning handshake.");
        }

        is_client = mode;
    }

    public void setWantClientAuth(boolean want) {
        logger.debug("JSSEngine: setWantClientAuth(" + want + ")");
        want_client_auth = want;
    }

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) {
        logger.debug("JSSEngine: unwrap()");
        return null;
    }

    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {
        logger.debug("JSSEngine: wrap()");
        return null;
    }
}
