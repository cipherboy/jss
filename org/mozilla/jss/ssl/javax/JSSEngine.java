import java.lang.*;
import java.util.*;

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

    public HashSet<String> enabled_ciphers = null;

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

        // Initialize our JSSEngine when we begin to handshake; otherwise,
        // calls to Set<Option>(...) won't be processed if we call it too
        // early; some of these need to be applied at initialization.

        // If the buffers exist, destroy them and recreate.
        if (read_buf != null) {
            Buffer.Free(read_buf);
        }
        read_buf = Buffer.Create(BUFFER_SIZE);

        if (write_buf != null) {
            Buffer.Free(write_buf);
        }
        write_buf = Buffer.Create(BUFFER_SIZE);

        // Ensure we don't leak ssl_fd if we're called multiple times.
        if (ssl_fd != null) {
            PR.Close(ssl_fd);
        }
        ssl_fd = PR.NewBufferPRFD(read_buf, write_buf, peer_info.getBytes());

        // Initialize the appropriate end of this connection.
        if (is_client) {
            initClient();

            // Update handshake status; client initiates connection, so we
            // need to wrap first.
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
        } else {
            initServer();

            // Update handshake status; client initiates connection, so wait
            // for unwrap on the server end.
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        }

        applyCiphers();
    }

    private void initClient() {
        // Initialize ssl_fd as a client connection.
        PRFDProxy model = SSL.ImportFD(null, PR.NewTCPSocket());
        ssl_fd = SSL.ImportFD(model, ssl_fd);
        PR.Close(model);
    }

    private void initServer() {
        // Initialize ssl_fd as a server connection.
        PRFDProxy model = SSL.ImportFD(null, PR.NewTCPSocket());
        ssl_fd = SSL.ImportFD(model, ssl_fd);
        PR.Close(model);

        if (cert == null || key == null) {
            throw new IllegalArgumentException("JSSEngine: must be initialized with server certificate and key!");
        }

        SSL.ConfigSecureServer(ssl_fd, cert, key, 1);
        SSL.ConfigServerSessionIDCache(1, 100, 100, null);
    }

    private void applyCiphers() {
        // Enabled the ciphersuites specified by setEnabledCipherSuites(...).
        // When this isn't called, enabled_ciphers will be null, so we'll just
        // use whatever is enabled by default.
        if (enabled_ciphers == null) {
            return;
        }

        // We need to disable the suite if it isn't present in the list of
        // suites above. Be lazy about it for the time being and disable all
        // cipher suites first.
        for (SSLCipher suite : SSLCipher.values()) {
            SSL.CipherPrefSet(ssl_fd, suite.getID(), false);
        }

        // Only enable these particular suites.
        for (String suite_name : enabled_ciphers) {
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

    public void beginHandshake() {
        logger.debug("JSSEngine: beginHandshake()");

        // We assume beginHandshake(...) is the entry point for initializing
        // the buffer. In particular, wrap(...) / unwrap(...) *MUST* call
        // beginHandshake(...) if ssl_fd == null.

        // ssl_fd == null <-> we've not initialized anything yet.
        if (ssl_fd == null) {
            init();
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

    private void queryEnabledCipherSuites() {
        enabled_ciphers = new HashSet<String>();

        for (SSLCipher cipher : SSLCipher.values()) {
            try {
                if (SSL.CipherPrefGet(ssl_fd, cipher.getID())) {
                    enabled_ciphers.add(cipher.name());
                }
            } catch (Exception e) {
                // Do nothing -- this shouldn't happen as SSLCipher should be
                // synced with NSS. However, we won't throw an exception as
                // doing so would break this loop.
            }
        }
    }

    public String[] getEnabledCipherSuites() {
        logger.debug("JSSEngine: getEnabledCipherSuites()");

        if (enabled_ciphers == null) {
            queryEnabledCipherSuites();
        }

        return enabled_ciphers.toArray(new String[0]);
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

        if (ssl_fd != null) {
            throw new RuntimeException("Must call JSSEngine.setEnabledCipherSuites() prior to calling beginHandshake()");
        }

        enabled_ciphers = new HashSet<String>();
        for (String suite : suites) {
            enabled_ciphers.add(suite);
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
                SSLVersionRange vrange = new SSLVersionRange(min_version, max_version);
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

    private int computeSize(ByteBuffer[] buffers, int offset, int length) throws IllegalArgumentException {
        int result = 0;

        if (buffers == null) {
            return result;
        }

        // Semantics of arguments:
        //
        // - buffers is where we're reading/writing application data.
        // - offset is the index of the first buffer we read/write to.
        // - length is the total number of buffers we read/write to.
        //
        // We use a relative index and an absolute index to handle these
        // constraints.
        for (int rel_index = 0; rel_index < length; rel_index++) {
            int index = offset + rel_index;
            if (index >= buffers.length) {
                throw new IllegalArgumentException("offset (" + offset + ") or length (" + length + ") exceeds contract based on number of buffers (" + buffers.length + ")");
            }
            if (buffers[index] == null) {
                throw new IllegalArgumentException("Buffer at index " + index + " is null.");
            }

            result += (buffers[index].capacity() - buffers[index].position());
        }

        return result;
    }

    private void putData(byte[] data, ByteBuffer[] buffers, int offset, int length) {
        // Handle the rather unreasonable task of moving data into the buffers.
        // We assume the buffer parameters have already been checked by
        // computeSize(...); that is, offset/length contracts hold and that
        // each buffer in the range is non-null.
        //
        // We also assume that data.length does not exceed the total number
        // of bytes the buffers can hold; this is what computeSize(...)'s
        // return value should ensure.

        int buffer_index = offset;

        for (int data_index = 0; data_index < data.length; data_index++) {
            // Ensure we have have a buffer with capacity.
            while (buffers[buffer_index].capacity() == buffers[buffer_index].position()) {
                buffer_index += 1;
            }

            // TODO: use bulk copy
            buffers[buffer_index].put(data[data_index]);
        }
    }

    private void updateHandshakeState() {

    }

    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws IllegalArgumentException {
        logger.debug("JSSEngine: unwrap()");
        // In this method, we're taking the network wire contents of src and
        // passing them as the read side of our buffer. If there's any data
        // for us to read from the remote peer (via ssl_fd), we place it in
        // the various dsts.
        //
        // However, we also need to detect if the handshake is still ongoing;
        // if so, we can't send data (from src) until then.

        if (ssl_fd == null) {
            beginHandshake();
        }

        // wire_data is the number of bytes from src we've written into
        // read_buf. This is bounded above by src.capcity but also the
        // free space left in read_buf to write to. Allows us to size the
        // temporary byte array appropriately.
        int wire_data = (int) Buffer.WriteCapacity(read_buf);
        if (src == null) {
            wire_data = 0;
        } else {
            wire_data = Math.max(wire_data, src.capacity());
        }

        int app_data = 0;
        int max_app_data = computeSize(dsts, offset, length);
        int buffer_index = offset;

        // When we have data from src, write it to read_buf
        if (wire_data > 0) {
            byte[] wire_buffer = new byte[wire_data];
            src.get(wire_buffer);
            int written = (int) Buffer.Write(read_buf, wire_buffer);

            // For safety: ensure everything we thought we could write was
            // actually written. Otherwise, we've done something wrong.
            wire_data = Math.min(wire_data, written);

            // TODO: Determine if we should write the trail of wire_buffer
            // back to the front of src... Seems like unnecessary work.
        }

        // Check to see if we need to step our handshake process or not
        if (handshake_state != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            updateHandshakeState();
        }

        // When we have app data to read, go ahead and do so
        if (max_app_data > 0) {

        }

        return null;
    }

    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {
        logger.debug("JSSEngine: wrap()");
        // In this method, we're taking the application data from the various
        // srcs and writing it to the remote peer (via ssl_fd). If there's any
        // data for us to send to the remote peer, we place it in dst.
        return null;
    }
}
