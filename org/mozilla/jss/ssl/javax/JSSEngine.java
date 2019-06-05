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
    /*
     * TODO list:
     *
     *  - Allow client authentication.
     *  - Pass want_client_auth and need_client_auth.
     *  - Finish wrap/unwrap.
     *
     * Optional list:
     *
     *  - KeyManager/TrustManager constructor?
     *  - SSLSession object interactions?
     */

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

    public ArrayList<SSLCipher> enabled_ciphers = null;
    public SSLVersion min_protocol = null;
    public SSLVersion max_protocol = null;

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
        } else {
            initServer();
        }

        // Apply the requested cipher suites and protocols.
        applyCiphers();
        applyProtocols();
    }

    private void initClient() {
        // Initialize ssl_fd as a client connection.
        PRFDProxy model = SSL.ImportFD(null, PR.NewTCPSocket());
        ssl_fd = SSL.ImportFD(model, ssl_fd);
        PR.Close(model);

        // Update handshake status; client initiates connection, so we
        // need to wrap first.
        handshake_state = SSLEngineResult.HandshakeStatus.NEED_WRAP;
    }

    private void initServer() {
        // Initialize ssl_fd as a server connection.
        PRFDProxy model = SSL.ImportFD(null, PR.NewTCPSocket());
        ssl_fd = SSL.ImportFD(model, ssl_fd);
        PR.Close(model);

        // The only time cert and key are required are when we're creating a
        // server SSLEngine.
        if (cert == null || key == null) {
            throw new IllegalArgumentException("JSSEngine: must be initialized with server certificate and key!");
        }

        SSL.ConfigSecureServer(ssl_fd, cert, key, 1);
        SSL.ConfigServerSessionIDCache(1, 100, 100, null);

        // Update handshake status; client initiates connection, so wait
        // for unwrap on the server end.
        handshake_state = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
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
        for (SSLCipher suite : enabled_ciphers) {
            if (suite == null) {
                continue;
            }

            try {
                SSL.CipherPrefSet(ssl_fd, suite.getID(), true);
            } catch (Exception e) {
                // The most common case would be if enabled_ciphers contains
                // a cipher removed from NSS.
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    }

    private void applyProtocols() {
        // Enable the protocols only when both a maximum and minimum protocol
        // version are specified.
        if (min_protocol == null || max_protocol == null) {
            return;
        }

        // We should bound this range by crypto-policies in the future to
        // match the current behavior.
        SSLVersionRange vrange = new SSLVersionRange(min_protocol, max_protocol);
        SSL.VersionRangeSet(ssl_fd, vrange);
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

        // Always, reset the handshake status, using the existing
        // socket and configuration (which might've been just created).
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

        // We fake being a non-blocking SSLEngine. In particular, we never
        // export tasks as delegated tasks (e.g., OCSP checking), so this
        // method will always return null.

        return null;
    }

    private void queryEnabledCipherSuites() {
        enabled_ciphers = new ArrayList<SSLCipher>();

        for (SSLCipher cipher : SSLCipher.values()) {
            try {
                if (SSL.CipherPrefGet(ssl_fd, cipher.getID())) {
                    enabled_ciphers.add(cipher);
                }
            } catch (Exception e) {
                // Do nothing -- this shouldn't happen as SSLCipher should be
                // synced with NSS. However, we won't throw an exception as
                // doing so would break this method.
            }
        }
    }

    public String[] getEnabledCipherSuites() {
        logger.debug("JSSEngine: getEnabledCipherSuites()");

        // This only happens in the event that setEnabledCipherSuites(...)
        // isn't called. In which case, we'll need to explicitly query the
        // list off the ssl_fd.
        if (enabled_ciphers == null && ssl_fd == null) {
            queryEnabledCipherSuites();
        }

        if (enabled_ciphers == null) {
            // TODO: Query default ciphersuites here.
            throw new RuntimeException("Unable to query enabled ciphers off of empty ssl_fd.");
        }

        // Convert from SSLCipher Enum values to Java standard strings.
        ArrayList<String> result = new ArrayList<String>();
        for (SSLCipher suite : enabled_ciphers) {
            result.add(suite.name());
        }

        return result.toArray(new String[0]);
    }

    private void queryEnabledProtocols() {
        SSLVersionRange vrange = null;
        try {
            vrange = SSL.VersionRangeGet(ssl_fd);
        } catch (Exception e) {
            // This shouldn't happen unless the PRFDProxy is null.
            throw new RuntimeException("JSSEngine.queryEnabledProtocols() Unexpected failure: " + e.getMessage(), e);
        }

        if (vrange == null) {
            // Again; this shouldn't happen as the vrange should always
            // be created by VersionRangeGet(...).
            throw new RuntimeException("JSSEngine.queryEnabledProtocols() - null protocol range; this shouldn't happen");
        }

        min_protocol = vrange.getMinVersion();
        max_protocol = vrange.getMaxVersion();
    }

    public String[] getEnabledProtocols() {
        logger.debug("JSSEngine: getEnabledProtocols()");

        if ((min_protocol == null || max_protocol == null) && ssl_fd != null) {
            queryEnabledProtocols();
        }

        if (min_protocol == null || max_protocol == null) {
            // TODO: Query default ciphersuites here.
            throw new RuntimeException("JSSEngine.getEnabledProtocls() - Unable to query enabled protocols off of empty ssl_fd.");
        }

        // NSS enables a range of protocols [min_protocol, max_protocol], but
        // Java expects you to be able to pick and choose.
        ArrayList<String> enabledProtocols = new ArrayList<String>();

        for (SSLVersion v: SSLVersion.values()) {
            if (min_protocol.ordinal() <= v.ordinal() && v.ordinal() <= max_protocol.ordinal()) {
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

    public void setEnabledCipherSuites(String[] suites) throws IllegalArgumentException {
        logger.debug("JSSEngine: setEnabledCipherSuites(");
        for (String suite : suites) {
            logger.debug("\t" + suite + ",");
        }
        logger.debug(")");

        if (suites == null || suites.length == 0) {
            throw new IllegalArgumentException("Must specify at least one cipher suite to enable.");
        }

        if (ssl_fd != null) {
            throw new RuntimeException("Must call JSSEngine.setEnabledCipherSuites() prior to calling beginHandshake()");
        }

        enabled_ciphers = new ArrayList<SSLCipher>();
        for (String suite_name : suites) {
            try {
                SSLCipher suite = SSLCipher.valueOf(suite_name);
                enabled_ciphers.add(suite);
            } catch (Exception e) {
                // This should only happen when the suite isn't a know cipher;
                // best to inform the user.
                throw new IllegalArgumentException("Cipher suite (" + suite_name + ") isn't present in the list of supported SSLCiphers: " + e.getMessage(), e);
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
            min_protocol = SSLVersion.findByAlias(protocols[0]);
            max_protocol = SSLVersion.findByAlias(protocols[0]);

            for (String protocol : protocols) {
                SSLVersion version = SSLVersion.findByAlias(protocol);
                if (min_protocol.ordinal() > version.ordinal()) {
                    min_protocol = version;
                }

                if (max_protocol.ordinal() < version.ordinal()) {
                    max_protocol = version;
                }
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

    private int putData(byte[] data, ByteBuffer[] buffers, int offset, int length) {
        // Handle the rather unreasonable task of moving data into the buffers.
        // We assume the buffer parameters have already been checked by
        // computeSize(...); that is, offset/length contracts hold and that
        // each buffer in the range is non-null.
        //
        // We also assume that data.length does not exceed the total number
        // of bytes the buffers can hold; this is what computeSize(...)'s
        // return value should ensure.

        int buffer_index = offset;
        int data_index = 0;

        for (data_index = 0; data_index < data.length; data_index++) {
            // Ensure we have have a buffer with capacity.
            while (buffers[buffer_index].capacity() == buffers[buffer_index].position()) {
                buffer_index += 1;
            }

            // TODO: use bulk copy
            buffers[buffer_index].put(data[data_index]);
        }

        return data_index;
    }

    private void updateHandshakeState() {
        // If we're already done, nothing to do.
        if (handshake_state != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            return;
        }

        // If we've previously finished handshaking, then move to
        // NOT_HANDSHAKING.
        if (handshake_state == SSLEngineResult.HandshakeStatus.FINISHED) {
            handshake_state = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
            return;
        }

        // Since we're not obviously done handshaking, and the last time we
        // were called, we were still handshaking, step the handshake.
        SSL.ForceHandshake(ssl_fd);

        // Check if we've just finished handshaking.
        SecurityStatusResult handshakeStatus = SSL.SecurityStatus(ssl_fd);
        if (handshakeStatus.on == 1) {
            handshake_state = SSLEngineResult.HandshakeStatus.FINISHED;
            return;
        }

        // Otherwise, set NEED_WRAP / NEED_UNWRAP as appropriate.
        if (!Buffer.CanRead(read_buf)) {
            // Cant read; to read, we need to call unwrap to provide
            // more data to read.
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
            return;
        }

        if (!Buffer.CanWrite(write_buf)) {
            // Cant write; to read, we need to call wrap to provide more
            // data to write.
            handshake_state = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
            return;
        }

        // If we get here, it isn't clear what the next step in the
        // handshake should be. Keep it at whatever it currently is.
        // Perhaps we should flipflop between WRAP/UNWRAP, but that'd
        // require additional code.
    }

    private boolean isHandshakeFinished() {
        return (handshake_state == SSLEngineResult.HandshakeStatus.FINISHED ||
                (ssl_fd != null && handshake_state == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING));
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
            wire_data = Math.max(wire_data, src.capacity() - src.position());
        }

        // Actual amount of data written to the buffer.
        int app_data = 0;

        // Maximum theoretical amount of data we could've written to the
        // destination. This is bounded by both the size of our dsts and
        // the maximum BUFFER_SIZE. Worst case, we'll be forced to call
        // unwrap(...) multiple times.
        int max_app_data = Math.max(computeSize(dsts, offset, length), BUFFER_SIZE);

        // Order of operations:
        //  1. Read data from srcs
        //  2. Update handshake status
        //  3. Write data to dsts
        //
        // Since srcs is coming from the data, it could affect our ability to
        // handshake. It could also affect our ability to write data to dsts,
        // as src could provide new data to decrypt. When no new data from src
        // is present, we could have residual steps in handshake(), in which
        // case no data would be written to dsts. Lastly, even if no new data
        // from srcs, could still have residual data in read_buf, so we should
        // attempt to read from the ssl_fd.

        // When we have data from src, write it to read_buf.
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

        // Check to see if we need to step our handshake process or not.
        updateHandshakeState();

        // When we have app data to write over the network, go ahead and do
        // so. This involves reading from ssl_fd and writing to dsts. We don't
        // currently have a good proxy metric for "can read from a ssl_fd",
        // so always attempt it if the handshake is finished.
        if (max_app_data > 0 && isHandshakeFinished()) {
            byte[] app_buffer = PR.Read(ssl_fd, max_app_data);
            app_data = putData(app_buffer, dsts, offset, length);
        }

        // Need a way to introspect the open/closed state of the TLS
        // connection.

        return new SSLEngineResult(SSLEngineResult.Status.OK, handshake_state, wire_data, app_data);
    }

    public int writeData(srcs, offset, length) {
        // This is the tough end of reading/writing. There's two potential
        // places buffering could occur:
        //
        //  - Inside the NSS library (unclear if this happens).
        //  - write_buf
        //
        // So when we call PR.Write(ssl_fd, data), it isn't guaranteed that
        // we can write all of data to ssl_fd (unlike with all our other read
        // or write operations where we have a clear bound). In the event that
        // our Write call is truncated, we have to put data back into the
        // buffer from whence it was read.
        //
        // However, we do use Buffer.WriteCapacity(write_buf) as a proxy
        // metric for how much we can write without having to place data back
        // in a src buffer.
        int data_length = 0;

        for (int rel_index = 0; rel_index < length; rel_index += 1) {
            int this_write = 0;
            int expected_write = (int) Buffer.WriteCapacity(write_buf);
        }

        return data_length;
    }

    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws IllegalArgumentException {
        logger.debug("JSSEngine: wrap()");
        // In this method, we're taking the application data from the various
        // srcs and writing it to the remote peer (via ssl_fd). If there's any
        // data for us to send to the remote peer, we place it in dst.
        //
        // However, we also need to detect if the handshake is still ongoing;
        // if so, we can't send data (from src) until then.

        if (ssl_fd == null) {
            beginHandshake();
        }

        // wire_data is the number of bytes written to dst. This is bounded
        // above by two fields: the number of bytes we can read from
        // write_buf, and the size of dst, if present.
        int wire_data = (int) Buffer.ReadCapacity(write_buf);
        if (dst == null) {
            wire_data = 0;
        } else {
            wire_data = Math.max(wire_data, dst.capacity() - dst.position());
        }

        // Actual amount of data read from srcs (and written to ssl_fd). This
        // is determined by the PR.Write(...) call on ssl_fd.
        int app_data = 0;

        // Maximum theoretical amount of data we could've read from srcs.
        // While this isn't strictly bounded above by BUFFER_SIZE (as it is
        // being written to ssl_fd instead of to read_buf or write_buf), we're
        // better off limiting ourselves to a reasonable limit.
        int max_app_data = Math.max(computeSize(srcs, offset, length), BUFFER_SIZE);

        // Order of operations:
        //  1. Step the handshake
        //  2. Write data from srcs to ssl_fd
        //  3. Write data from write_buf to dst
        //
        // This isn't technically locally optimal: it could be that write_buf
        // is full while we're handshaking so step 1 could be a no-op, but
        // we could read from write_buf and step the handshake then. However,
        // on our next call to wrap() would also step the handshake, which
        // two in a row would almost certainly result in one being a no-op.
        // Both steps 1 and 2 could write data to dsts. At best 2 will fail if
        // write_buf is full, however, we'd again end up calling wrap() again
        // anyways.

        // Check to see if we need to step our handshake process or not.
        updateHandshakeState();

        // Try writing data from srcs to
        if (max_app_data > 0 && isHandshakeFinished()) {
            app_data = writeData(srcs, offset, length);
        }

        // Try reading data from write_buf to dst
        if (wire_data > 0) {
            byte[] wire_buffer = Buffer.Read(write_buf, wire_data);
            dst.put(wire_buffer);
        }

        // Need a way to introspect the open/closed state of the TLS
        // connection.

        return new SSLEngineResult(SSLEngineResult.Status.OK, handshake_state, wire_data, app_data);
    }
}
