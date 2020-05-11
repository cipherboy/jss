package org.mozilla.jss.nss;

import java.nio.ByteBuffer;

public class JByteBuffer {
    /**
     * Create a new j_buffer object with the specified number of bytes.
     *
     * See also: jbb_alloc in org/mozilla/jss/ssl/javax/j_bytebuffer.h
     */
    public static native ByteBufferProxy Create();

    /**
     * Set the underlying buffer for this ByteBufferProxy instance.
     *
     * See also: jbb_set_buffer in org/mozilla/jss/ssl/javax/j_bytebuffer.h
     */
    public static void SetBuffer(ByteBufferProxy proxy, ByteBuffer buffer) {
        if (proxy == null) {
            return;
        }

        if (buffer == null) {
            long offset = SetBufferNative(proxy, null, 0);
            if (proxy.last == null && offset != 0) {
                String msg = "Invariant violated: jbb_set_buffer should ";
                msg += "only return a non-zero offset when the previous ";
                msg += "buffer was non-NULL.";
                throw new RuntimeException(msg);
            }

            if (proxy.last == null) {
                // Nothing lef to do: previous buffer was NULL, as was this
                // one.
                return;
            }

            // Update the position with the offset relative to our new
            // position according to how much data was read/written from
            // the j_bytebuffer instance by NSPR.
            proxy.last.position(proxy.last.position() + (int) offset);
            proxy.last = null;
        }

        long offset = SetBufferNative(proxy, buffer.array(), buffer.position());
        if (proxy.last != null) {
            proxy.last.position(proxy.last.position() + (int) offset);
        }

        proxy.last = buffer;
    }

    /**
     * Clear the underlying buffer for this ByteBufferProxy instance.
     */
    public static void ClearBuffer(ByteBufferProxy proxy) {
        SetBuffer(proxy, null);
    }

    /**
     * Internal helper to implement the native portion of SetBuffer.
     *
     * See also: jbb_set_buffer in org/mozilla/jss/ssl/javax/j_bytebuffer.h
     */
    private static native long SetBufferNative(ByteBufferProxy proxy, byte[] array, long offset);

    /**
     * Destroy a buffer object, freeing its resources.
     *
     * See also: jbb_free in org/mozilla/jss/ssl/javax/j_buffer.h
     */
    public static void Free(ByteBufferProxy proxy) {
        ClearBuffer(proxy);
        FreeNative(proxy);
    }

    /**
     * Internal helper to implement the free call.
     */
    private static native void FreeNative(ByteBufferProxy proxy);
}
