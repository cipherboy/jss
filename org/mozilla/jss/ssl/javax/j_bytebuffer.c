#include "j_bytebuffer.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <jni.h>
#include "jssutil.h"

j_bytebuffer *jbb_alloc(void) {
    j_bytebuffer *buf = calloc(1, sizeof(j_bytebuffer));

    // Our j_bytebuffer doesn't initially point to any buffers; this means
    // that we're unable to read or write from this buffer.

    return buf;
}

void jbb_release_buffer(j_bytebuffer *buf, JNIEnv *env) {
    if (buf == NULL || env == NULL || buf->backingArray == NULL ||
        buf->contents == NULL)
    {
        return;
    }

    // We wish to preserve changes to our underlying byteArray, so specify 0
    // as the mode parameter.
    jbyte *data = NULL;
    jsize length = 0;
    if (!JSS_RefByteArray(env, buf->backingArray, &data, &length)) {
        return;
    }
    memcpy(data, buf->contents, length);
    JSS_DerefByteArray(env, buf->backingArray, buf->contents, 0);
    free(buf->contents);
    buf->backingArray = NULL;
    buf->contents = NULL;
}

size_t jbb_set_buffer(j_bytebuffer *buf, JNIEnv *env, jbyteArray backingArray, size_t offset) {
    size_t ret = 0;
    if (buf == NULL || env == NULL) {
        return ret;
    }

    // Save position for our return call.
    ret = buf->position;

    // Save and copy any previous data from any previous invocations.
    jbb_release_buffer(buf, env);

    if (backingArray == NULL) {
        // When the new array is NULL, there's no array to reference and this
        // is a "clear" operation. Empty our internal state.
        buf->backingArray = NULL;
        buf->contents = NULL;
        buf->capacity = 0;
        buf->position = 0;
        return ret;
    }

    // Otherwise, take a reference to the underlying data in the byte
    // array, updating the capacity as necessary.
    size_t capacity;
    if (!JSS_FromByteArray(env, backingArray, &buf->contents, &capacity)
        || offset > capacity) {
        // We've failed to set the new data. This means RefByteArray
        // should've thrown an exception. Reset our contents to NULL
        // so we don't try using anything.
        buf->backingArray = NULL;
        buf->contents = NULL;
        buf->capacity = 0;
        buf->position = 0;
        return ret;
    }

    // Otherwise, update our remaining fields with their new values. Note that
    // we update contents with the given offset.
    buf->backingArray = backingArray;
    buf->contents = buf->contents + offset;
    buf->capacity = capacity - offset;
    buf->position = 0;
    return ret;
}

size_t jbb_position(j_bytebuffer *buf) {
    if (buf == NULL) {
        return 0;
    }

    return buf->position;
}

int jbb_put(j_bytebuffer *buf, uint8_t byte) {
    /* ret == EOF <=> can't write to the buffer */
    if (buf == NULL || buf->contents == NULL ||
        buf->position == buf->capacity)
    {
        return EOF;
    }

    buf->contents[buf->position] = byte;
    buf->position += 1;

    // Semantics of put.
    return byte;
}

size_t jbb_write(j_bytebuffer *buf, const uint8_t *input, size_t input_size) {
    /* ret == 0 <=> can't write to the buffer or input_size == 0 */
    if (buf == NULL || buf->contents == NULL || input == NULL ||
        input_size == 0 || buf->position >= buf->capacity)
    {
        return 0;
    }

    // When the input size exceeds that of the remaining space in the
    // destination buffer, update the write size to reflect the smaller
    // of the two values.
    size_t write_size = input_size;
    size_t remaining_space = buf->capacity - buf->position;
    if (write_size > remaining_space) {
        write_size = remaining_space;
    }

    // Copy the data we're writing to this buffer at the specified location,
    // bounding by the reduced write size.
    memcpy(
        buf->contents + buf->position,
        input,
        write_size
    );

    // Update our position so we don't overwrite what we just wrote.
    buf->position += write_size;

    // Semantics of write.
    return write_size;
}

int jbb_get(j_bytebuffer *buf) {
    /* ret == EOF <=> can't read from the buffer */
    if (buf == NULL || buf->contents == NULL ||
        buf->position == buf->capacity)
    {
        return EOF;
    }

    uint8_t result = buf->contents[buf->position];
    buf->position += 1;

    // Semantics of get.
    return result;
}

size_t jbb_read(j_bytebuffer *buf, uint8_t *output, size_t output_size) {
    /* ret == 0 <=> can't read from the buffer or output_size == 0 */
    if (buf == NULL || buf->contents == NULL || output == NULL ||
        output_size == 0 || buf->position >= buf->capacity)
    {
        return 0;
    }

    // When the output size exceeds that of the remaining space in the
    // destination buffer, update the read size to reflect the smaller of
    // the two values.
    size_t read_size = output_size;
    size_t remaining_space = buf->capacity - buf->position;
    if (read_size > remaining_space) {
        read_size = remaining_space;
    }

    // Copy the data we're reading from this buffer at the specified location
    // into the output buffer, bounding by the reduced size.
    memcpy(
        output,
        buf->contents + buf->position,
        read_size
    );

    // Update our position so we don't re-read what we just read.
    buf->position += read_size;

    // Semantics of read.
    return read_size;
}

void jbb_free(j_bytebuffer *buf, JNIEnv *env) {
    // Safely handle partial or invalid structures.
    if (buf == NULL) {
        return;
    }

    // Hand the data back to its own. Usually this should be a no-op as the
    // SSLEngine should make sure to remove the byteBuffers between calls to
    // wrap/unwrap.
    jbb_release_buffer(buf, env);

    // Overwrite our data so we don't keep references to it.
    buf->backingArray = NULL;
    buf->contents = NULL;
    buf->capacity = 0;
    buf->position = 0;

    free(buf);
}
