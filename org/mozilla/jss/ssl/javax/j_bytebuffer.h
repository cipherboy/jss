#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <jni.h>

#pragma once

/*
 * Opaque structure for using byte buffers from C/JNI. Subject to change at
 * any time.
 *
 * A j_bytebuffer is an interface over a ByteBuffer, for backing IO in
 * JSSEngineOptimizedImpl. It is only meant to either write or read from
 * the given buffer; doing both from a single buffer is likely to fail.
 */
typedef struct {
    /* Original byteArray contents came from. */
    jbyteArray backingArray;

    /* Contents of the buffer. Populated via a call to .array() and offset by
     * .position(). */
    uint8_t *contents;

    /* Capacity is used as a sentinel value; when position == capacity,
     * can't write or read from this buffer. */
    size_t capacity;

    /* Next position to write or read from. */
    size_t position;
} j_bytebuffer;

/*
 * Create a new buffer; must be freed with jbb_free.
 */
j_bytebuffer *jbb_alloc(void);

/*
 * Update this j_bytebuffer struct with the information from a ByteBuffer.
 */
size_t jbb_set_buffer(j_bytebuffer *buf, JNIEnv *env, jbyteArray backingArray, size_t offset);

/* Get the current position of the specified buffer; used for updating the
 * original ByteBuffer. */
size_t jbb_position(j_bytebuffer *buf);

/*
 * Store a character into the buffer. Returns the character if stored,
 * else EOF if unable to store the character (because the buffer is full).
 * When not EOF, can safely be casted to a uint8_t.
 */
int jbb_put(j_bytebuffer *buf, uint8_t byte);

/*
 * Store many characters into the buffer from an array of characters. Returns
 * the number of characters written into the buffer; max of input_size. This
 * is zero when the buffer is already full.
 */
size_t jbb_write(j_bytebuffer *buf, const uint8_t *input, size_t input_size);

/*
 * Get the next character from the buffer or EOF if the buffer is empty. If
 * not EOF, can safely be casted to uint8_t.
 */
int jbb_get(j_bytebuffer *buf);

/*
 * Read several characters from the buffer in the order they were written. The
 * characters are placed in output and up to output_size characters are read.
 * Returns the number of characters read; zero if the buffer was empty.
 */
size_t jbb_read(j_bytebuffer *buf, uint8_t *output, size_t output_size);

/*
 * Free a buffer allocated with jbb_alloc. Note that if jbb_set_buffer isn't
 * called prior to this, we'll copy and release the underlying buffers back
 * to the backing jbyteArray here. Pass NULL for the env parameter to skip
 * this.
 */
void jbb_free(j_bytebuffer *buf, JNIEnv *env);
