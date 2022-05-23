/*
 * Copyright 2022 Oded Arbel
 * Use of this source code is governed by an MIT-style license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
package coil.geek;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;

/**
 * A saner/feature-full revision for Java's incomplete, outdated and broken UUID class.
 * Best effort is made in being RFC4122 compliant, though some operations allow a user to create non-RFC compliant data.
 * @author odeda
 */
public class UUID implements Comparable<UUID> {

	/* -- Java for https://www.rfc-editor.org/rfc/rfc4122#appendix-C -- */

	/** Name string is a fully-qualified domain name */
	public final static UUID NameSpace_DNS = new UUID( /* 6ba7b810-9dad-11d1-80b4-00c04fd430c8 */
			0x6ba7b8109dad11d1L, 0x80b400c04fd430c8L);
	/** Name string is a URL */
	public final static UUID NameSpace_URL = new UUID( /* 6ba7b811-9dad-11d1-80b4-00c04fd430c8 */
			0x6ba7b8119dad11d1L, 0x80b400c04fd430c8L);
	/** Name string is an ISO OID */
	public final static UUID NameSpace_OID = new UUID( /* 6ba7b812-9dad-11d1-80b4-00c04fd430c8 */
			0x6ba7b8129dad11d1L, 0x80b400c04fd430c8L);
	/** Name string is an X.500 DN (in DER or a text output format) */
	public final static UUID NameSpace_X500 = new UUID( /* 6ba7b814-9dad-11d1-80b4-00c04fd430c8 */
			0x6ba7b8149dad11d1L, 0x80b400c04fd430c8L);
	
	public final static byte Variant_0_NCS = 0x0;
	public final static byte Variant_1_4122 = (byte) 0x80;
	public final static byte Variant_2_Microsoft = (byte) 0xC0;
	public final static byte Variant_3_Future = (byte) 0xE0;

	/* lazy initialized RNG for v4 UUIDs */
	private static class RandHolder {
		static final SecureRandom rng = new SecureRandom();
		static final long current_clock_sequence = rng.nextLong();
		static final byte[] node_id = new byte[6];
		static { rng.nextBytes(node_id); }
	}

	private final long[] value = new long[2];

	/**
	 * Constructs a new {@code UUID} using the specified data.
	 * @param data byte array containing exactly 16 bytes
	 */
	public UUID(byte[] data) {
		assert data.length == 16 : "data must be 16 bytes in length";
		init(data);
	}

	/**
	 * Constructs a new {@code UUID} using the specified data, setting the designated variant and version fields.
	 * Please note that using this constructor (unlike {@link #UUID(byte[])}, some of the bits in the provided
	 * data will be overridden by the variant and version bits.
	 * @param variant the variant data. Only the bits designated by https://www.rfc-editor.org/rfc/rfc4122#section-4.1.1 are used
	 * @param version numerical version data, this is a number that is mapped to bits using https://www.rfc-editor.org/rfc/rfc4122#section-4.1.3
	 * @param data byte array containing exactly 16 bytes
	 */
	public UUID(byte variant, int version, byte[] data) {
		assert data.length >= 16 : "data must be 16 bytes in length";
		if ((variant & 0x80) == 0) { // NCS backward compatibility
			data[8] &= 0x7F;
		} else if ((variant & 0xC0) >> 6 == 2) {// RFC 4122 current version
			data[8] &= 0x3F;
			data[8] |= 0x80;
		} else if ((variant & 0xE0) >> 5 == 6) { // Microsoft GUID mixed-endianess format
			data[8] &= 0x1F;
			data[8] |= 0xC0;
		} else if ((variant & 0xE0) >> 5 == 7) { // Future-reserved
			data[8] |= 0xE0;
		}
		data[6] = (byte) ((data[6] & 0x0F) | ((version & 0x0F) << 4));
		init(data);
	}

	/**
	 * Constructs a new {@code UUID} using the specified data. {@code mostSigBits} is used for the most significant 64
	 * bits of the {@code UUID} and {@code leastSigBits} becomes the least significant 64 bits of the {@code UUID}.
	 * @param mostSigBits high 64 bits of the UUID
	 * @param leastSigBits log 64 bits of the UUID
	 */
	public UUID(long mostSigBits, long leastSigBits) {
		value[0] = mostSigBits;
		value[1] = leastSigBits;
	}
	
	/**
	 * Create v4 (pseudo randomly generated) UUID.
	 * Random bits are generated using a statically initialized {@link SecureRandom} instance.
	 * @return Version 4 (type 4) randomly generated UUID
	 */
	public static UUID randomUUID() {
		byte[] data = new byte[16];
		RandHolder.rng.nextBytes(data);
		return new UUID(Variant_1_4122, 4, data);
	}
	
	/**
	 * Create v1 (time-based) UUID from the current UTC time.
	 * The clock sequence and node ID are randomly generated using a statically initialized {@link SecureRandom}
	 * instance, and are kept the same for the life time of this class (normally the lifetime of the class loader).
	 * @return Version 1 (type 1) time-based UUID with the current timestamp and random clock sequence and node ID.
	 */
	public static UUID timeBasedUUID() {
		return timeBasedUUID(Instant.now());
	}
	
	/**
	 * Create v1 (time-based) UUID from the specified time instance.
	 * The clock sequence and node ID are randomly generated using a statically initialized {@link SecureRandom}
	 * instance, and are kept the same for the life time of this class (normally the lifetime of the class loader).
	 * @param time time instant for which to generate a timestamp UUID
	 * @return Version 1 (type 1) time-based UUID with the specified timestamp and random clock sequence and node ID.
	 */
	public static UUID timeBasedUUID(Instant time) {
		var dur = Duration.between(ZonedDateTime.of(1582, 10, 15, 0, 0, 0, 0, ZoneOffset.UTC),
				time.atZone(ZoneOffset.UTC));
		var timestamp = dur.getSeconds() * 10000 + dur.getNano() / 100;
		var time_low = timestamp & 0xFFFFFFFFL;
		timestamp >>>= 32;
		var time_mid = timestamp & 0xFFFFL;
		timestamp >>>= 16;
		var time_high = timestamp & 0xFFF;
		var msb = time_low << 32 | time_mid << 16 | time_high;
		ByteBuffer data = ByteBuffer.allocate(16);
		data.putLong(msb);
		data.putShort((short) (RandHolder.current_clock_sequence & 0xFFFF));
		data.put(RandHolder.node_id);
		return new UUID(Variant_1_4122, 1, data.array());
	}
	
	/**
	 * Create v3 (MD5-hashed) UUID with the specified namespace and content.
	 * The namespace is assumed to be one of the {@code Namespace_*} constants defined in the class - but it doesn't have
	 * to be and any namespace UUID can be specified and will generate a consistent result.
	 * @param namespace UUID of namespace in which to generate the UUID
	 * @param name content from which to generate the UUID - the text is UTF-8 encoded into the content data
	 * @return Version 3 (type 3) MD5 hash based UUID with the specified namespace and name
	 */
	public static UUID md5NameUUID(UUID namespace, String name) {
		return md5NameUUID(namespace, name.getBytes(StandardCharsets.UTF_8));
	}
	
	/**
	 * Create v3 (MD5-hashed) UUID with the specified namespace and content.
	 * The namespace is assumed to be one of the {@code Namespace_*} constants defined in the class - but it doesn't have
	 * to be and any namespace UUID can be specified and will generate a consistent result.
	 * @param namespace UUID of namespace in which to generate the UUID
	 * @param name content from which to generate the UUID
	 * @return Version 3 (type 3) MD5 hash based UUID with the specified namespace and name
	 */
	public static UUID md5NameUUID(UUID namespace, byte[] name) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new InternalError("MD5 hashing is not supported", e);
		}
		var buffer = ByteBuffer.allocate(name.length + 16);
		buffer.putLong(namespace.value[0]);
		buffer.putLong(namespace.value[1]);
		buffer.put(name);
		buffer.flip();
		md.update(buffer);
		return new UUID(Variant_1_4122, 3, md.digest());
	}
	
	/**
	 * Create v5 (SHA1-hashed) UUID with the specified namespace and content.
	 * The namespace is assumed to be one of the {@code Namespace_*} constants defined in the class - but it doesn't have
	 * to be and any namespace UUID can be specified and will generate a consistent result.
	 * @param namespace UUID of namespace in which to generate the UUID
	 * @param name content from which to generate the UUID - the text is UTF-8 encoded into the content data
	 * @return Version 5 (type 5) SHA1 hash based UUID with the specified namespace and name
	 */
	public static UUID sha1NameUUID(UUID namespace, String name) {
		return sha1NameUUID(namespace, name.getBytes(StandardCharsets.UTF_8));
	}
	
	/**
	 * Create v5 (SHA1-hashed) UUID with the specified namespace and content.
	 * The namespace is assumed to be one of the {@code Namespace_*} constants defined in the class - but it doesn't have
	 * to be and any namespace UUID can be specified and will generate a consistent result.
	 * @param namespace UUID of namespace in which to generate the UUID
	 * @param name content from which to generate the UUID
	 * @return Version 5 (type 5) SHA1 hash based UUID with the specified namespace and name
	 */
	public static UUID sha1NameUUID(UUID namespace, byte[] name) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			throw new InternalError("SHA1 hashing is not supported", e);
		}
		var buffer = ByteBuffer.allocate(name.length + 16);
		buffer.putLong(namespace.value[0]);
		buffer.putLong(namespace.value[1]);
		buffer.put(name);
		buffer.flip();
		md.update(buffer);
		return new UUID(Variant_1_4122, 5, md.digest());
	}
	
	/**
	 * Create a UUID instance by parsing the UUID string representation provided
	 * This method does not verify the RFC 4122 compliance according to the variant and version values - it just reads
	 * the bit data encoded in the string representation
	 * @param uuid String representation of a UUID according to RFC 4122
	 * @return UUID containing the data encoded in the string
	 * @throws  IllegalArgumentException if the provided string is not a valid RFC 4122 string representation
	 */
	public static UUID fromString(String uuid) throws IllegalArgumentException {
		try {
			var dash1 = uuid.indexOf('-', 0);
			long time_low, time_mid, time_high_and_version, clock_seq, node;
			if (dash1 < 8)
				throw new NumberFormatException("missing dashes");
			time_low = Long.parseLong(uuid, 0, dash1, 16);
			var dash2 = uuid.indexOf('-', dash1 + 1);
			if (dash2 < 0)
				throw new NumberFormatException("missing dashes");
			time_mid = Long.parseLong(uuid, dash1 + 1, dash2, 16);
			var dash3 = uuid.indexOf('-', dash2 + 1);
			if (dash3 < 0)
				throw new NumberFormatException("missing dashes");
			time_high_and_version = Long.parseLong(uuid, dash2 + 1, dash3, 16);
			var dash4 = uuid.indexOf('-', dash3 + 1);
			if (dash4 < 0)
				throw new NumberFormatException("missing dashes");
			clock_seq = Long.parseLong(uuid, dash3 + 1, dash4, 16);
			node = Long.parseLong(uuid, dash4 + 1, uuid.length(), 16);
			return new UUID(time_low << 32 | time_mid << 16 | time_high_and_version, clock_seq << 48 | node);
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid UUID string: " + uuid, e);
		}
	}
	
	/**
	 * Convert a {@code java.util.UUID} to our UUID instance
	 * @param uuid Java UUID class
	 * @return a new UUID containing the same data as the provided Java UUID
	 */
	public static UUID fromJavaUUID(java.util.UUID uuid) {
		return new UUID(uuid.getMostSignificantBits(), uuid.getLeastSignificantBits());
	}
	
	/**
	 * Convert to a {@code java.util.UUID}
	 * @return a new Java UUID containing the same data as this UUID
	 */
	public java.util.UUID toJavaUUID() {
		return new java.util.UUID(value[0], value[1]);
	}

	/**
	 * Returns the most significant 64 bits of this UUID's 128 bit value.
	 * @return The most significant 64 bits of this UUID's 128 bit value
	 */
	public long getMostSignificantBits() {
		return value[0];
	}

	/**
	 * Returns the least significant 64 bits of this UUID's 128 bit value.
	 * @return The least significant 64 bits of this UUID's 128 bit value
	 */
	public long getLeastSignificantBits() {
		return value[1];
	}
	
	/**
	 * The RFC 4122 specified UUID variant.
	 * This method returns one of the values specified by the {@code Variant_?_*} constants defined in this class.
	 * <strong>Please Note:</strong> the return value of this method is not compatible with {@code java.util.UUID.variant()}! 
	 * @return The variant code of this {@code UUID}
	 */
	public byte variant() {
		byte clock_seq_hi_and_reserved = (byte)(value[1] >>> 56);
		if (clock_seq_hi_and_reserved > 0)
			return Variant_0_NCS;
		if ((clock_seq_hi_and_reserved & 0xC0) == 0x80)
			return Variant_1_4122;
		if ((clock_seq_hi_and_reserved & 0xE0) == 0xC0)
			return Variant_2_Microsoft;
		return Variant_3_Future;
	}

	/**
	 * The RFC 4122 version number of this UUID.
	 * @return The version number of this {@code UUID}
	 */
	public int version() {
		// Version is the bits masked by 0x000000000000F000 in MSL
		return (int) ((value[0] >>> 12) & 0x0f);
	}
	
	public int time_low() {
		return (int) (value[0] >>> 32);
	}
	public int time_mid() {
		return (int) ((value[0] >> 16) & 0xFFFFL);
	}
	public int time_high() {
		return (int) (value[0] & 0x0FFFL);
	}

	/**
	 * The timestamp value in this UUID. The result is constructed from the RFC 4122 time_low, time_mid, and time_hi fields
	 * (reordered according to significance). The correctness of this value is only relevant for RFC 4122 version 1 UUIDs.
	 * <strong>Please Note:</strong> this method is not compatible with {@code java.util.UUID.variant()}, in that it
	 * will not throw an undeclared exception if this UUID is not a time-based UUID - it is up to the caller to
	 * decide if they care or not.
	 * @return The timestamp value of the {@code UUID}.
	 */
	public long timestamp() {
		return ((long)time_high() << 48) | ((long)time_mid() << 32) | time_low();
	}

	/**
	 * The clock sequence value in this UUID. The result is constructed from the RFC 4122 clock sequence fields of this
	 * UUID. The correctness of this value is only relevant for RFC 4122 version 1 UUIDs.
	 * <strong>Please Note:</strong> this method is not compatible with {@code java.util.UUID.variant()}, in that it
	 * will not throw an undeclared exception if this UUID is not a time-based UUID - it is up to the caller to
	 * decide if they care or not.
	 * @return the clock sequence value of the {@code UUID}
	 */
	public int clockSequence() {
		return (int) ((value[1] >>> 48) & variantMask(variant()));
	}

	/**
	 * The node value in this UUID. The result is constructed from the RFC 4122 node field of this UUID. The correctness
	 * of this value is only relevant for RFC 4122 version 1 UUIDs.
	 * <strong>Please Note:</strong> this method is not compatible with {@code java.util.UUID.variant()}, in that it
	 * will not throw an undeclared exception if this UUID is not a time-based UUID - it is up to the caller to
	 * decide if they care or not.
	 * @return The node value of the {@code UUID}
	 */
	public long node() {
		return value[1] & 0x0000FFFFFFFFFFFFL;
	}
	
	/**
	 * Return the UUID data as a sequence of bytes
	 * @return an array of 16 bytes
	 */
	public byte[] bytes() {
		var buffer = ByteBuffer.allocate(16);
		buffer.putLong(value[0]);
		buffer.putLong(value[1]);
		return buffer.array();
	}
	
	/**
	 * Return an RFC 4122 UUID string representation using {@link java.util.UUID#toString()} as that implementation uses
	 * an efficient but complex algorithm that is package private.
	 * For an internal (but likely less efficient) implementation, see {@link #toStringRepresentation()}.
	 * @return string representation as generated by Java's internal efficient code
	 */
	@Override
	public String toString() {
		return toJavaUUID().toString();
	}
	
	/**
	 * Return an RFC 4122 UUID string representation according to https://www.rfc-editor.org/rfc/rfc4122#section-3
	 * This implementation takes pains to implement the algorithm correctly even though the data can be relatively
	 * easily just encode directly.
	 * @return an RFC 4122 UUID string representation composed by hex encoding the various RFC 4122 data fields
	 */
	public String toStringRepresentation() {
		byte variant = variant();
		short variantMask = variantMask(variant);
		return Integer.toHexString(time_low()) + "-" + Integer.toHexString(time_mid()) + "-"
				+ Integer.toHexString(version()) + Integer.toHexString(time_high()) + "-"
				+ Integer.toHexString(((short)variant << 8 & 0xFFFF) | (clockSequence() & variantMask)) + "-"
				+ Long.toHexString(node());
	}
	
	@Override
	public int hashCode() {
		long hilo = value[0] ^ value[1];
		return ((int) (hilo >> 32)) ^ (int) hilo;
	}
	
	@Override
	public boolean equals(Object o) {
		return o instanceof UUID u && Arrays.equals(value, u.value);
	}

	@Override
	public int compareTo(UUID u) {
		var comp = Long.compare(value[0], u.value[0]);
		if (comp == 0)
			comp = Long.compare(value[1], u.value[1]);
		return comp;
	}

	/**
	 * Compute the bits in clock_seq not used by the variant data, for each supported variant
	 * @param variant a supported variant constant value from one of the {@code Variant_*} contants;
	 * @return the map to apply to zero the correct number of bits needed to store the variant data
	 */
	private static short variantMask(byte variant) {
		switch (variant) {
		case Variant_0_NCS: return(short) 0x7FFF;
		case Variant_1_4122: return (short) 0x3FFF;
		default: return (short) 0x1FFF;
		}
	}
	
	/**
	 * Constructor helper for byte mapping
	 * @param data 16-byte array with UUID data to be mapped to MSL and LSL
	 */
	private void init(byte[] data) {
		value[0] = 0L;
		value[1] = 0L;
		for (int i = 0; i < 8; i++)
			value[0] = (value[0] << 8) | (data[i] & 0xff);
		for (int i = 8; i < 16; i++)
			value[1] = (value[1] << 8) | (data[i] & 0xff);
	}
}
