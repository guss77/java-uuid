/*
 * Copyright 2022 Oded Arbel
 * Use of this source code is governed by an MIT-style license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
package coil.geek;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.not;

import java.security.SecureRandom;
import java.time.Instant;

import org.junit.jupiter.api.Test;

class UUIDTest {

	static final SecureRandom rng = new SecureRandom();
	
	@Test
	void testUUIDByteArray() {
		byte[] data = new byte[16];
		rng.nextBytes(data);
		UUID u = new UUID(data);
		assertThat(u.bytes(), is(equalTo(data)));
	}

	@Test
	void testUUIDByteIntByteArray() {
		byte[] dataZeros = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		byte[] dataOnes = new byte[] { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };
		UUID u = new UUID(UUID.Variant_0_NCS, 0, dataZeros);
		assertThat(u.getMostSignificantBits(), is(equalTo(0L)));
		assertThat(u.getLeastSignificantBits(), is(equalTo(0L)));
		u = new UUID(UUID.Variant_1_4122, 1, dataZeros);
		assertThat(u.getMostSignificantBits(), is(equalTo(0x1000L)));
		assertThat(u.getLeastSignificantBits(), is(equalTo(0x8000000000000000L)));
		u = new UUID(UUID.Variant_1_4122, 4, dataOnes);
		assertThat(u.getMostSignificantBits() & 0xFFFF, is(equalTo(0x4FFFL)));
		assertThat(u.getLeastSignificantBits() >>> 32, is(equalTo(0xBFFFFFFFL)));
		u = new UUID(UUID.Variant_2_Microsoft, 0, dataOnes);
		assertThat(u.getMostSignificantBits() & 0xFFFF, is(equalTo(0x0FFFL)));
		assertThat(u.getLeastSignificantBits() >>> 32, is(equalTo(0xDFFFFFFFL)));
		u = new UUID(UUID.Variant_3_Future, 0, dataOnes);
		assertThat(u.getMostSignificantBits() & 0xFFFF, is(equalTo(0x0FFFL)));
		assertThat(u.getLeastSignificantBits() >>> 32, is(equalTo(0xFFFFFFFFL)));
	}

	@Test
	void testUUIDLongLong() {
		long l1 = rng.nextLong(), l2 = rng.nextLong();
		UUID u = new UUID(l1, l2);
		assertThat(u.getMostSignificantBits(), is(equalTo(l1)));
		assertThat(u.getLeastSignificantBits(), is(equalTo(l2)));
	}

	@Test
	void testRandomUUID() {
		UUID u = UUID.randomUUID();
		assertThat(u.variant(), is(equalTo(UUID.Variant_1_4122)));
		assertThat(u.version(), is(equalTo(4)));
		java.util.UUID ju = new java.util.UUID(u.getMostSignificantBits(), u.getLeastSignificantBits());
		assertThat(ju.variant(), is(equalTo(2)));
		assertThat(ju.version(), is(equalTo(4)));
	}

	@Test
	void testTimeBasedUUID() {
		UUID u = UUID.timeBasedUUID(Instant.ofEpochSecond(1577872805).plusNanos(500)); // 2020-01-01T10:00:05.0005Z
		assertThat(u.variant(), is(equalTo(UUID.Variant_1_4122)));
		assertThat(u.version(), is(equalTo(1)));
		assertThat(u.timestamp(), is(equalTo(137971656050005L)));
		assertThat(u.clockSequence(), not(equalTo(u.node())));
	}

	@Test
	void testMd5NameUUIDUUIDString() {
		UUID u = UUID.md5NameUUID(UUID.NameSpace_URL, "https://cloudonix.io/uuid-test");
		assertThat(u.toString(), is(equalTo("78b27cd6-ae27-3e33-919d-83a7e1d235f5")));
	}

	@Test
	void testMd5NameUUIDUUIDByteArray() {
		UUID u = UUID.md5NameUUID(UUID.NameSpace_URL, "https://cloudonix.io/uuid-test".getBytes());
		assertThat(u.toString(), is(equalTo("78b27cd6-ae27-3e33-919d-83a7e1d235f5")));
	}

	@Test
	void testSha1NameUUIDUUIDString() {
		UUID u = UUID.sha1NameUUID(UUID.NameSpace_URL, "https://cloudonix.io/uuid-test");
		assertThat(u.toString(), is(equalTo("9f15406f-3afd-555d-85b7-ad3a6ff0b2e2")));
	}

	@Test
	void testSha1NameUUIDUUIDByteArray() {
		UUID u = UUID.sha1NameUUID(UUID.NameSpace_URL, "https://cloudonix.io/uuid-test".getBytes());
		assertThat(u.toString(), is(equalTo("9f15406f-3afd-555d-85b7-ad3a6ff0b2e2")));
	}

	@Test
	void testFromString() {
		UUID u = UUID.fromString("078532d8-053f-4f95-9380-9f63d15e1d28");
		assertThat(u.getMostSignificantBits(), is(equalTo(0x078532d8053f4f95L)));
		assertThat(u.getLeastSignificantBits(), is(equalTo(0x93809f63d15e1d28L)));
	}

	@Test
	void testFromJavaUUID() {
		java.util.UUID ju = java.util.UUID.randomUUID();
		UUID u = UUID.fromJavaUUID(ju);
		assertThat(ju.toString(), is(equalTo(u.toString())));
	}

	@Test
	void testToJavaUUID() {
		UUID u = UUID.randomUUID();
		java.util.UUID ju = u.toJavaUUID();
		assertThat(u.toString(), is(equalTo(ju.toString())));
	}

	@Test
	void testGetMostSignificantBits() {
		long l = rng.nextLong();
		UUID u = new UUID(l, 0);
		assertThat(u.getMostSignificantBits(), is(equalTo(l)));
	}

	@Test
	void testGetLeastSignificantBits() {
		long l = rng.nextLong();
		UUID u = new UUID(0, l);
		assertThat(u.getLeastSignificantBits(), is(equalTo(l)));
	}

	@Test
	void testVariant() {
		UUID u = new UUID(UUID.Variant_0_NCS, 0, UUID.randomUUID().bytes());
		assertThat(u.variant(), is(equalTo(UUID.Variant_0_NCS)));
		u = new UUID(UUID.Variant_1_4122, 0, UUID.randomUUID().bytes());
		assertThat(u.variant(), is(equalTo(UUID.Variant_1_4122)));
		u = new UUID(UUID.Variant_2_Microsoft, 0, UUID.randomUUID().bytes());
		assertThat(u.variant(), is(equalTo(UUID.Variant_2_Microsoft)));
		u = new UUID(UUID.Variant_3_Future, 0, UUID.randomUUID().bytes());
		assertThat(u.variant(), is(equalTo(UUID.Variant_3_Future)));
	}

	@Test
	void testVersion() {
		UUID u = new UUID(UUID.Variant_1_4122, 1, UUID.randomUUID().bytes());
		assertThat(u.version(), is(equalTo(1)));
		u = new UUID(UUID.Variant_1_4122, 2, UUID.randomUUID().bytes());
		assertThat(u.version(), is(equalTo(2)));
		u = new UUID(UUID.Variant_1_4122, 3, UUID.randomUUID().bytes());
		assertThat(u.version(), is(equalTo(3)));
		u = new UUID(UUID.Variant_1_4122, 4, UUID.randomUUID().bytes());
		assertThat(u.version(), is(equalTo(4)));
		u = new UUID(UUID.Variant_1_4122, 5, UUID.randomUUID().bytes());
		assertThat(u.version(), is(equalTo(5)));
	}
	
	@Test
	void testToString() {
		java.util.UUID ju = java.util.UUID.randomUUID();
		UUID u = UUID.fromJavaUUID(ju);
		assertThat(u.toString(), is(equalTo(ju.toString())));
	}

	@Test
	void testToStringRepresentation() {
		var uuidString = "fa0d68f3-882f-4c34-97b1-466e2fed93e9";
		java.util.UUID ju = java.util.UUID.fromString(uuidString);
		UUID u = UUID.fromJavaUUID(ju);
		assertThat(u.toStringRepresentation(), is(equalTo(uuidString)));
	}

	@Test
	void testEqualsObject() {
		UUID u1 = UUID.fromString("078532d8-053f-4f95-9380-9f63d15e1d28");
		UUID u2 = new UUID(0x078532d8053f4f95L, 0x93809f63d15e1d28L);
		assertThat(u1, is(equalTo(u2)));
	}

	@Test
	void testCompareTo() {
		UUID u1 = UUID.fromString("d5c6374f-6f89-4950-afa2-f5cbdb3ee7bf");
		UUID u2 = UUID.fromString("078532d8-053f-4f95-9380-9f63d15e1d28");
		UUID u3 = new UUID(0x078532d8053f4f95L, 0x93809f63d15e1d28L);
		assertThat(u1.compareTo(u2), is(lessThan(0)));
		assertThat(u2.compareTo(u1), is(greaterThan(0)));
		assertThat(u2.compareTo(u3), is(equalTo(0)));
	}

}
