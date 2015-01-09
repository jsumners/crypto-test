package com.example;

import java.security.SecureRandom;
import java.util.Optional;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertTrue;

public class EncryptedDataTest {
  private static final Logger log = LoggerFactory.getLogger(EncryptedDataTest.class);

  private final SecureRandom secureRandom = new SecureRandom();

  @Test
  public void testFromBase64() throws Exception {
    Optional<EncryptedData> encryptedDataOptional =
      EncryptedData
        .fromBase64("eyJpdiI6ICJZbUZ5WW1GNiIsICJkYXRhIjogIlptOXZZbUZ5In0=");

    assertTrue(encryptedDataOptional.isPresent());

    EncryptedData encryptedData = encryptedDataOptional.get();
    String iv = new String(encryptedData.getIv());
    String data = new String(encryptedData.getData());

    assertTrue(iv.equals("barbaz"));
    assertTrue(data.equals("foobar"));
  }

  @Test
  public void testToString() throws Exception {
    byte[] data = "foobar".getBytes();
    byte[] iv = "barbaz".getBytes();

    EncryptedData encryptedData = new EncryptedData(iv, data);
    String string = "{\"iv\": \"YmFyYmF6\", \"data\": \"Zm9vYmFy\"}";

    assertTrue(encryptedData.toString().equals(string));
  }
}