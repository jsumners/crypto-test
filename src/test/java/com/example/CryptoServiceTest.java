package com.example;

import java.security.Key;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertTrue;

public class CryptoServiceTest {
  private static final Logger log = LoggerFactory.getLogger(CryptoServiceTest.class);

  private final Key key;

  public CryptoServiceTest() throws Exception{
    String b64key = "uCntWeIpo4kgDAaGDUQo2w==";
    this.key = new SecretKeySpec(Base64.getDecoder().decode(b64key), "AES");
  }

  @Test
  public void testDecrypt() throws Exception {
    CryptoService cryptoService = new CryptoService(this.key);
    Optional<EncryptedData> encryptedDataOptional = EncryptedData.fromJSON(
      "{\"iv\": \"VSadcPgqXYoegXchXrej2Q==\"," +
      "\"data\": \"66qbexIcG0VlGHw5E2JHcA==\"}"
    );

    assertTrue(encryptedDataOptional.isPresent());

    EncryptedData encryptedData = encryptedDataOptional.get();
    Optional<String> stringOptional = cryptoService.decrypt(encryptedData);

    assertTrue(stringOptional.isPresent());
    assertTrue(stringOptional.get().equals("foobar"));
  }

  @Test
  public void testEncrypt() throws Exception {
    CryptoService cryptoService = new CryptoService(this.key);

    Optional<EncryptedData> encryptedDataOptional = cryptoService.encrypt("foobar");
    assertTrue(encryptedDataOptional.isPresent());

    log.info(encryptedDataOptional.get().toString());

    encryptedDataOptional =
      EncryptedData.fromJSON(encryptedDataOptional.get().toString());
    assertTrue(encryptedDataOptional.isPresent());

    EncryptedData encryptedData = encryptedDataOptional.get();
    Optional<String> decryptedOptional = cryptoService.decrypt(encryptedData);

    assertTrue(decryptedOptional.isPresent());
    assertTrue(decryptedOptional.get().equals("foobar"));
  }

  @Test
  public void testGenerateKey() throws Exception {
    Key key1 = CryptoService.generateKey("AES");
    Key key2 = new SecretKeySpec(key1.getEncoded(), "AES");

    assertTrue(key1.equals(key2));

    Base64.Decoder decoder = Base64.getDecoder();
    Base64.Encoder encoder = Base64.getEncoder();
    String b64key = new String(encoder.encode(key1.getEncoded()));
    Key key3 = new SecretKeySpec(decoder.decode(b64key), "AES");

    assertTrue(key1.equals(key3));
  }
}
