package com.example;

import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoService {
  private static final Logger log = LoggerFactory.getLogger(CryptoService.class);

  private final Key key;
  private final String algorithm;
  private final String algorithmMode;
  private final int randomBytesLength = 16;
  private final SecureRandom random = new SecureRandom();

  /**
   * <p>Creates a new instance of
   * {@linkplain com.example.CryptoService} that can
   * be used to encrypt and decrypt data.</p>
   *
   * <p>If you already have an existing AES key, of which you have stored
   * the raw data as a Base64 string, the following would be a valid key:</p>
   *
   * <pre><code>
   * byte[] rawKeyData = Base64.getDecoder().decode(base64KeyData);
   * Key key = new SecretKeySpec(rawKeyData, "AES");
   * </code></pre>
   *
   * @param key A {@link java.security.Key} for the "AES" algorightm.
   *            See {@link com.example.CryptoService#generateKey}.
   */
  public CryptoService(Key key) {
    this.key = key;
    this.algorithm = "AES";
    this.algorithmMode = "AES/CBC/PKCS5Padding";
  }

  public Optional<String> decrypt(EncryptedData data) {
    Optional<String> result = Optional.empty();

    Optional<Cipher> cipherOptional = this.getDecryptCipher(data.getIv());
    if (!cipherOptional.isPresent()) {
      return result;
    }

    Cipher cipher = cipherOptional.get();
    byte[] decryptedBytes;
    try {
      // This is returning 0 bytes
      decryptedBytes = cipher.doFinal(data.getData());
      result = (decryptedBytes.length > 0) ?
        Optional.of(new String(decryptedBytes)) : result;
    } catch (BadPaddingException e) {
      log.error("Bad encryption padding size: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (IllegalBlockSizeException e) {
      log.error("Bad encryption block size: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    return result;
  }

  public Optional<EncryptedData> encrypt(String data) {
    Optional<EncryptedData> result = Optional.empty();
    Optional<Cipher> cipherOptional = this.getEncryptCipher();
    if (!cipherOptional.isPresent()) {
      return result;
    }

    Cipher cipher = cipherOptional.get();
    byte[] encryptedBytes = null;
    try {
      encryptedBytes = cipher.doFinal();
    } catch (IllegalBlockSizeException e) {
      log.error("Bad encryption block size: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (BadPaddingException e) {
      log.error("Bad encryption padding size: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    if (encryptedBytes != null) {
      Base64.Encoder base64 = Base64.getEncoder();
      EncryptedData encryptedData = new EncryptedData(
        cipher.getIV(),
        encryptedBytes
      );

      result = Optional.of(encryptedData);
    }

    return result;
  }

  /**
   * Generates a key to be used when encrypting and decrypting data. This key
   * should be retained, or else you will no longer be able to decrypt your
   * encrypted data.
   *
   * @param algorithm A valid {@link javax.crypto.Cipher} algorightm name,
   *                  e.g "AES".
   *
   * @return A random {@link java.security.Key}
   * @throws java.security.NoSuchAlgorithmException
   */
  public static Key generateKey(String algorithm) throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
    SecureRandom secureRandom = new SecureRandom();
    // Can't use a 256bit key because
    // http://javamex.com/tutorials/cryptography/key_size.shtml
    keyGenerator.init(128, secureRandom);
    return keyGenerator.generateKey();
  }

  private Optional<Cipher> getDecryptCipher(byte[] iv) {
    return this.getCipher(Cipher.DECRYPT_MODE, iv);
  }

  private Optional<Cipher> getEncryptCipher() {
    byte[] randomBytes = new byte[this.randomBytesLength];
    this.random.nextBytes(randomBytes);

    return this.getCipher(Cipher.ENCRYPT_MODE, randomBytes);
  }

  private Optional<Cipher> getCipher(int mode, byte[] iv) {
    Optional<Cipher> result = Optional.empty();

    Cipher cipher = null;
    try {
      cipher = Cipher.getInstance(this.algorithmMode);

      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      AlgorithmParameters parameters =
        AlgorithmParameters.getInstance(this.algorithm);
      parameters.init(ivParameterSpec);

      cipher.init(mode, this.key, parameters);
      result = Optional.of(cipher);
    } catch (NoSuchAlgorithmException e) {
      log.error("Could not find cipher mode: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (NoSuchPaddingException e) {
      log.error("Could not find padding type: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (InvalidKeyException e) {
      log.error("Encryption key is invalid: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (InvalidParameterSpecException e) {
      log.error("Algorithm parameter spec invalid: `{}`", e.getMessage());
      log.debug(e.toString());
    } catch (InvalidAlgorithmParameterException e) {
      log.error("Algorithm parameters invalid: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    return result;
  }
}