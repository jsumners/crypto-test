package com.example;

import java.io.IOException;
import java.util.Base64;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptedData {
  private static final Logger log = LoggerFactory.getLogger(EncryptedData.class);

  @JsonProperty("iv")
  private byte[] iv;

  @JsonProperty("data")
  private byte[] data;

  public EncryptedData() {}

  public EncryptedData(byte[] iv, byte[] data) {
    this.iv = iv;
    this.data = data;
  }

  public static Optional<EncryptedData> fromJSON(String json) {
    Optional<EncryptedData> result = Optional.empty();

    try {
      ObjectMapper mapper = new ObjectMapper();
      EncryptedData encryptedData = mapper.readValue(json, EncryptedData.class);

      result = Optional.of(encryptedData);
    } catch (IOException e) {
      log.error("Couldn't read JSON string: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    return result;
  }

  public static Optional<EncryptedData> fromBase64(String string) {
    Optional<EncryptedData> result = Optional.empty();

    try {
      ObjectMapper mapper = new ObjectMapper();
      EncryptedData encryptedData =
        mapper.readValue(
          Base64.getDecoder().decode(string),
          EncryptedData.class
        );

      result = Optional.of(encryptedData);
    } catch (IOException e) {
      log.error("Couldn't read JSON string: `{}`", e.getMessage());
      log.debug(e.toString());
    }

    return result;
  }

  public byte[] getIv() {
    return this.iv;
  }

  public void setIv(byte[] iv) {
    this.iv = iv;
  }

  public byte[] getData() {
    return this.data;
  }

  public void setData(byte[] data) {
    this.data = data;
  }

  @Override
  @JsonIgnore
  public String toString() {
    Base64.Encoder base64 = Base64.getEncoder();
    return String.format(
      "{\"iv\": \"%s\", \"data\": \"%s\"}",
      base64.encodeToString(this.iv),
      base64.encodeToString(this.data)
    );
  }
}