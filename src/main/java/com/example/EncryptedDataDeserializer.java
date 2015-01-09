package com.example;

import java.io.IOException;
import java.util.Base64;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

public class EncryptedDataDeserializer extends JsonDeserializer<EncryptedData> {
  @Override
  public EncryptedData deserialize(JsonParser jp, DeserializationContext ctxt)
    throws IOException
  {
    EncryptedData result = new EncryptedData();

    ObjectCodec codec = jp.getCodec();
    JsonNode node = codec.readTree(jp);

    Base64.Decoder base64 =  Base64.getDecoder();

    result.setIv(
      base64.decode(node.get("iv").asText())
    );

    result.setData(
      base64.decode(node.get("data").asText())
    );

    return result;
  }
}