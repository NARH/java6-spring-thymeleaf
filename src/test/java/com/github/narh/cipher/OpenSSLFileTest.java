package com.github.narh.cipher;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.*;

import java.io.File;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import com.github.narh.cipher.command.AES256CBCCryptCommand;
import com.github.narh.cipher.command.CryptCommand;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class OpenSSLFileTest {

  private static final String FILE_NAME = "OpenSSLEncryptFile.enc";
  private static final String WRITE_FILE_NAME = "OpenSSLEncryptFile.zip";
  private static final String PASSPHRASE = "12345678";
  private static final String HASH_ALGORITHM = "SHA-256";
  private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

  @Test
  public void testLoadOpenSSLEncryptFile() throws Exception {
    log.info("start");
    File file = new File(getClass().getClassLoader().getResource(FILE_NAME).toURI());
    File parentDir = file.getParentFile().getParentFile().getParentFile();
    log.info("base directory is {}.", parentDir.getAbsolutePath());

    byte[] origin = Utils.getContentsByFile(file);
    byte[] salt = CipherAESUtils.getSaltByOpenSSLCryptFiles(origin);
    MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
    byte[][] keyAndIV = EVP_BytesToKey(32, 16, md, salt, PASSPHRASE.getBytes(), 1);
    byte[] secretKey = keyAndIV[0];
    byte[] iv = keyAndIV[1];
    /*
    byte[] secretKey = Utils.generateSecretKey(PASSPHRASE.getBytes(), "SHA-256",salt);
    byte[] iv = Utils.generateIV(PASSPHRASE.getBytes(), salt, secretKey);
    */

    log.info("key is {}.", Hex.encodeHexString(secretKey));
    log.info("iv is {}.", Hex.encodeHexString(iv));

    CipherContext context = CipherContext.builder()
        .cryptMode(CryptMode.DECRYPT)
        .passphrase(PASSPHRASE.getBytes())
        .salt(salt)
        .secretKey(secretKey)
        .iv(iv)
        .origin(origin)
        .baseDirectoryName(parentDir.getAbsolutePath())
        .writeFileName(WRITE_FILE_NAME)
        .build();

    CryptCommand command = new AES256CBCCryptCommand();
    command.decrypt(context);
    Utils.writeContestsToFile(context);

    log.info("end");
  }

  //@Test /* JDK1.8 later */
  public void PBKDF2Test() throws Exception {
    int iterateCount = 10000;
    int keyLengh = 256;

    File file = new File(getClass().getClassLoader().getResource(FILE_NAME).toURI());
    byte[] origin = Utils.getContentsByFile(file);
    byte[] salt = CipherAESUtils.getSaltByOpenSSLCryptFiles(origin);
    PBEKeySpec keySpec = new PBEKeySpec(PASSPHRASE.toCharArray(), salt, iterateCount, keyLengh);
    SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
    SecretKey sk = skf.generateSecret(keySpec);
    log.info(Hex.encodeHexString(sk.getEncoded()));
  }


  @Test
  public void testDigest() throws Exception {
    log.info("start");
    File file = new File(getClass().getClassLoader().getResource(FILE_NAME).toURI());
    byte[] origin = Utils.getContentsByFile(file);
    byte[] salt = CipherAESUtils.getSaltByOpenSSLCryptFiles(origin);
    MessageDigest messageDigest = MessageDigest.getInstance(HASH_ALGORITHM);
    byte[] keyDigest = openSSLEvpBytesToKey(PASSPHRASE.getBytes(), salt, messageDigest);
    log.info("key digest is {}.", Hex.encodeHexString(keyDigest));
    log.info("key digest length is {}", keyDigest.length);
    byte[] ivDigest = openSSLEvpBytesToKey(PASSPHRASE.getBytes(), salt, messageDigest, 1, keyDigest);
    byte[] iv = Arrays.copyOfRange(ivDigest, 0, 16);
    log.info("key digest is {}.", Hex.encodeHexString(iv));
    log.info("key digest length is {}", iv.length);

    assertThat("SALT が期待値であること", Hex.encodeHexString(salt).toUpperCase()
        ,  is("06A8EE4D903FE34B"));
    assertThat("SECRET KEy が期待値であること", Hex.encodeHexString(keyDigest).toUpperCase()
        ,  is("766F67BA226C360F0D70E183FD52CC279DF9826FF969E15DC39A547C8B9BAA5F"));
    assertThat("IV が期待値であること", Hex.encodeHexString(iv).toUpperCase()
        ,  is("1E3E89317C7E22D3D7E626B018D5A117"));
    log.info("end");
  }

  public static byte[] openSSLEvpBytesToKey(final byte[] passphrase, final byte[] salt, MessageDigest messageDigest) {
    return openSSLEvpBytesToKey(passphrase, salt, messageDigest, 1, null);
  }

  public static byte[] openSSLEvpBytesToKey(final byte[] passphrase, final byte[] salt, MessageDigest messageDigest, int count, byte[] digest) {
    if(null == passphrase || 0 == passphrase.length) throw new IllegalArgumentException("passphrase is empty.");
    if(null == salt || 8 > salt.length) throw new IllegalArgumentException("salt is empty or too short.");
    messageDigest.reset();
    if(null != digest) messageDigest.update(digest);
    messageDigest.update(passphrase);
    messageDigest.update(salt, 0, 8);
    digest = messageDigest.digest();
    return (1 < count) ? openSSLEvpBytesToKey(passphrase, salt, messageDigest, count--, digest) : digest;
  }

  public static byte[][] EVP_BytesToKey(int key_len, int iv_len, MessageDigest md
      , byte[] salt, byte[] data, int count) {

    byte[][] both = new byte[2][];
    byte[] key = new byte[key_len];
    int key_ix = 0;
    byte[] iv = new byte[iv_len];
    int iv_ix = 0;
    both[0] = key;
    both[1] = iv;
    byte[] md_buf = null;
    int nkey = key_len;
    int niv = iv_len;
    int i = 0;
    if (data == null) {
      return both;
    }
    int addmd = 0;
    for (;;) {
      md.reset();
      if (addmd++ > 0) {
        md.update(md_buf);
      }
      md.update(data);
      if (null != salt) {
        md.update(salt, 0, 8);
      }
      md_buf = md.digest();
      log.debug("0. md_buf is {}", Hex.encodeHexString(md_buf));
      for (i = 1; i < count; i++) {
        md.reset();
        md.update(md_buf);
        md_buf = md.digest();
        log.debug("1. md_buf is {}", Hex.encodeHexString(md_buf));
      }
      i = 0;
      if (nkey > 0) {
        for (;;) {
          if (nkey == 0)
            break;
          if (i == md_buf.length)
            break;
          key[key_ix++] = md_buf[i];
          nkey--;
          i++;
        }
      }
      if (niv > 0 && i != md_buf.length) {
        for (;;) {
          if (niv == 0)
            break;
          if (i == md_buf.length)
            break;
          iv[iv_ix++] = md_buf[i];
          niv--;
          i++;
        }
      }
      if (nkey == 0 && niv == 0) {
        break;
      }
    }
    // お掃除
    for (i = 0; i < md_buf.length; i++) {
      md_buf[i] = 0;
    }
    return both;
  }
}
