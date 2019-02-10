/*
 * Copyright (c) 2018, NARH https://github.com/NARH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * * Neither the name of the copyright holder nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.github.narh.cipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.lang.ArrayUtils;

import lombok.extern.slf4j.Slf4j;

/**
 * @author narita
 *
 */
@Slf4j
public class Utils {

  /**
   * OpenSSL によって暗号化されたデータファイルよりSALTを取得します。
   *
   * @param contents OpenSSL によって暗号化されたデータ
   * @return SALT データ
   */
  public static byte[] getSaltByOpenSSLCryptFiles(final byte[] contents) {
    if(null == contents || 16 > contents.length) throw new IllegalArgumentException("data size error.");
    byte[] salt = new byte[8];
    salt = Arrays.copyOfRange(contents, 8, 16);
    if(log.isTraceEnabled()) log.trace("SALT is {}.", Hex.encodeHexString(salt));
    return salt;
  }

  /**
   * OpenSSL 方式でパスフレーズとSALTから共通鍵を生成する
   * @param passphrase パスフレーズ
   * @param salt SALT
   * @return 共通鍵データ
   */
  public static byte[] generateSecretKey(final byte[] passphrase, final byte[] salt) {
    byte[] secretKey = new byte[64];
    byte[] secretKey1 = new byte[32];
    byte[] secretKey2 = new byte[32];
    if(null != salt) {
      secretKey1 = DigestUtils.md5(ArrayUtils.addAll(passphrase, salt));
      secretKey2 = DigestUtils.md5(ArrayUtils.addAll(secretKey1, ArrayUtils.addAll(passphrase, salt)));
    }
    else {
      secretKey1 = DigestUtils.md5(passphrase);
      secretKey2 = DigestUtils.md5(ArrayUtils.addAll(secretKey1, passphrase));
    }
    secretKey = ArrayUtils.addAll(secretKey1, secretKey2);
    if(log.isTraceEnabled()) log.trace("SECRET KEY is {}.", Hex.encodeHexString(secretKey));
    return secretKey;
  }

  /**
   * 共通鍵、パスフレーズ、SALT より初期化ベクトルを生成する
   * @param passphrase パスフレーズ
   * @param salt SALT
   * @param secretKey 共通鍵
   * @return 初期化ベクトルデータ
   */
  public static byte[] generateIV(final byte[] passphrase, final byte[] salt, final byte[] secretKey) {
    byte[] iv = new byte[32];
    byte[] secretKey2 = new byte[32];
    secretKey2 = Arrays.copyOfRange(secretKey, 16, secretKey.length);
    if(log.isTraceEnabled()) log.trace("SECRET KEY use {}.", Hex.encodeHexString(secretKey2));
    iv = DigestUtils.md5(ArrayUtils.addAll(secretKey2, ArrayUtils.addAll(passphrase, salt)));
    if(log.isTraceEnabled()) log.trace("IV is {}.", Hex.encodeHexString(iv));
    return iv;
  }

  /**
   * 指定したファイルのデータを取得する
   * @param file 対象ファイル
   * @return 対象データ
   * @throws IOException ファイル例外
   */
  public static byte[] getContentsByFile(File file) throws IOException {
    FileInputStream inputStream = new FileInputStream(file);
    byte[] contents = IOUtils.toByteArray(inputStream);
    inputStream.close();
    return contents;
   }
}

