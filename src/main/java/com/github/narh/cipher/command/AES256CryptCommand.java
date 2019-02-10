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

package com.github.narh.cipher.command;

import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.github.narh.cipher.CipherContext;

/**
 * @author narita
 *
 */
public class AES256CryptCommand extends AbstractAESCryptCommand implements CryptCommand {

  public static final String HASH_ALGORITHM = "SHA-256";
  public static final String KEY_ENCODING   = "AES";
  public static final String ENCODING_MODE  = "AES/CBC/PKCS5PADDING";

  public boolean USE_MESSAGE_DIGEST         = false;

  /* (非 Javadoc)
   * @see com.github.narh.cipher.command.AbstractAESCryptCommand#getEncodingMode()
   */
  @Override
  protected String getEncodingMode() {
    return ENCODING_MODE;
  }

  /* (非 Javadoc)
   * @see com.github.narh.cipher.command.AbstractAESCryptCommand#getSecretKeySpec()
   */
  @Override
  protected Key getSecretKeySpec(final CipherContext context)
      throws NoSuchAlgorithmException {
    return new SecretKeySpec(context.getSecretKey(), KEY_ENCODING);
  }

  /* (非 Javadoc)
   * @see com.github.narh.cipher.command.AbstractAESCryptCommand#getIvParameterSpec()
   */
  @Override
  protected IvParameterSpec getIvParameterSpec(final CipherContext context) {
    return new IvParameterSpec(context.getIv());
  }

}
