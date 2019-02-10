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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.ArrayUtils;

import com.github.narh.cipher.CipherContext;

import lombok.extern.slf4j.Slf4j;

/**
 * @author narita
 *
 */
@Slf4j
public abstract class AbstractAESCryptCommand implements CryptCommand {

  /* (非 Javadoc)
   * @see com.github.narh.cipher.command.CryptCommand#encrypt(com.github.narh.cipher.CipherContext)
   */
  public void encrypt(CipherContext context) {
    if(log.isDebugEnabled()) log.debug("AES256 do encrypt... {}", Hex.encodeHexString(context.getOrigin()));
    byte[] contents = getGraph(context);
    context.setContents(contents);
    if(log.isDebugEnabled()) log.debug("AES256 encrypt result... {}", Hex.encodeHexString(context.getContents()));
  }

  /* (非 Javadoc)
   * @see com.github.narh.cipher.command.CryptCommand#decrypt(com.github.narh.cipher.CipherContext)
   */
  public void decrypt(CipherContext context) {
    if(log.isDebugEnabled()) log.debug("AES256 do decrypt... {}", Hex.encodeHexString(context.getOrigin()));
    byte[] contents = getGraph(context);
    context.setContents(contents);
    if(log.isDebugEnabled()) log.debug("AES256 decrypt result... {}", Hex.encodeHexString(context.getContents()));
  }

  /**
   * @param context
   * @return
   */
  private byte[] getGraph(final CipherContext context) {
    try {
      Cipher cipher = getCipher();
      cipher.init(context.getCryptMode().mode, getSecretKeySpec(context), getIvParameterSpec(context));
      if(log.isDebugEnabled())
        log.debug("===> AES256 passphrase:{}, iv:{}", new String(context.getPassphrase()), Hex.encodeHexString(context.getIv()));

      byte[] origin;
      if(null != context.getCryptMode() && Cipher.DECRYPT_MODE == context.getCryptMode().mode) {
        int offset = 8 + context.getSalt().length;
        origin = Arrays.copyOfRange(context.getOrigin(), offset, context.getOrigin().length);
        return (0 == origin.length) ? origin : cipher.doFinal(origin);
      }
      else {
        byte[] payload = "Salted__".getBytes();
        byte[] header = ArrayUtils.addAll(payload, context.getSalt());
        origin = ArrayUtils.addAll(header, cipher.doFinal(context.getOrigin()));
        return origin;
      }
    }
    catch (NoSuchAlgorithmException e) {
      if(log.isErrorEnabled()) log.error(e.getLocalizedMessage(), e);
      throw new IllegalArgumentException(e);
    }
    catch (NoSuchPaddingException e) {
      if(log.isErrorEnabled()) log.error(e.getLocalizedMessage(), e);
      throw new IllegalArgumentException(e);
    }
    catch (InvalidKeyException e) {
      if(log.isErrorEnabled()) log.error(e.getLocalizedMessage(), e);
      throw new IllegalArgumentException(e);
    }
    catch (IllegalBlockSizeException e) {
      if(log.isErrorEnabled()) log.error(e.getLocalizedMessage(), e);
      throw new IllegalArgumentException(e);
    }
    catch (BadPaddingException e) {
      if(log.isErrorEnabled()) log.error(e.getLocalizedMessage(), e);
      throw new IllegalArgumentException(e);
    }
    catch (InvalidAlgorithmParameterException e) {
      if(log.isErrorEnabled()) log.error(e.getLocalizedMessage(), e);
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * @param context
   * @return
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   */
  private Cipher getCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
    return Cipher.getInstance(getEncodingMode());
  }

  /**
   * @return
   */
  protected abstract String getEncodingMode();

  /**
   * @return
   */
  protected abstract  Key getSecretKeySpec(final CipherContext context) throws NoSuchAlgorithmException;

  /**
   * @return
   */
  protected abstract IvParameterSpec getIvParameterSpec(final CipherContext context);

}
