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

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.*;

import org.junit.Test;

/**
 * @author narita
 *
 */
public class CipherAlgorithmTest {

  @Test
  public void testAlgorithm取得() throws Exception {
    CipherAlgorithm aes128cbc = CipherAlgorithm.AES128CBC;
    assertThat("AES128CBC のアルゴリズムは AES であること"
        , aes128cbc.algorithm(), is("AES"));
    assertThat("AES128CBC のオペレーションモードは CBC であること"
        , aes128cbc.modeOfOperation(), is("CBC"));
    assertThat("AES128CBC のパディング方式は PKCS5PADDING であること"
        , aes128cbc.padding(), is("PKCS5PADDING"));
    assertThat("AES128CBC の鍵長は128bit であること"
        , aes128cbc.length, is((long)128));
    assertThat("AES128CBC はIVを利用する"
        , aes128cbc.useIV, is(true));

    CipherAlgorithm aes256cbc = CipherAlgorithm.AES256CBC;
    assertThat("AES256 のアルゴリズムは AES であること"
        , aes256cbc.algorithm(), is("AES"));
    assertThat("AES256CBC のオペレーションモードは CBC であること"
        , aes256cbc.modeOfOperation(), is("CBC"));
    assertThat("AES256BC のパディング方式は PKCS5PADDING であること"
        , aes256cbc.padding(), is("PKCS5PADDING"));
    assertThat("AES256CBC の鍵長は128bit であること"
        , aes256cbc.length, is((long)256));
    assertThat("AES256CBC はIVを利用する"
        , aes256cbc.useIV, is(true));
  }
}
