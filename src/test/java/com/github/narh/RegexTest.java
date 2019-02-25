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

package com.github.narh;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.*;

import org.junit.Test;

/**
 * @author narita
 *
 */
public class RegexTest {

  @Test
  public void testRegexASCII() throws Exception {
    String ptn = "^[\\p{ASCII}]+$";
    String str = "01234567890";
    assertThat("数値はマッチする", str.matches(ptn), is(true));

    str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    assertThat("英字大文字はマッチする", str.matches(ptn), is(true));
    assertThat("英字小文字はマッチする", str.toLowerCase().matches(ptn), is(true));

    str = "!\"#$%&\'()-=^~|@`[{;+:*]},<.>/?_ ";
    assertThat("記号はマッチする", str.matches(ptn), is(true));

    str = "!qAz2WsX#dC".concat("\r\n\t");
    assertThat("混在マッチする", str.matches(ptn), is(true));

    str = "あいうえお";
    assertThat("ひらがなはマッチしない", str.matches(ptn), is(false));

    str = "アイウエオ";
    assertThat("カタカナはマッチしない", str.matches(ptn), is(false));

    str = "ｱｲｳｴｵ";
    assertThat("半角カタカナはマッチしない", str.matches(ptn), is(false));

    str = "亜井宇江尾";
    assertThat("漢字はマッチしない", str.matches(ptn), is(false));

    str = "!qAiあz2イWsX宇#dC".concat("\r\n\t");
    assertThat("混在マッチしない", str.matches(ptn), is(false));

    ptn = "^[\\p{ASCII}]{8,256}+$";
    str = "1qAz\"sx";
    assertThat("長さが短い", str.matches(ptn), is(false));
    str = "1qAz\"sxE";
    assertThat("長さが範囲内", str.matches(ptn), is(true));
    str =  "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    str += "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    str += "12345678901234567890123456789012345678901234567890123456";
    assertThat("長さ256文字",str.length(), is(256));
    assertThat("長さが範囲内", str.matches(ptn), is(true));

    str =  "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    str += "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    str += "123456789012345678901234567890123456789012345678901234567";
    assertThat("長さ256文字",str.length(), is(257));
    assertThat("長さが範囲内", str.matches(ptn), is(false));
  }
}
