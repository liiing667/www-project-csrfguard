/*
 * The OWASP CSRFGuard Project, BSD License
 * Copyright (c) 2011, Eric Sheridan (eric@infraredsecurity.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     1. Redistributions of source code must retain the above copyright notice,
 *        this list of conditions and the following disclaimer.
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *     3. Neither the name of OWASP nor the names of its contributors may be used
 *        to endorse or promote products derived from this software without specific
 *        prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.owasp.csrfguard.util;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class CsrfGuardUtilsTest {

    @Test
    void testCanonicalizeResourceURI() {
        assertEquals(Optional.of("/admin/save"), CsrfGuardUtils.canonicalizeResourceURI("/admin/save"));
        assertEquals(Optional.of("/admin/save"), CsrfGuardUtils.canonicalizeResourceURI("//admin/./save"));
        assertEquals(Optional.of("/admin/save"), CsrfGuardUtils.canonicalizeResourceURI("/admin//save"));
        assertEquals(Optional.of("/admin/save"), CsrfGuardUtils.canonicalizeResourceURI("/admin/public/../save"));
        assertEquals(Optional.of("/admin/save"), CsrfGuardUtils.canonicalizeResourceURI("/admin/./save/"));
        assertEquals(Optional.of("/admin/save"), CsrfGuardUtils.canonicalizeResourceURI("/admin/save?foo=bar&x=y"));
        assertEquals(Optional.of("/admin/save"), CsrfGuardUtils.canonicalizeResourceURI("/admin/save#fragment"));
        assertEquals(Optional.of("/admin/save.js"), CsrfGuardUtils.canonicalizeResourceURI("/admin/./save.js"));
        assertEquals(Optional.of("/"), CsrfGuardUtils.canonicalizeResourceURI("/"));
        assertEquals(Optional.of("/"), CsrfGuardUtils.canonicalizeResourceURI("/./"));
        // relative inputs get a leading slash like the legacy normalization did
        assertEquals(Optional.of("/admin/save"), CsrfGuardUtils.canonicalizeResourceURI("admin/./save"));
        // casing is preserved because path matching is case-sensitive
        assertEquals(Optional.of("/Admin/Save.JSP"), CsrfGuardUtils.canonicalizeResourceURI("/Admin/./Save.JSP"));
    }

    @Test
    void testCanonicalizeResourceURIReturnsEmptyForNonNormalizablePaths() {
        assertFalse(CsrfGuardUtils.canonicalizeResourceURI("/../admin/save").isPresent());
        assertFalse(CsrfGuardUtils.canonicalizeResourceURI("/admin/../../save").isPresent());
        assertFalse(CsrfGuardUtils.canonicalizeResourceURI("..").isPresent());
        assertFalse(CsrfGuardUtils.canonicalizeResourceURI("").isPresent());
        assertFalse(CsrfGuardUtils.canonicalizeResourceURI((String) null).isPresent());
    }
}
