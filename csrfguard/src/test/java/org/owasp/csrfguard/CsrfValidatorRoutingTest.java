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
package org.owasp.csrfguard;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.csrfguard.servlet.JavaScriptServlet;
import org.owasp.csrfguard.util.CsrfGuardUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CsrfValidatorRoutingTest {

    private static final String PROTECTED_PAGE = "/admin/save";

    private static final Set<String> PROTECTED_PAGES = new HashSet<>(Collections.singletonList(PROTECTED_PAGE));

    @Test
    void testCanonicalizationCollapsesAliasesToTheSamePath() {
        assertEquals(Optional.of(PROTECTED_PAGE), CsrfGuardUtils.canonicalizeResourceURI("//admin/./save"));
        assertEquals(Optional.of(PROTECTED_PAGE), CsrfGuardUtils.canonicalizeResourceURI("/admin//save"));
        assertEquals(Optional.of(PROTECTED_PAGE), CsrfGuardUtils.canonicalizeResourceURI("/admin/./save/"));
        assertEquals(Optional.of(PROTECTED_PAGE), CsrfGuardUtils.canonicalizeResourceURI("/admin/public/../save"));
        assertEquals(Optional.of("/admin/save.js"), CsrfGuardUtils.canonicalizeResourceURI("/admin/./save.js"));
        assertEquals(Optional.of(PROTECTED_PAGE), CsrfGuardUtils.canonicalizeResourceURI("/admin/save?foo=bar"));
        assertEquals(Optional.of(PROTECTED_PAGE), CsrfGuardUtils.canonicalizeResourceURI("/admin/save#fragment"));
    }

    @Test
    void testCanonicalizationKeepsCaseAndExtension() {
        assertEquals(Optional.of("/Admin/Save.JSP"), CsrfGuardUtils.canonicalizeResourceURI("/Admin/./Save.JSP"));
    }

    @Test
    void testNonNormalizablePathsAreReportedAsEmpty() {
        assertFalse(CsrfGuardUtils.canonicalizeResourceURI("/../admin/save").isPresent());
        assertFalse(CsrfGuardUtils.canonicalizeResourceURI("/admin/../../save").isPresent());
        assertFalse(CsrfGuardUtils.canonicalizeResourceURI("").isPresent());
    }

    @Test
    void testProtectedPageAliasesRequireTokenWhenProtectIsEnabled() {
        final RoutingFixture fixture = new RoutingFixture(true, PROTECTED_PAGES, Collections.emptySet());

        fixture.run(validator -> {
            assertProtected(validator, "/admin/save");
            assertProtected(validator, "//admin/./save");
            assertProtected(validator, "/admin//save");
            assertProtected(validator, "/admin/public/../save");
            assertProtected(validator, "/admin/./save?foo=bar");
            // path matching is case-sensitive, a different casing is not the same configured resource
            assertNotProtected(validator, "/ADMIN/SAVE");
            assertNotProtected(validator, "/admin/other");
        });
    }

    @Test
    void testExplicitUnprotectedPageTakesPrecedenceOverProtectedRules() {
        final Set<String> unprotectedPages = new HashSet<>(Collections.singletonList("/admin/save"));
        final RoutingFixture fixture = new RoutingFixture(true, new HashSet<>(Collections.singletonList("/admin/*")), unprotectedPages);

        fixture.run(validator -> {
            assertNotProtected(validator, "/admin/save");
            assertNotProtected(validator, "//admin/./save");
            assertProtected(validator, "/admin/delete");
        });
    }

    @Test
    void testExplicitProtectedPageTakesPrecedenceOverUnprotectedRules() {
        final Set<String> protectedPages = new HashSet<>(Collections.singletonList("/admin/save"));
        final RoutingFixture fixture = new RoutingFixture(false, protectedPages, new HashSet<>(Collections.singletonList("/admin/*")));

        fixture.run(validator -> {
            assertProtected(validator, "/admin/save");
            assertProtected(validator, "//admin/./save");
            assertNotProtected(validator, "/admin/delete");
        });
    }

    @Test
    void testExtensionWildcardAndRegexConfigurationsAreStillSupported() {
        final Set<String> protectedPages = new HashSet<>();
        protectedPages.add("*.jsp");
        protectedPages.add("/api/*");
        protectedPages.add("^/rest/.*$");
        final RoutingFixture fixture = new RoutingFixture(true, protectedPages, Collections.emptySet());

        fixture.run(validator -> {
            // extension matching survives canonicalization
            assertProtected(validator, "/admin/./save.jsp");
            // partial path wildcard matching survives canonicalization
            assertProtected(validator, "//api//v1/./users");
            // regular expression matching survives canonicalization
            assertProtected(validator, "/rest/./items/1");
            assertNotProtected(validator, "/admin/save.html");
        });
    }

    @Test
    void testNonNormalizableRequestsAreProtectedByDefault() {
        final RoutingFixture fixture = new RoutingFixture(true, PROTECTED_PAGES, Collections.emptySet());

        fixture.run(validator -> {
            assertProtected(validator, "/../admin/save");
            assertProtected(validator, "/admin/../../save");
        });

        // the same holds when everything is protected by default and only unprotected pages are configured
        final RoutingFixture defaultProtectedFixture = new RoutingFixture(false, Collections.emptySet(), new HashSet<>(Collections.singletonList("/*")));
        defaultProtectedFixture.run(validator -> {
            assertProtected(validator, "/../admin/save");
            assertProtected(validator, "/admin/../../save");
        });
    }

    @Test
    void testMockedRequestRoutingUsesCanonicalUri() {
        final RoutingFixture fixture = new RoutingFixture(true, PROTECTED_PAGES, Collections.emptySet());

        fixture.run(validator -> {
            final HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getRequestURI()).thenReturn("//admin/./save");
            when(request.getMethod()).thenReturn("POST");

            final ProtectionResult protectionResult = validator.isProtectedPageAndMethod(request.getRequestURI(), request.getMethod());
            assertTrue(protectionResult.isProtected());
            assertEquals(PROTECTED_PAGE, protectionResult.getResourceIdentifier());
        });
    }

    @Test
    void testJavaScriptServletBypassStillWorks() {
        final RoutingFixture fixture = new RoutingFixture(true, new HashSet<>(Collections.singletonList("/*")), Collections.emptySet());

        fixture.run(validator -> {
            assertNotProtected(validator, "/JavaScriptServlet");
            // an alias pointing at the javascript servlet has to bypass the token check as well
            assertNotProtected(validator, "/./JavaScriptServlet");
        });
    }

    private static void assertProtected(final CsrfValidator validator, final String resourceUri) {
        final ProtectionResult protectionResult = validator.isProtectedPageAndMethod(resourceUri, "POST");
        assertTrue(protectionResult.isProtected(), () -> String.format("The '%s' resource should be protected!", resourceUri));
    }

    private static void assertNotProtected(final CsrfValidator validator, final String resourceUri) {
        final ProtectionResult protectionResult = validator.isProtectedPageAndMethod(resourceUri, "POST");
        assertFalse(protectionResult.isProtected(), () -> String.format("The '%s' resource should not be protected!", resourceUri));
    }

    /**
     * Mock-based routing fixture: it wires a {@link CsrfGuard} mock with explicit protected/unprotected page
     * sets and the static {@link CsrfGuard}/{@link JavaScriptServlet} singletons, then executes the assertions.
     */
    private static final class RoutingFixture {

        private final boolean protectEnabled;
        private final Set<String> protectedPages;
        private final Set<String> unprotectedPages;

        private RoutingFixture(final boolean protectEnabled, final Set<String> protectedPages, final Set<String> unprotectedPages) {
            this.protectEnabled = protectEnabled;
            this.protectedPages = protectedPages;
            this.unprotectedPages = unprotectedPages;
        }

        private void run(final java.util.function.Consumer<CsrfValidator> assertions) {
            final CsrfGuard csrfGuard = mock(CsrfGuard.class);
            lenient().when(csrfGuard.isProtectEnabled()).thenReturn(this.protectEnabled);
            lenient().when(csrfGuard.getProtectedPages()).thenReturn(this.protectedPages);
            lenient().when(csrfGuard.getUnprotectedPages()).thenReturn(this.unprotectedPages);
            lenient().when(csrfGuard.getRegexPatternCache()).thenReturn(new HashMap<String, Pattern>());

            try (final MockedStatic<JavaScriptServlet> javaScriptServletMockedStatic = mockStatic(JavaScriptServlet.class);
                 final MockedStatic<CsrfGuard> csrfGuardMockedStatic = mockStatic(CsrfGuard.class)) {
                javaScriptServletMockedStatic.when(JavaScriptServlet::getJavascriptUris)
                                             .thenReturn(Collections.singleton("/JavaScriptServlet"));
                csrfGuardMockedStatic.when(CsrfGuard::getInstance).thenReturn(csrfGuard);

                assertions.accept(new CsrfValidator());
            }
        }
    }
}
