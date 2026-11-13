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

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.config.overlay.ConfigPropertiesCascadeCommonUtils;
import org.owasp.csrfguard.token.transferobject.TokenTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Objects;
import java.util.Optional;

/**
 * Various utility methods/helpers.
 */
public final class CsrfGuardUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(CsrfGuardUtils.class.getName());

    private CsrfGuardUtils() {}

    /**
     * for a url, get the protocol and domain, e.g. for url https://a.b/path, will return https://a.b
     *
     * @param url             a string representing a URL
     * @param includeProtocol whether to include the HTTP or HTTPS protocol in the result
     * @return the path with or without the protocol
     */
    public static String httpProtocolAndDomain(final String url, final boolean includeProtocol) {
        if (includeProtocol) {
            return httpProtocolAndDomain(url);
        }

        return httpProtocolAndDomain(url.replaceFirst("^(http[s]?)://", StringUtils.EMPTY));
    }

    /**
     * <pre>Returns the class object.</pre>
     *
     * @param <T> the type of the desired class
     * @param origClassName is fully qualified
     * @return the class
     */
    public static <T> Class<T> forName(final String origClassName) {
        try {
            return (Class<T>) Class.forName(origClassName);
        } catch (final Throwable t) {
            throw new RuntimeException("Problem loading class: " + origClassName, t);
        }
    }

    public static String readResourceFileContent(final String resourceName) {
        try (final InputStream inputStream = CsrfGuardUtils.class.getClassLoader().getResourceAsStream(resourceName)) {
            if (inputStream == null) {
                throw new IllegalStateException("Could not find resource " + resourceName);
            } else {
                return readInputStreamContent(inputStream);
            }
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String readFileContent(final String fileNameWithAbsolutePath) {
        try (final InputStream inputStream = new FileInputStream(fileNameWithAbsolutePath)) {
            return readInputStreamContent(inputStream);
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    /**
     * Construct a class
     *
     * @param <T>      template type
     * @param theClass the class on which to invoke newInstance()
     * @return the instance
     */
    public static <T> T newInstance(final Class<T> theClass) {
        return ConfigPropertiesCascadeCommonUtils.newInstance(theClass);
    }

    public static void addResponseTokenHeader(final CsrfGuard csrfGuard, final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse, final TokenTO tokenTO) {
        if (csrfGuard.isAjaxEnabled() && CsrfGuardUtils.isAjaxRequest(httpServletRequest)) {
            if (!tokenTO.isEmpty()) {
                httpServletResponse.setHeader(csrfGuard.getTokenName(), tokenTO.toString());
            }
        }
    }

    public static boolean isAjaxRequest(final HttpServletRequest request) {
        final Enumeration<String> headers = request.getHeaders("X-Requested-With");
        return Objects.nonNull(headers) && Collections.list(headers).stream()
                                                      .flatMap(headerValue -> Arrays.stream(headerValue.split(",")))
                                                      .map(String::trim)
                                                      .anyMatch("XMLHttpRequest"::equals);
    }

    public static String normalizeResourceURI(final HttpServletRequest httpServletRequest) {
        return normalizeResourceURI(httpServletRequest.getRequestURI());
    }

    public static String normalizeResourceURI(final String resourceURI) {
        return resourceURI.startsWith("/") ? resourceURI : '/' + resourceURI;
    }

    /**
     * Canonicalizes the request URI of the given request before it is matched against the configured
     * protected/unprotected page rules.
     * <p>
     * The canonicalization:
     * <ul>
     *     <li>discards the query string and the fragment (if any are present),</li>
     *     <li>collapses sequences of duplicate slash characters into a single slash,</li>
     *     <li>resolves {@code .} and {@code ..} path segments according to RFC 3986,</li>
     *     <li>keeps the (case-sensitive) path characters, including file extensions, untouched.</li>
     * </ul>
     * As a consequence, aliases such as {@code //admin/./save} or {@code /admin//save} resolve to the same
     * canonical path as the servlet they are routed to ({@code /admin/save}).
     *
     * @param httpServletRequest the current request
     * @return the canonical request path, or an empty {@link Optional} when the path cannot be normalized
     *         (for example it contains a {@code ..} segment escaping the servlet context root)
     */
    public static Optional<String> canonicalizeResourceURI(final HttpServletRequest httpServletRequest) {
        return canonicalizeResourceURI(httpServletRequest.getRequestURI());
    }

    /**
     * Canonicalizes the given resource URI before it is matched against the configured protected/unprotected
     * page rules.
     *
     * @param resourceURI the raw resource URI, never {@code null}
     * @return the canonical request path, or an empty {@link Optional} when the path cannot be normalized
     * @see #canonicalizeResourceURI(HttpServletRequest)
     */
    public static Optional<String> canonicalizeResourceURI(final String resourceURI) {
        if (Objects.isNull(resourceURI) || resourceURI.isEmpty()) {
            return Optional.empty();
        }

        final String path = normalizeResourceURI(stripQueryAndFragment(resourceURI));
        final String[] segments = path.split("/", -1);
        final Deque<String> canonicalSegments = new ArrayDeque<>();

        for (int i = 0; i < segments.length; i++) {
            final String segment = segments[i];
            if (i == 0) {
                // the first segment is empty for absolute paths and must not be treated as a path element
                continue;
            }
            if (segment.isEmpty() || ".".equals(segment)) {
                // duplicate slashes and current-directory references are dropped
                continue;
            }
            if ("..".equals(segment)) {
                if (canonicalSegments.isEmpty()) {
                    // the path tries to escape the context root, it cannot be represented canonically
                    return Optional.empty();
                }
                canonicalSegments.removeLast();
            } else {
                canonicalSegments.addLast(segment);
            }
        }

        final StringBuilder canonicalPath = new StringBuilder();
        for (final String segment : canonicalSegments) {
            canonicalPath.append('/').append(segment);
        }

        return Optional.of(canonicalPath.length() == 0 ? "/" : canonicalPath.toString());
    }

    private static String stripQueryAndFragment(final String resourceURI) {
        int end = resourceURI.length();
        final int queryIndex = resourceURI.indexOf('?');
        if (queryIndex >= 0 && queryIndex < end) {
            end = queryIndex;
        }
        final int fragmentIndex = resourceURI.indexOf('#');
        if (fragmentIndex >= 0 && fragmentIndex < end) {
            end = fragmentIndex;
        }
        return resourceURI.substring(0, end);
    }

    public static String readInputStreamContent(final InputStream inputStream) {
        try {
            return IOUtils.toString(inputStream, Charset.defaultCharset());
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    public static boolean isPermittedUserAgent(HttpServletRequest request, HttpServletResponse response, CsrfGuard csrfGuard) throws IOException {
        final boolean result;

        final String[] bannedUserAgentProperties = csrfGuard.getBannedUserAgentProperties().toArray(new String[0]);
        final String userAgent = request.getHeader("User-Agent");
        if (bannedUserAgentProperties.length > 0 && StringUtils.containsAnyIgnoreCase(userAgent, bannedUserAgentProperties)) {
            LOGGER.warn("HTTP request with forbidden User-Agent: '{}'", userAgent);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden HTTP Client!");
            result = false;
        } else {
            result = true;
        }
        return result;
    }

    /**
     * for a url, get the protocol and domain, e.g. for url https://a.b/path, will return https://a.b
     *
     * @param url a string representing a URL
     * @return the protocol and path
     */
    private static String httpProtocolAndDomain(final String url) {
        final int firstSlashAfterProtocol = url.indexOf('/', 8); // FIXME this should be rewritten..
        return firstSlashAfterProtocol < 0 ? url // must not have a path
                                           : url.substring(0, firstSlashAfterProtocol);
    }
}
