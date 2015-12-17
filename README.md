# php-xss-filter

Five functions for implementing [OWASP's XSS prevention rule 1-5](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet). Simple and light weight if you don't need to pull in a full security library like [OWASP ESAPI for PHP](https://code.google.com/p/owasp-esapi-php/).

## Methods

* ***encodeForHTML*** &mdash; When you want to put untrusted data into HTML element content

* ***encodeForHTMLAttribute*** &mdash; When you want to put untrusted data into HTML attribute values. This should not be used for complex attributes like href, src, style, or any of the event handlers like onmouseover (use URL and JavaScript encode)

* ***encodeForJavaScript*** &mdash; When you want to put untrusted data into JavaScript script blocks and event-handler attributes. Only safe place to put untrusted data in this case is inside a quoted "data values"

* ***encodeForCSS*** &mdash; When you want to put untrusted data into a stylesheet or a style tag. Only use for property value and not into other places in style data

* ***encodeForURL*** &mdash; When you want to put untrusted data into HTTP GET parameter value

More: https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet
