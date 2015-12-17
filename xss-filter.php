<?php

// https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet

/**
 * RULE #1 - HTML Escape Before Inserting Untrusted Data into HTML Element Content
 *
 * Escape the following characters with HTML entity encoding to prevent switching into
 * any execution context, such as script, style, or event handlers. Using hex entities is
 * recommended in the spec. In addition to the 5 characters significant in XML (&, <, >, ", '), the
 * forward slash is included as it helps to end an HTML entity.
 *
 * & --> &amp;
 * < --> &lt;
 * > --> &gt;
 * " --> &quot;
 * ' --> &#x27;     &apos; not recommended because its not in the HTML spec
 * / --> &#x2F;     forward slash is included as it helps end an HTML entity
 *
 */

function encodeForHTML($input, $stripTags = false) {
  if ($stripTags) {
    $input = strip_tags($input);
  }
  return str_replace('/', '&#x2F;', htmlentities($input, ENT_QUOTES, 'UTF-8'));
}


/**
 * RULE #2 - Attribute Escape Before Inserting Untrusted Data into HTML Common Attributes
 *
 * For putting untrusted data into typical attribute values like width, name, value, etc.
 * This should not be used for complex attributes like href, src, style, or any of the event
 * handlers like onmouseover. (Use URL and JavaScript encode).
 *
 * Except for alphanumeric characters, escape all characters with ASCII values less than 256 with
 * the &#xHH; format (or a named entity if available) to prevent switching out of the attribute.
 */

function encodeForHTMLAttribute($input) {
  return hexEscapeString($input, '&#x{{hex}};');
}


/**
 * RULE #3 - JavaScript Escape Before Inserting Untrusted Data into JavaScript Data Values
 *
 * For dynamically generated JavaScript code - both script blocks and event-handler attributes.
 * The only safe place to put untrusted data into this code is inside a quoted "data value."
 *
 * Except for alphanumeric characters, escape all characters less than 256 with the \xHH format
 * to prevent switching out of the data value into the script context or into another attribute.
 * DO NOT use any escaping shortcuts like \" because the quote character may be matched by the
 * HTML attribute parser which runs first. These escaping shortcuts are also susceptible to
 * "escape-the-escape" attacks where the attacker sends \" and the vulnerable code turns that
 * into \\" which enables the quote.
 */

function encodeForJavaScript($input) {
  return hexEscapeString($input, '\x{{hex}}');
}


/**
 * RULE #4 - CSS Escape And Strictly Validate Before Inserting Untrusted Data into HTML Style Property Values
 *
 * When you want to put untrusted data into a stylesheet or a style tag. CSS is surprisingly powerful,
 * and can be used for numerous attacks. Therefore, it's important that you only use untrusted data in a
 * property value and not into other places in style data.
 *
 * Except for alphanumeric characters, escape all characters with ASCII values less than 256 with
 * the \HH escaping format. DO NOT use any escaping shortcuts like \" because the quote character may be
 * matched by the HTML attribute parser which runs first. These escaping shortcuts are also susceptible
 * to "escape-the-escape" attacks where the attacker sends \" and the vulnerable code turns that into \\" which
 * enables the quote.
 */

function encodeForCSS($input) {
  return hexEscapeString($input, '\{{hex}}');
}


/**
 * RULE #5 - URL Escape Before Inserting Untrusted Data into HTML URL Parameter Values
 *
 * When you want to put untrusted data into HTTP GET parameter value.
 *
 * Except for alphanumeric characters, escape all characters with ASCII values less than 256 with
 * the %HH escaping format. Including untrusted data in data: URLs should not be allowed as there is no
 * good way to disable attacks with escaping to prevent switching out of the URL. All attributes should
 * be quoted. Unquoted attributes can be broken out of with many characters
 * including [space] % * + , - / ; < = > ^ and |. Note that entity encoding is useless in this context.
 *
 * WARNING: Do not encode complete or relative URL's with this encoding! If untrusted input is meant to
 * be placed into href, src or other URL-based attributes, it should be validated to make sure it does
 * not point to an unexpected protocol, especially Javascript links. URL's should then be encoded based
 * on the context of display like any other piece of data. For example, user driven URL's in HREF links
 * should be attribute encoded (Rule #2).
 */

function encodeForURL($input) {
  return hexEscapeString($input, '%{{hex}}');
}


/**
 * Escapes all non-alphanumeric characters with ASCII value less than 256 with the $hexFormat
 * escaping format.
 */

function hexEscapeString($string, $hexFormat = '&#x{{hex}};') {
  if (!is_string($string)) {
    return '';
  }

  $hexTranslationTable = array();

  for ($charNum = 32; $charNum < 127; $charNum++) {
    if (!ctype_alnum(chr($charNum))) {
      $hex = str_pad(dechex($charNum), 2, '0', STR_PAD_LEFT);
      $hexTranslationTable[chr($charNum)] = str_replace('{{hex}}', $hex, $hexFormat);
    }
  }

  return strtr($string, $hexTranslationTable);
}

?>
