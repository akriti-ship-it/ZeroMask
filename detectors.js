/**
 * ZeroMask Detection Engine (detectors.js)
 * 100% client-side, deterministic PII detection with checksum validation
 * (Luhn for payment cards, Verhoeff for Aadhaar) and priority overlap resolution.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.ZeroMask = root.ZeroMask || {};
    root.ZeroMask.detectors = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const ENTITY_TYPES = ['CREDIT_CARD', 'AADHAAR', 'PAN', 'EMAIL', 'IP', 'PHONE'];

  // Overlap resolution priority: CREDIT_CARD > AADHAAR > PAN > EMAIL > IP > PHONE
  const ENTITY_PRIORITY = {
    CREDIT_CARD: 6,
    AADHAAR: 5,
    PAN: 4,
    EMAIL: 3,
    IP: 2,
    PHONE: 1,
  };

  const ENTITY_META = {
    EMAIL: { label: 'Email', short: 'Email', tokenPrefix: 'EMAIL', colorKey: 'email' },
    PHONE: { label: 'Phone', short: 'Phone', tokenPrefix: 'PHONE', colorKey: 'phone' },
    IP: { label: 'IP Address', short: 'IP', tokenPrefix: 'IP', colorKey: 'ip' },
    PAN: { label: 'PAN', short: 'PAN', tokenPrefix: 'PAN', colorKey: 'pan' },
    AADHAAR: { label: 'Aadhaar', short: 'Aadhaar', tokenPrefix: 'AADHAAR', colorKey: 'aadhaar' },
    CREDIT_CARD: { label: 'Credit Card', short: 'Card', tokenPrefix: 'CARD', colorKey: 'card' },
  };

  // Valid 4th character entity-type codes for Indian PAN numbers
  const PAN_ENTITY_TYPES = new Set(['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G']);

  // Verhoeff dihedral group D5 multiplication table
  const VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
  ];

  // Verhoeff permutation table indexed by (position mod 8) and digit
  const VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
  ];

  /**
   * Validates a numeric string using the Luhn (mod-10) checksum algorithm.
   * Strips optional spaces and hyphens before evaluation.
   *
   * @param {string} value - Candidate card number or digit sequence.
   * @returns {boolean} True when the input is >= 2 digits and passes Luhn mod-10.
   */
  function luhnCheck(value) {
    if (typeof value !== 'string') return false;
    const digits = value.replace(/[\s-]/g, '');
    if (digits.length < 2 || !/^\d+$/.test(digits)) return false;

    let sum = 0;
    let shouldDouble = false;

    // Traverse from rightmost check digit toward the most significant digit
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = digits.charCodeAt(i) - 48;
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }

    return sum % 10 === 0;
  }

  /**
   * Validates a numeric string using the Verhoeff checksum algorithm (D5 dihedral group).
   * Used by UIDAI to detect all single-digit and adjacent-transposition errors in Aadhaar IDs.
   *
   * @param {string} value - Candidate 12-digit Aadhaar number (with or without spaces/hyphens).
   * @returns {boolean} True when the checksum reduces to the identity element (0).
   */
  function verhoeffCheck(value) {
    if (typeof value !== 'string') return false;
    const digits = value.replace(/[\s-]/g, '');
    if (digits.length < 2 || !/^\d+$/.test(digits)) return false;

    let c = 0;
    const len = digits.length;

    // Iterate right-to-left: index 0 is the check digit itself
    for (let i = 0; i < len; i++) {
      const digit = digits.charCodeAt(len - 1 - i) - 48;
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
    }

    return c === 0;
  }

  /**
   * Checks whether a digit-only card string matches a plausible network prefix and length.
   * Supports Visa, Mastercard, Amex, Discover, and RuPay.
   *
   * @param {string} digits - Digit-only string.
   * @returns {string|null} Network name if plausible, otherwise null.
   */
  function identifyCardNetwork(digits) {
    const len = digits.length;
    if (len < 13 || len > 19) return null;

    // Amex: 34, 37 (length 15)
    if ((digits.startsWith('34') || digits.startsWith('37')) && len === 15) {
      return 'Amex';
    }

    // Visa: 4 (length 13, 16, 19)
    if (digits.startsWith('4') && (len === 13 || len === 16 || len === 19)) {
      return 'Visa';
    }

    // Mastercard: 51-55 or 2221-2720 (length 16)
    const prefix2 = Number(digits.slice(0, 2));
    const prefix4 = Number(digits.slice(0, 4));
    if (len === 16 && ((prefix2 >= 51 && prefix2 <= 55) || (prefix4 >= 2221 && prefix4 <= 2720))) {
      return 'Mastercard';
    }

    // Discover: 6011, 644-649, 65 (length 16 or 19)
    const prefix3 = Number(digits.slice(0, 3));
    if (
      (len === 16 || len === 19) &&
      (digits.startsWith('6011') || (prefix3 >= 644 && prefix3 <= 649) || digits.startsWith('65'))
    ) {
      return 'Discover';
    }

    // RuPay: 60, 6521, 6522, 81, 82, 508 (length 16)
    if (
      len === 16 &&
      (digits.startsWith('60') ||
        digits.startsWith('6521') ||
        digits.startsWith('6522') ||
        digits.startsWith('81') ||
        digits.startsWith('82') ||
        digits.startsWith('508'))
    ) {
      return 'RuPay';
    }

    return null;
  }

  function isAlnumChar(ch) {
    if (!ch) return false;
    const code = ch.charCodeAt(0);
    return (
      (code >= 48 && code <= 57) ||
      (code >= 65 && code <= 90) ||
      (code >= 97 && code <= 122)
    );
  }

  function isDigitChar(ch) {
    if (!ch) return false;
    const code = ch.charCodeAt(0);
    return code >= 48 && code <= 57;
  }

  function detectEmails(text) {
    const results = [];
    const regex =
      /(?<![A-Za-z0-9._%+-])([A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,24})(?![A-Za-z0-9._%+-])/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[1];
      if (value.includes('..')) continue;
      results.push({
        type: 'EMAIL',
        start: match.index,
        end: match.index + value.length,
        value,
        validation: 'RFC pattern valid',
      });
    }
    return results;
  }

  function detectPANs(text, rejections) {
    const results = [];
    const regex = /(?<![A-Za-z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Za-z0-9])/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      const entityChar = value[3];
      if (!PAN_ENTITY_TYPES.has(entityChar)) {
        if (rejections) {
          rejections.push({
            type: 'PAN',
            start: match.index,
            end: match.index + value.length,
            reason: 'Invalid PAN 4th-character entity code (' + entityChar + ')',
          });
        }
        continue;
      }
      results.push({
        type: 'PAN',
        start: match.index,
        end: match.index + value.length,
        value,
        validation: 'Format + entity code (' + entityChar + ')',
      });
    }
    return results;
  }

  function detectAadhaar(text, rejections) {
    const results = [];
    // Consistent separator (either spaces, hyphens, or none) for 4-4-4 grouping starting 2-9
    const regex = /(?<![\dA-Za-z+.])([2-9]\d{3}(?:([ -]?)\d{4}\2\d{4}))(?![ -]?\d)(?![A-Za-z.])/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[1];
      const start = match.index;
      const prevChar = start > 0 ? text[start - 1] : '';
      const prevPrevChar = start > 1 ? text[start - 2] : '';

      // Avoid matching inside a hyphenated ID (e.g., ORD-234567890123) or middle of spaced digits
      if (prevChar === '-' && isAlnumChar(prevPrevChar)) continue;
      if ((prevChar === ' ' || prevChar === '-') && isDigitChar(prevPrevChar)) continue;

      if (!verhoeffCheck(value)) {
        if (rejections) {
          rejections.push({
            type: 'AADHAAR',
            start,
            end: start + value.length,
            reason: 'Failed Verhoeff checksum',
          });
        }
        continue;
      }

      results.push({
        type: 'AADHAAR',
        start,
        end: start + value.length,
        value,
        validation: 'Verhoeff valid',
      });
    }
    return results;
  }

  function detectCreditCards(text, rejections) {
    const results = [];
    // 13 to 19 digits with optional single space or hyphen separators
    const regex = /(?<![\dA-Za-z.])\d(?:[ -]?\d){12,18}(?![\dA-Za-z.])/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      const start = match.index;
      const prevChar = start > 0 ? text[start - 1] : '';
      const prevPrevChar = start > 1 ? text[start - 2] : '';
      const end = start + value.length;
      const nextChar = end < text.length ? text[end] : '';
      const nextNextChar = end + 1 < text.length ? text[end + 1] : '';

      // Ignore alphanumeric token suffixes like ORD-12345678901234 or trailing -ABC
      if (prevChar === '-' && isAlnumChar(prevPrevChar)) continue;
      if (nextChar === '-' && isAlnumChar(nextNextChar)) continue;

      const digits = value.replace(/[\s-]/g, '');
      const luhnOk = luhnCheck(digits);
      const network = identifyCardNetwork(digits);

      if (!luhnOk || !network) {
        if (rejections) {
          rejections.push({
            type: 'CREDIT_CARD',
            start,
            end,
            reason: !luhnOk ? 'Failed Luhn checksum' : 'Unrecognized card prefix/length',
          });
        }
        continue;
      }

      results.push({
        type: 'CREDIT_CARD',
        start,
        end,
        value,
        validation: 'Luhn valid · ' + network,
      });
    }
    return results;
  }

  function isValidIPv6(candidate) {
    if (!candidate || !candidate.includes(':')) return false;
    // Reject simple timestamps like 12:30:45 (only single colons and < 7 colons)
    const hasDoubleColon = candidate.includes('::');
    if (hasDoubleColon && candidate.indexOf('::') !== candidate.lastIndexOf('::')) {
      return false;
    }

    const halves = candidate.split('::');
    const leftParts = halves[0] ? halves[0].split(':') : [];
    const rightParts = halves.length === 2 && halves[1] ? halves[1].split(':') : [];

    // Support IPv4-mapped suffix like ::ffff:192.0.2.128
    const checkHexGroup = (g) => /^[0-9a-fA-F]{1,4}$/.test(g);

    if (!hasDoubleColon) {
      if (leftParts.length !== 8) return false;
      return leftParts.every(checkHexGroup);
    }

    // With ::, total non-empty groups must be <= 7 (and at least 1 group or ::1)
    const totalGroups = leftParts.length + rightParts.length;
    if (totalGroups > 7 || totalGroups === 0) return false;

    // Handle optional IPv4 tail on right side
    if (rightParts.length > 0 && rightParts[rightParts.length - 1].includes('.')) {
      const ipv4Tail = rightParts[rightParts.length - 1];
      const octets = ipv4Tail.split('.');
      if (
        octets.length !== 4 ||
        !octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) >= 0 && Number(o) <= 255)
      ) {
        return false;
      }
      const hexRight = rightParts.slice(0, -1);
      return totalGroups + 1 <= 7 && leftParts.every(checkHexGroup) && hexRight.every(checkHexGroup);
    }

    return leftParts.every(checkHexGroup) && rightParts.every(checkHexGroup);
  }

  function detectIPs(text, rejections) {
    const results = [];

    // IPv4 detection with 0-255 octet validation and version-number filtering
    const ipv4Regex = /(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])/g;
    let match;
    while ((match = ipv4Regex.exec(text)) !== null) {
      const value = match[0];
      const start = match.index;
      const end = start + value.length;

      // Check preceding context to avoid flagging software version numbers like v1.2.3.4 or version 1.2.3.4
      const prevChar = start > 0 ? text[start - 1] : '';
      if (prevChar === 'v' || prevChar === 'V' || isAlnumChar(prevChar)) {
        if (rejections && (prevChar === 'v' || prevChar === 'V')) {
          rejections.push({
            type: 'IP',
            start,
            end,
            reason: 'Version string context (v-prefix)',
          });
        }
        continue;
      }

      const lookback = text.slice(Math.max(0, start - 24), start);
      if (/\b(?:version|ver|release|rel|build|rev|sdk|app)\.?\s*[:=#-]?\s*$/i.test(lookback)) {
        if (rejections) {
          rejections.push({
            type: 'IP',
            start,
            end,
            reason: 'Version number context',
          });
        }
        continue;
      }

      const octets = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])];
      const validOctets = octets.every((o) => o >= 0 && o <= 255);
      if (!validOctets) {
        if (rejections) {
          rejections.push({
            type: 'IP',
            start,
            end,
            reason: 'IPv4 octet out of range (0-255)',
          });
        }
        continue;
      }

      results.push({
        type: 'IP',
        start,
        end,
        value,
        validation: 'IPv4 valid (0-255)',
      });
    }

    // IPv6 detection (full 8-group or :: compressed)
    const ipv6Regex = /(?<![A-Za-z0-9:])((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:\.\d{1,3}){0,3})(?![A-Za-z0-9:])/g;
    while ((match = ipv6Regex.exec(text)) !== null) {
      const value = match[1];
      if (!isValidIPv6(value)) continue;
      results.push({
        type: 'IP',
        start: match.index,
        end: match.index + value.length,
        value,
        validation: 'IPv6 valid',
      });
    }

    return results;
  }

  function detectPhones(text) {
    const results = [];
    const seen = new Set();

    function tryPush(start, end, value, validation) {
      // Boundary protection: prevent matching inside longer digit strings, cards, Aadhaar, or order IDs
      const prevChar = start > 0 ? text[start - 1] : '';
      const prevPrevChar = start > 1 ? text[start - 2] : '';
      const nextChar = end < text.length ? text[end] : '';
      const nextNextChar = end + 1 < text.length ? text[end + 1] : '';

      if (isDigitChar(prevChar) || isAlnumChar(prevChar)) return;
      if (isDigitChar(nextChar) || isAlnumChar(nextChar)) return;
      if ((prevChar === ' ' || prevChar === '-') && isDigitChar(prevPrevChar)) return;
      if ((nextChar === ' ' || nextChar === '-') && isDigitChar(nextNextChar)) return;
      // Avoid matching suffixes of alphanumeric IDs like ORD-9876543210
      if (prevChar === '-' && isAlnumChar(prevPrevChar)) return;

      const key = start + ':' + end;
      if (seen.has(key)) return;
      seen.add(key);

      results.push({
        type: 'PHONE',
        start,
        end,
        value,
        validation,
      });
    }

    // 1. Indian numbers: +91 / (+91) / 0 prefix or 10 digits starting 6-9 with optional spaces/hyphens
    const indianRegex =
      /(?:(?:\(\+91\)|\+91)[\s-]?|0[\s-]?)?[6-9](?:\d{9}|\d{4}[\s-]\d{5}|\d{2}[\s-]\d{3}[\s-]\d{4}|\d{3}[\s-]\d{3}[\s-]\d{3})/g;
    let match;
    while ((match = indianRegex.exec(text)) !== null) {
      const value = match[0];
      const digits = value.replace(/\D/g, '');
      const localDigits = digits.startsWith('91') && digits.length === 12
        ? digits.slice(2)
        : digits.startsWith('0') && digits.length === 11
          ? digits.slice(1)
          : digits;
      if (localDigits.length !== 10 || !/^[6-9]/.test(localDigits)) continue;
      tryPush(match.index, match.index + value.length, value, 'IN phone format valid');
    }

    // 2. International E.164-style numbers: +<country code 1-9> followed by 7-14 digits (total 8-15 digits)
    const intlRegex = /\+[1-9](?:[\s.-]?\(?\d{1,4}\)?){1,5}[\s.-]?\d{2,10}/g;
    while ((match = intlRegex.exec(text)) !== null) {
      const value = match[0];
      // Reject unbalanced parentheses like "+1 (415"
      const openParens = (value.match(/\(/g) || []).length;
      const closeParens = (value.match(/\)/g) || []).length;
      if (openParens !== closeParens) continue;

      const digits = value.replace(/\D/g, '');
      if (digits.length < 8 || digits.length > 15) continue;
      tryPush(match.index, match.index + value.length, value, 'E.164 international valid');
    }

    return results;
  }

  /**
   * Resolves overlapping detections by priority (CREDIT_CARD > AADHAAR > PAN > EMAIL > IP > PHONE)
   * and then by longer span length. Returns detections sorted by start offset ascending.
   */
  function resolveOverlaps(detections) {
    if (!Array.isArray(detections) || detections.length === 0) return [];

    const ranked = detections.slice().sort((a, b) => {
      const prioDiff = (ENTITY_PRIORITY[b.type] || 0) - (ENTITY_PRIORITY[a.type] || 0);
      if (prioDiff !== 0) return prioDiff;
      const lenDiff = b.end - b.start - (a.end - a.start);
      if (lenDiff !== 0) return lenDiff;
      return a.start - b.start;
    });

    const accepted = [];
    for (let i = 0; i < ranked.length; i++) {
      const cand = ranked[i];
      let overlaps = false;
      for (let j = 0; j < accepted.length; j++) {
        const existing = accepted[j];
        if (cand.start < existing.end && existing.start < cand.end) {
          overlaps = true;
          break;
        }
      }
      if (!overlaps) {
        accepted.push(cand);
      }
    }

    accepted.sort((a, b) => a.start - b.start);
    return accepted;
  }

  /**
   * Scans input text across all enabled PII detectors, resolves overlaps,
   * and aggregates per-type counts and validation rejections.
   *
   * @param {string} text
   * @param {Object<string, boolean>} [enabledTypes]
   */
  function scanText(text, enabledTypes) {
    const counts = {
      EMAIL: 0,
      PHONE: 0,
      IP: 0,
      PAN: 0,
      AADHAAR: 0,
      CREDIT_CARD: 0,
    };

    if (!text) {
      return {
        detections: [],
        counts,
        totalCount: 0,
        rejectedCount: 0,
        rejectedByType: { CREDIT_CARD: 0, AADHAAR: 0, PAN: 0, IP: 0 },
        rejectedItems: [],
      };
    }

    const enabled = enabledTypes || {
      EMAIL: true,
      PHONE: true,
      IP: true,
      PAN: true,
      AADHAAR: true,
      CREDIT_CARD: true,
    };

    const raw = [];
    const rejections = [];

    if (enabled.CREDIT_CARD) raw.push(...detectCreditCards(text, rejections));
    if (enabled.AADHAAR) raw.push(...detectAadhaar(text, rejections));
    if (enabled.PAN) raw.push(...detectPANs(text, rejections));
    if (enabled.EMAIL) raw.push(...detectEmails(text));
    if (enabled.IP) raw.push(...detectIPs(text, rejections));
    if (enabled.PHONE) raw.push(...detectPhones(text));

    const detections = resolveOverlaps(raw);

    for (let i = 0; i < detections.length; i++) {
      counts[detections[i].type] = (counts[detections[i].type] || 0) + 1;
    }

    // Filter out rejection candidates that overlap an accepted entity (e.g., 12-digit slice of a valid 16-digit card)
    const filteredRejections = rejections.filter((rej) => {
      for (let i = 0; i < detections.length; i++) {
        const det = detections[i];
        if (rej.start < det.end && det.start < rej.end) return false;
      }
      return true;
    });

    // Deduplicate overlapping rejections at identical spans
    const uniqueRejections = [];
    const rejKeys = new Set();
    for (let i = 0; i < filteredRejections.length; i++) {
      const r = filteredRejections[i];
      const key = r.type + ':' + r.start + ':' + r.end;
      if (!rejKeys.has(key)) {
        rejKeys.add(key);
        uniqueRejections.push(r);
      }
    }

    const rejectedByType = { CREDIT_CARD: 0, AADHAAR: 0, PAN: 0, IP: 0 };
    for (let i = 0; i < uniqueRejections.length; i++) {
      const t = uniqueRejections[i].type;
      rejectedByType[t] = (rejectedByType[t] || 0) + 1;
    }

    return {
      detections,
      counts,
      totalCount: detections.length,
      rejectedCount: uniqueRejections.length,
      rejectedByType,
      rejectedItems: uniqueRejections,
    };
  }

  return {
    ENTITY_TYPES,
    ENTITY_PRIORITY,
    ENTITY_META,
    luhnCheck,
    verhoeffCheck,
    identifyCardNetwork,
    detectEmails,
    detectPhones,
    detectIPs,
    detectPANs,
    detectAadhaar,
    detectCreditCards,
    resolveOverlaps,
    scanText,
  };
});
