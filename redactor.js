/**
 * ZeroMask Redaction Engine (redactor.js)
 * Supports three redaction modes:
 *   1. full      - Fixed [REDACTED] or typed [REDACTED:TYPE] token
 *   2. partial   - Format-preserving context mask
 *   3. pseudonym - Consistent per-type normalized tokens (EMAIL_01, CARD_01, etc.)
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.ZeroMask = root.ZeroMask || {};
    root.ZeroMask.redactor = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const PSEUDONYM_PREFIX = {
    EMAIL: 'EMAIL',
    PHONE: 'PHONE',
    IP: 'IP',
    PAN: 'PAN',
    AADHAAR: 'AADHAAR',
    CREDIT_CARD: 'CARD',
  };

  /**
   * Normalizes an entity value so equivalent variants (e.g., spaced vs plain numbers,
   * uppercase vs lowercase emails) map to the same pseudonym ID.
   */
  function normalizeValue(type, value) {
    switch (type) {
      case 'EMAIL':
        return value.trim().toLowerCase();
      case 'PHONE':
      case 'AADHAAR':
      case 'CREDIT_CARD':
        return value.replace(/[\s\-().]/g, '');
      case 'PAN':
        return value.trim().toUpperCase();
      case 'IP':
        return value.trim().toLowerCase();
      default:
        return value.trim();
    }
  }

  function partialMaskEmail(value) {
    const atIndex = value.indexOf('@');
    if (atIndex <= 0) return '***@***';
    const local = value.slice(0, atIndex);
    const domain = value.slice(atIndex + 1);
    return local[0] + '***@' + domain;
  }

  function partialMaskPhone(value) {
    const trimmed = value.trim();
    const digits = trimmed.replace(/\D/g, '');
    const last4 = digits.slice(-4);

    // Preserve country code prefix if explicitly present (+91, +1, +44, etc.)
    const ccMatch = trimmed.match(/^\(?(\+\d{1,3})\)?/);
    if (ccMatch) {
      return ccMatch[1] + '-XXXXX-X' + last4;
    }
    if (digits.length === 11 && digits.startsWith('0')) {
      return '0-XXXXX-X' + last4;
    }
    return '+91-XXXXX-X' + last4;
  }

  function partialMaskIP(value) {
    if (value.includes(':')) {
      // IPv6: preserve first 2 non-empty segments where available
      const parts = value.split(':').filter((p) => p.length > 0);
      const head = parts.slice(0, 2).join(':') || '::';
      return head + ':XXXX:XXXX';
    }
    const octets = value.split('.');
    if (octets.length === 4) {
      return octets[0] + '.' + octets[1] + '.X.X';
    }
    return 'X.X.X.X';
  }

  function partialMaskPAN(value) {
    if (value.length !== 10) return 'XXXXXXXXXX';
    // First 2 characters + masked middle 7 + last 1 character (ABXXXXXXXF)
    return value.slice(0, 2) + 'XXXXXXX' + value.slice(9);
  }

  function partialMaskAadhaar(value) {
    const digits = value.replace(/\D/g, '');
    const last4 = digits.slice(-4);
    return 'XXXX-XXXX-' + last4;
  }

  function partialMaskCard(value) {
    const digits = value.replace(/\D/g, '');
    const last4 = digits.slice(-4);
    return 'XXXX-XXXX-XXXX-' + last4;
  }

  function formatPartial(type, value) {
    switch (type) {
      case 'EMAIL':
        return partialMaskEmail(value);
      case 'PHONE':
        return partialMaskPhone(value);
      case 'IP':
        return partialMaskIP(value);
      case 'PAN':
        return partialMaskPAN(value);
      case 'AADHAAR':
        return partialMaskAadhaar(value);
      case 'CREDIT_CARD':
        return partialMaskCard(value);
      default:
        return '[REDACTED]';
    }
  }

  function formatFullMask(type, typedTokens) {
    if (!typedTokens) return '[REDACTED]';
    const tag = PSEUDONYM_PREFIX[type] || type;
    return '[REDACTED:' + tag + ']';
  }

  function formatCounter(num) {
    return num < 10 ? '0' + num : String(num);
  }

  /**
   * Applies redactions in a single linear pass using array joins (safe for ~2 MB inputs).
   *
   * @param {string} text
   * @param {Array<{type: string, start: number, end: number, value: string, validation?: string}>} detections
   * @param {{ mode?: 'full'|'partial'|'pseudonym', typedTokens?: boolean }} [options]
   */
  function redactText(text, detections, options) {
    const opts = options || {};
    const mode = opts.mode || 'full';
    const typedTokens = Boolean(opts.typedTokens);

    if (!text || !detections || detections.length === 0) {
      return {
        redactedText: text || '',
        replacements: [],
        mapping: [],
        mappingObject: {},
      };
    }

    const parts = [];
    const replacements = [];
    const counters = {};
    const valueToPseudonym = new Map();
    const mapping = [];
    const mappingObject = {};

    let cursor = 0;
    let outLen = 0;

    for (let i = 0; i < detections.length; i++) {
      const det = detections[i];
      if (det.start < cursor) continue;

      if (det.start > cursor) {
        const unchanged = text.slice(cursor, det.start);
        parts.push(unchanged);
        outLen += unchanged.length;
      }

      let replacement;
      let normalizedKey = null;

      if (mode === 'partial') {
        replacement = formatPartial(det.type, det.value);
      } else if (mode === 'pseudonym') {
        normalizedKey = det.type + '::' + normalizeValue(det.type, det.value);
        if (valueToPseudonym.has(normalizedKey)) {
          const entry = valueToPseudonym.get(normalizedKey);
          entry.occurrences += 1;
          replacement = entry.pseudonym;
        } else {
          const nextIndex = (counters[det.type] || 0) + 1;
          counters[det.type] = nextIndex;
          const prefix = PSEUDONYM_PREFIX[det.type] || det.type;
          replacement = prefix + '_' + formatCounter(nextIndex);
          const entry = {
            type: det.type,
            pseudonym: replacement,
            normalized: normalizeValue(det.type, det.value),
            sampleOriginal: det.value,
            occurrences: 1,
          };
          valueToPseudonym.set(normalizedKey, entry);
          mapping.push(entry);
          mappingObject[replacement] = det.value;
        }
      } else {
        replacement = formatFullMask(det.type, typedTokens);
      }

      const outStart = outLen;
      parts.push(replacement);
      outLen += replacement.length;
      const outEnd = outLen;

      replacements.push({
        type: det.type,
        start: det.start,
        end: det.end,
        outStart,
        outEnd,
        value: det.value,
        replacement,
        validation: det.validation || '',
      });

      cursor = det.end;
    }

    if (cursor < text.length) {
      parts.push(text.slice(cursor));
    }

    return {
      redactedText: parts.join(''),
      replacements,
      mapping,
      mappingObject,
    };
  }

  return {
    PSEUDONYM_PREFIX,
    normalizeValue,
    formatPartial,
    formatFullMask,
    redactText,
  };
});
