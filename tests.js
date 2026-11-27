/**
 * ZeroMask Unit Test Suite (tests.js)
 * Runnable directly in Node (`node tests.js`) or in the browser via `tests.html`.
 */
(function (root) {
  'use strict';

  const isNode = typeof module !== 'undefined' && module.exports && typeof require === 'function';
  const detectors = isNode ? require('./detectors.js') : root.ZeroMask.detectors;
  const redactor = isNode ? require('./redactor.js') : root.ZeroMask.redactor;
  const samples = isNode ? require('./samples.js') : root.ZeroMask.samples;

  const {
    luhnCheck,
    verhoeffCheck,
    detectEmails,
    detectPhones,
    detectIPs,
    detectPANs,
    detectAadhaar,
    detectCreditCards,
    resolveOverlaps,
    scanText,
  } = detectors;
  const { redactText } = redactor;
  const { SAMPLE_NOISY_TEXT } = samples;

  const results = [];

  function assert(condition, message) {
    if (!condition) throw new Error(message || 'Assertion failed');
  }

  function assertEqual(actual, expected, message) {
    if (actual !== expected) {
      throw new Error((message ? message + ' — ' : '') + 'Expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
    }
  }

  function test(name, fn) {
    try {
      fn();
      results.push({ name, passed: true });
    } catch (err) {
      results.push({ name, passed: false, error: err.message });
    }
  }

  // --- Luhn Checksum ---
  test('Luhn: validates genuine Visa, Mastercard, and Amex numbers', () => {
    assert(luhnCheck('4532 7562 7962 4585'), 'Visa should pass');
    assert(luhnCheck('5412-7512-3412-3452'), 'Mastercard should pass');
    assert(luhnCheck('378282246310005'), 'Amex should pass');
  });

  test('Luhn: rejects invalid check digits, non-digits, and short strings', () => {
    assert(!luhnCheck('4532 7562 7962 4589'), 'Tampered Visa should fail');
    assert(!luhnCheck('5412-7512-3412-3459'), 'Tampered Mastercard should fail');
    assert(!luhnCheck('4'), 'Single digit should fail');
    assert(!luhnCheck('abcd1234'), 'Alpha chars should fail');
  });

  // --- Verhoeff Checksum ---
  test('Verhoeff: validates valid 12-digit Aadhaar checksums', () => {
    assert(verhoeffCheck('2345 6789 0124'), 'Spaced Aadhaar should pass');
    assert(verhoeffCheck('3456-7890-1238'), 'Hyphenated Aadhaar should pass');
    assert(verhoeffCheck('456789012341'), 'Plain Aadhaar should pass');
  });

  test('Verhoeff: catches single-digit errors and adjacent transpositions', () => {
    assert(!verhoeffCheck('2345 6789 0125'), 'Single digit mutation should fail');
    assert(!verhoeffCheck('2354 6789 0124'), 'Adjacent transposition (45->54) should fail');
    assert(!verhoeffCheck('123456'), 'Non-12 / invalid checksum fails');
  });

  // --- Email Detector ---
  test('Email detector: matches valid emails and skips malformed strings', () => {
    const matches = detectEmails('Reach aarav.k@finscale.io or Priya+1@med.co.in, not bad..dots@x.io or user@localhost');
    assertEqual(matches.length, 2, 'Email count');
    assertEqual(matches[0].value, 'aarav.k@finscale.io');
    assertEqual(matches[1].value, 'Priya+1@med.co.in');
  });

  // --- Phone Detector ---
  test('Phone detector: matches Indian and E.164 international formats', () => {
    const text = 'Call +91-98201-44512, 09123456789, 98765 43210, +1 (415) 555-0192, +44 20 7946 0958';
    const matches = detectPhones(text);
    assertEqual(matches.length, 5, 'Should detect all 5 phones');
  });

  test('Phone detector: ignores order IDs, invalid prefixes, cards, and Aadhaar', () => {
    const text = 'ORD-9876543210 | invalid 1234567890 | card 4532 7562 7962 4585 | aadhaar 2345 6789 0124';
    const matches = detectPhones(text);
    assertEqual(matches.length, 0, 'Should detect zero false-positive phones');
  });

  // --- IP Detector ---
  test('IP detector: matches valid IPv4 & IPv6, rejects out-of-range and version numbers', () => {
    const text = 'Hosts 192.168.1.10 and 2001:db8::1; ignore 999.1.1.1, v1.2.3.4, version 1.2.3.4, time 14:22:09';
    const matches = detectIPs(text);
    assertEqual(matches.length, 2, 'IP count');
    assertEqual(matches[0].value, '192.168.1.10');
    assertEqual(matches[1].value, '2001:db8::1');
  });

  // --- PAN Detector ---
  test('PAN detector: matches valid PANs and rejects invalid 4th-char entity codes', () => {
    const matches = detectPANs('Valid: ABCPK1234F, AABCC9912K. Invalid: ABCDE1234F, abcpk1234f');
    assertEqual(matches.length, 2, 'PAN count');
    assertEqual(matches[0].value, 'ABCPK1234F');
    assertEqual(matches[1].value, 'AABCC9912K');
  });

  // --- Aadhaar Detector ---
  test('Aadhaar detector: matches Verhoeff-valid 4-4-4 formats and rejects leading 0/1 or bad checksum', () => {
    const matches = detectAadhaar('2345 6789 0124 and 3456-7890-1238 and 456789012341; ignore 134567890124 and 2345 6789 0125');
    assertEqual(matches.length, 3, 'Aadhaar count');
  });

  // --- Credit Card Detector ---
  test('Credit Card detector: detects Visa/MC/Amex and rejects Luhn failures or unknown prefixes', () => {
    const matches = detectCreditCards('4532 7562 7962 4585 | 5412-7512-3412-3452 | 3782 822463 10005 | bad 4532 7562 7962 4589');
    assertEqual(matches.length, 3, 'Card count');
  });

  // --- Overlap Resolution ---
  test('Overlap resolution: enforces CREDIT_CARD > AADHAAR > PAN > EMAIL > IP > PHONE priority', () => {
    const resolved = resolveOverlaps([
      { type: 'PHONE', start: 0, end: 12, value: '987654321012' },
      { type: 'AADHAAR', start: 0, end: 12, value: '987654321012' },
      { type: 'EMAIL', start: 20, end: 35, value: 'a@b.com' },
      { type: 'IP', start: 22, end: 32, value: '1.2.3.4' },
    ]);
    assertEqual(resolved.length, 2);
    assertEqual(resolved[0].type, 'AADHAAR');
    assertEqual(resolved[1].type, 'EMAIL');
  });

  test('Overlap resolution: picks longer span when priorities are equal', () => {
    const resolved = resolveOverlaps([
      { type: 'PHONE', start: 4, end: 14, value: '9876543210' },
      { type: 'PHONE', start: 0, end: 14, value: '+91-9876543210' },
    ]);
    assertEqual(resolved.length, 1);
    assertEqual(resolved[0].value, '+91-9876543210');
  });

  // --- Redaction Modes & Pseudonymization ---
  test('Redaction modes: Full Mask (untyped & typed) and Partial Mask format properly', () => {
    const text = 'Email: jane@acme.io | PAN: ABCPK1234F | Card: 4532 7562 7962 4585 | IP: 192.168.14.82';
    const scan = scanText(text);

    const untyped = redactText(text, scan.detections, { mode: 'full', typedTokens: false });
    assert(untyped.redactedText.includes('[REDACTED]'), 'Untyped token');
    assert(!untyped.redactedText.includes('jane@acme.io'), 'Email removed');

    const typed = redactText(text, scan.detections, { mode: 'full', typedTokens: true });
    assert(typed.redactedText.includes('[REDACTED:EMAIL]'));
    assert(typed.redactedText.includes('[REDACTED:PAN]'));
    assert(typed.redactedText.includes('[REDACTED:CARD]'));
    assert(typed.redactedText.includes('[REDACTED:IP]'));

    const partial = redactText(text, scan.detections, { mode: 'partial' });
    assert(partial.redactedText.includes('j***@acme.io'), 'Partial email');
    assert(partial.redactedText.includes('ABXXXXXXXF'), 'Partial PAN');
    assert(partial.redactedText.includes('XXXX-XXXX-XXXX-4585'), 'Partial card');
    assert(partial.redactedText.includes('192.168.X.X'), 'Partial IP');
  });

  test('Pseudonymization: normalizes case and separators to maintain consistent IDs per type', () => {
    const text =
      'E1: Aarav@FinScale.IO | E2: aarav@finscale.io | E3: other@finscale.io | ' +
      'P1: 9876543210 | P2: 98765 43210 | A1: 2345 6789 0124 | A2: 2345-6789-0124';
    const scan = scanText(text);
    const out = redactText(text, scan.detections, { mode: 'pseudonym' });

    assert(out.redactedText.includes('E1: EMAIL_01 | E2: EMAIL_01 | E3: EMAIL_02'), 'Email normalization & counter');
    assert(out.redactedText.includes('P1: PHONE_01 | P2: PHONE_01'), 'Phone normalization');
    assert(out.redactedText.includes('A1: AADHAAR_01 | A2: AADHAAR_01'), 'Aadhaar normalization');
    assertEqual(out.mapping.length, 4, '4 unique normalized entities in mapping');
  });

  // --- Sample Noisy Text End-to-End ---
  test('Sample Noisy Text: detects all 6 entity types and rejects all decoys', () => {
    const scan = scanText(SAMPLE_NOISY_TEXT);
    assertEqual(scan.counts.EMAIL, 4, 'Sample emails');
    assertEqual(scan.counts.PHONE, 6, 'Sample phones');
    assertEqual(scan.counts.IP, 3, 'Sample IPs');
    assertEqual(scan.counts.PAN, 2, 'Sample PANs');
    assertEqual(scan.counts.AADHAAR, 3, 'Sample Aadhaar');
    assertEqual(scan.counts.CREDIT_CARD, 3, 'Sample Credit Cards');
    assert(scan.rejectedCount >= 4, 'Should track rejected Luhn/Verhoeff/IP/version candidates');
  });

  // Output / Export for Node & Browser
  if (isNode) {
    let passed = 0;
    let failed = 0;
    for (const r of results) {
      if (r.passed) {
        passed++;
        console.log('PASS:', r.name);
      } else {
        failed++;
        console.error('FAIL:', r.name, '->', r.error);
      }
    }
    console.log('\nTotal:', results.length, '| Passed:', passed, '| Failed:', failed);
    if (failed > 0) process.exit(1);
  } else if (root) {
    root.ZeroMask = root.ZeroMask || {};
    root.ZeroMask.testResults = results;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
