/**
 * ZeroMask Sample Datasets (samples.js)
 * Realistic mixed support ticket / resume / clinical note containing valid PII
 * alongside intentional decoy strings that must pass through unflagged.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.ZeroMask = root.ZeroMask || {};
    root.ZeroMask.samples = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // All credit cards pass Luhn + network prefix; all Aadhaar IDs pass Verhoeff;
  // all decoys intentionally fail validation or match non-PII formats.
  const SAMPLE_NOISY_TEXT = [
    '=== ESCALATION TICKET #SUP-2026-88412 (Mix: Support + Resume + Clinical Intake) ===',
    'Submitted via Web Portal (app version 1.2.3.4) from host 192.168.14.82',
    'Upstream proxy hop: 10.42.0.198 | IPv6 gateway: 2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    '',
    '1. APPLICANT / PATIENT CONTACT',
    'Name: Aarav Kulkarni',
    'Primary Email: aarav.kulkarni@finscale.io',
    'Backup Email: Aarav.Kulkarni@FinScale.IO (repeated with mixed case)',
    'HR Escalation: Priya.Sharma+urgent@medcare-ops.co.in',
    'Mobile (plain): 9876543210',
    'Mobile (spaced): 98765 43210',
    'Mobile (prefixed): +91-98201-44512 | Alt Landline/Mob: 09123456789',
    'US Relatives Contact: +1 (415) 555-0192 | UK Billing Desk: +44 20 7946 0958',
    '',
    '2. KYC & TAX IDENTIFIERS',
    'PAN Card (Individual): ABCPK1234F',
    'Corporate PAN (Company): AABCC9912K',
    'Aadhaar (spaced): 2345 6789 0124',
    'Aadhaar (hyphenated): 3456-7890-1238',
    'Aadhaar (plain): 456789012341',
    '',
    '3. BILLING & REIMBURSEMENT CARDS (LUHN VALID)',
    'Visa Corporate: 4532 7562 7962 4585',
    'Mastercard Backup: 5412-7512-3412-3452',
    'Amex Travel Card: 3782 822463 10005',
    '',
    '4. DECOY / NON-PII RECORDS (MUST NOT BE REDACTED)',
    'Order Reference: ORD-2026-998811223344 | Invoice: INV-4410-9876543210',
    'App Build: v1.2.3.4 (release 1.2.3.4) | Invalid IP probe: 999.1.1.1',
    'Failed Luhn 16-digit token: 4532 7562 7962 4589',
    'Failed Luhn test string: 5412-7512-3412-3459',
    'Failed Verhoeff 12-digit batch ID: 2345 6789 0125',
    'Timestamp log: 14:22:09 UTC | Follow-up email: aarav.kulkarni@finscale.io',
  ].join('\n');

  return {
    SAMPLE_NOISY_TEXT,
  };
});
