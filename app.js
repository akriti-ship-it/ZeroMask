/**
 * ZeroMask Application Controller (app.js)
 * Coordinates UI state, debounced scanning, XSS-safe DOM highlight rendering,
 * synchronized scrolling, FileReader ingestion, audit tables, and Blob exports.
 */
(function () {
  'use strict';

  const { ENTITY_TYPES, ENTITY_META, scanText } = window.ZeroMask.detectors;
  const { redactText, formatPartial } = window.ZeroMask.redactor;
  const { SAMPLE_NOISY_TEXT } = window.ZeroMask.samples;

  const DEBOUNCE_MS = 150;
  const MAX_HIGHLIGHT_DOM_SPANS = 4000;
  const MAX_AUDIT_TABLE_ROWS = 500;

  const DEFAULT_ENABLED = {
    EMAIL: true,
    PHONE: true,
    IP: true,
    PAN: true,
    AADHAAR: true,
    CREDIT_CARD: true,
  };

  const MODE_DESCRIPTIONS = {
    full: {
      badge: 'Full Mask',
      desc: 'Replaces every detected entity with a fixed token so no character structure leaks.',
      examples: ['[REDACTED]', '[REDACTED:EMAIL]'],
    },
    partial: {
      badge: 'Partial Mask',
      desc: 'Masks sensitive cores while keeping limited verification context (e.g. PAN first 2 + last 1: ABXXXXXXXF, Card/Aadhaar/Phone last 4).',
      examples: ['XXXX-XXXX-XXXX-1234', 'ABXXXXXXXF', 'j***@domain.com', '192.168.X.X'],
    },
    pseudonym: {
      badge: 'Pseudonymize',
      desc: 'Maps normalized equivalent values to deterministic per-type IDs across the document (memory-only lookup table).',
      examples: ['EMAIL_01', 'PHONE_01', 'CARD_01', 'AADHAAR_01'],
    },
  };

  const VALIDATION_STRATEGY_LABELS = {
    EMAIL: 'RFC-style pattern + domain TLD check',
    PHONE: 'IN (+91/0, 6-9) & E.164 with digit-boundary guard',
    IP: 'IPv4 (0–255) + version-context filter & IPv6',
    PAN: '^[A-Z]{5}[0-9]{4}[A-Z]$ + 4th-char entity code',
    AADHAAR: '12 digits (start 2–9) + Verhoeff D5 checksum',
    CREDIT_CARD: '13–19 digits + Luhn mod-10 + network prefix',
  };

  const state = {
    rawText: '',
    fileName: 'Untitled input',
    fileExt: 'txt',
    fileSizeBytes: 0,
    mode: 'full',
    typedTokens: true,
    enabledTypes: { ...DEFAULT_ENABLED },
    revealDetails: false,
    revealMapping: false,
    activeAuditTab: 'summary',
    lastScan: null,
    lastRedact: null,
  };

  // DOM References
  const el = {
    navLinks: document.querySelectorAll('.nav-link'),
    views: {
      workspace: document.getElementById('view-workspace'),
      rules: document.getElementById('view-rules'),
      'how-it-works': document.getElementById('view-how-it-works'),
    },
    themeToggleBtn: document.getElementById('themeToggleBtn'),
    errorBanner: document.getElementById('errorBanner'),
    errorBannerText: document.getElementById('errorBannerText'),
    dismissErrorBtn: document.getElementById('dismissErrorBtn'),

    statTotalDetected: document.getElementById('statTotalDetected'),
    statTypesFound: document.getElementById('statTypesFound'),
    statRejected: document.getElementById('statRejected'),
    statSanitized: document.getElementById('statSanitized'),
    statModeBadge: document.getElementById('statModeBadge'),
    distributionBar: document.getElementById('distributionBar'),
    legendCounts: {
      EMAIL: document.getElementById('legendCountEmail'),
      PHONE: document.getElementById('legendCountPhone'),
      IP: document.getElementById('legendCountIP'),
      PAN: document.getElementById('legendCountPAN'),
      AADHAAR: document.getElementById('legendCountAadhaar'),
      CREDIT_CARD: document.getElementById('legendCountCard'),
    },

    workspaceGrid: document.getElementById('workspaceGrid'),
    collapseSidebarBtn: document.getElementById('collapseSidebarBtn'),
    detectorInputs: document.querySelectorAll('input[name="detector"]'),
    toggleAllDetectorsBtn: document.getElementById('toggleAllDetectorsBtn'),
    segButtons: document.querySelectorAll('.seg-btn'),
    modeDescription: document.getElementById('modeDescription'),
    modeExamples: document.getElementById('modeExamples'),
    typedTokenGroup: document.getElementById('typedTokenGroup'),
    typedTokenSwitchRow: document.querySelector('#typedTokenGroup .switch-row'),
    typedTokenToggle: document.getElementById('typedTokenToggle'),
    resetConfigBtn: document.getElementById('resetConfigBtn'),

    mobileTabs: document.querySelectorAll('.mobile-tab'),
    originalPanel: document.getElementById('originalPanel'),
    sanitizedPanel: document.getElementById('sanitizedPanel'),

    fileMetaPill: document.getElementById('fileMetaPill'),
    fileInput: document.getElementById('fileInput'),
    uploadFileBtn: document.getElementById('uploadFileBtn'),
    loadSampleBtn: document.getElementById('loadSampleBtn'),
    clearInputBtn: document.getElementById('clearInputBtn'),
    emptyLoadSampleBtn: document.getElementById('emptyLoadSampleBtn'),
    emptyUploadBtn: document.getElementById('emptyUploadBtn'),

    originalDropZone: document.getElementById('originalDropZone'),
    dragOverlay: document.getElementById('dragOverlay'),
    originalEmptyState: document.getElementById('originalEmptyState'),
    originalGutter: document.getElementById('originalGutter'),
    originalBackdrop: document.getElementById('originalBackdrop'),
    rawInput: document.getElementById('rawInput'),

    processingStatusPill: document.getElementById('processingStatusPill'),
    processingStatusText: document.getElementById('processingStatusText'),
    copyOutputBtn: document.getElementById('copyOutputBtn'),
    downloadSanitizedBtn: document.getElementById('downloadSanitizedBtn'),
    sanitizedEmptyState: document.getElementById('sanitizedEmptyState'),
    noPiiBanner: document.getElementById('noPiiBanner'),
    sanitizedGutter: document.getElementById('sanitizedGutter'),
    sanitizedScroll: document.getElementById('sanitizedScroll'),
    sanitizedOutput: document.getElementById('sanitizedOutput'),

    auditSection: document.getElementById('auditSection'),
    toggleAuditBtn: document.getElementById('toggleAuditBtn'),
    auditTabs: document.querySelectorAll('.audit-tab'),
    auditPanes: {
      summary: document.getElementById('tab-summary'),
      details: document.getElementById('tab-details'),
      mapping: document.getElementById('tab-mapping'),
      validation: document.getElementById('tab-validation'),
    },
    tabCountDetails: document.getElementById('tabCountDetails'),
    tabCountMapping: document.getElementById('tabCountMapping'),
    tabCountValidation: document.getElementById('tabCountValidation'),

    summaryTableBody: document.getElementById('summaryTableBody'),
    detailsTableBody: document.getElementById('detailsTableBody'),
    mappingTableBody: document.getElementById('mappingTableBody'),
    validationTableBody: document.getElementById('validationTableBody'),

    revealValuesBtn: document.getElementById('revealValuesBtn'),
    revealMappingBtn: document.getElementById('revealMappingBtn'),
    downloadAuditBtn: document.getElementById('downloadAuditBtn'),
    downloadMappingBtn: document.getElementById('downloadMappingBtn'),

    entityTooltip: document.getElementById('entityTooltip'),
    tooltipType: document.getElementById('tooltipType'),
    tooltipValidation: document.getElementById('tooltipValidation'),
    tooltipReplacement: document.getElementById('tooltipReplacement'),

    mappingWarningModal: document.getElementById('mappingWarningModal'),
    cancelMappingExportBtn: document.getElementById('cancelMappingExportBtn'),
    confirmMappingExportBtn: document.getElementById('confirmMappingExportBtn'),
    toastContainer: document.getElementById('toastContainer'),
  };

  let debounceTimer = null;
  let scrollSyncing = false;

  // ---------- Utilities ----------

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  function countLines(text) {
    if (!text) return 1;
    let lines = 1;
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) lines++;
    }
    return lines;
  }

  function buildLineNumbersText(lineCount) {
    const arr = new Array(lineCount);
    for (let i = 0; i < lineCount; i++) {
      arr[i] = String(i + 1);
    }
    return arr.join('\n');
  }

  function maskForAudit(value) {
    if (!value) return '••••';
    if (value.length <= 4) return '••••';
    return '••••••' + value.slice(-2);
  }

  function animateStatValue(node, target) {
    const start = Number(node.dataset.currentVal || 0);
    if (start === target) return;
    node.dataset.currentVal = String(target);

    const reducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reducedMotion || Math.abs(target - start) <= 1) {
      node.textContent = target.toLocaleString();
      return;
    }

    const duration = 160;
    const startTime = performance.now();
    function frame(now) {
      const progress = Math.min(1, (now - startTime) / duration);
      const val = Math.round(start + (target - start) * progress);
      node.textContent = val.toLocaleString();
      if (progress < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  function showToast(message, variant) {
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + (variant || 'success');
    toast.textContent = message;
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 2800);
  }

  function showError(message) {
    el.errorBannerText.textContent = message;
    el.errorBanner.hidden = false;
    showToast(message, 'error');
  }

  function hideError() {
    el.errorBanner.hidden = true;
  }

  function triggerBlobDownload(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ---------- Safe Highlight Rendering (Zero innerHTML of user content) ----------

  function renderHighlightedPane(container, text, items, isSanitized) {
    container.textContent = '';
    if (!text) return;

    const frag = document.createDocumentFragment();
    let cursor = 0;
    const limit = Math.min(items.length, MAX_HIGHLIGHT_DOM_SPANS);

    for (let i = 0; i < limit; i++) {
      const item = items[i];
      const start = isSanitized ? item.outStart : item.start;
      const end = isSanitized ? item.outEnd : item.end;
      if (start < cursor) continue;

      if (start > cursor) {
        frag.appendChild(document.createTextNode(text.slice(cursor, start)));
      }

      const mark = document.createElement('mark');
      mark.className = 'pii-mark pii-' + item.type + (isSanitized ? ' sanitized-mark' : '');
      mark.dataset.idx = String(i);
      mark.textContent = text.slice(start, end);
      frag.appendChild(mark);
      cursor = end;
    }

    if (cursor < text.length) {
      frag.appendChild(document.createTextNode(text.slice(cursor)));
    }

    // Match textarea trailing newline height
    if (text.endsWith('\n')) {
      frag.appendChild(document.createTextNode('\n'));
    }

    container.appendChild(frag);
  }

  // ---------- Main Processing Pipeline ----------

  function updateMetadataBar() {
    const chars = state.rawText.length;
    const bytes = state.fileSizeBytes || new Blob([state.rawText]).size;
    el.fileMetaPill.textContent =
      state.fileName + ' · ' + formatBytes(bytes) + ' · ' + chars.toLocaleString() + ' chars';
  }

  function updateModeInfo() {
    const info = MODE_DESCRIPTIONS[state.mode];
    el.modeDescription.textContent = info.desc;
    el.modeExamples.textContent = '';
    const prefix = document.createTextNode('Examples: ');
    el.modeExamples.appendChild(prefix);
    info.examples.forEach((ex, i) => {
      if (i > 0) el.modeExamples.appendChild(document.createTextNode(' · '));
      const code = document.createElement('code');
      code.textContent = ex;
      el.modeExamples.appendChild(code);
    });

    const isFull = state.mode === 'full';
    el.typedTokenToggle.disabled = !isFull;
    el.typedTokenSwitchRow.classList.toggle('is-disabled', !isFull);
    el.statModeBadge.textContent = info.badge;
  }

  function processNow() {
    const text = state.rawText;
    const hasText = text.length > 0;

    el.originalEmptyState.hidden = hasText;
    el.sanitizedEmptyState.hidden = hasText;
    el.clearInputBtn.disabled = !hasText;
    el.copyOutputBtn.disabled = !hasText;
    el.downloadSanitizedBtn.disabled = !hasText;
    el.downloadAuditBtn.disabled = !hasText;

    el.clearInputBtn.title = hasText ? 'Clear editor' : 'No text to clear';
    el.copyOutputBtn.title = hasText ? 'Copy sanitized output to clipboard' : 'Enter text to copy sanitized output';
    el.downloadSanitizedBtn.title = hasText
      ? 'Download sanitized.' + state.fileExt
      : 'Enter text to download sanitized file';
    el.downloadAuditBtn.title = hasText
      ? 'Download zero-PII audit report JSON'
      : 'Scan text to export a zero-PII audit report';

    updateMetadataBar();

    const t0 = performance.now();
    const scanResult = scanText(text, state.enabledTypes);
    const redactResult = redactText(text, scanResult.detections, {
      mode: state.mode,
      typedTokens: state.typedTokens,
    });
    const elapsedMs = Math.max(1, Math.round(performance.now() - t0));

    state.lastScan = scanResult;
    state.lastRedact = redactResult;

    // Gutters
    el.originalGutter.textContent = buildLineNumbersText(countLines(text));
    el.sanitizedGutter.textContent = buildLineNumbersText(countLines(redactResult.redactedText));

    // Render highlight panes safely
    renderHighlightedPane(el.originalBackdrop, text, redactResult.replacements, false);
    renderHighlightedPane(el.sanitizedOutput, redactResult.redactedText, redactResult.replacements, true);

    // Sync banner & status
    el.noPiiBanner.hidden = !hasText || scanResult.totalCount > 0;
    el.processingStatusPill.classList.remove('is-processing');
    el.processingStatusPill.classList.add('is-done');
    el.processingStatusText.textContent = hasText ? 'Secured in ' + elapsedMs + 'ms' : 'Ready';

    // Update stats & distribution
    updateStatsAndDistribution(scanResult);

    // Update audit tables
    renderAuditTables(scanResult, redactResult);
  }

  function scheduleProcess(immediate) {
    clearTimeout(debounceTimer);
    if (immediate) {
      processNow();
      return;
    }
    el.processingStatusPill.classList.remove('is-done');
    el.processingStatusPill.classList.add('is-processing');
    el.processingStatusText.textContent = 'Scanning…';
    debounceTimer = setTimeout(processNow, DEBOUNCE_MS);
  }

  function updateStatsAndDistribution(scan) {
    const counts = scan.counts;
    let activeTypesFound = 0;
    ENTITY_TYPES.forEach((t) => {
      const c = counts[t] || 0;
      if (c > 0) activeTypesFound++;
      const badge = document.getElementById('count' + t);
      if (badge) badge.textContent = c.toLocaleString();
      if (el.legendCounts[t]) el.legendCounts[t].textContent = c.toLocaleString();
    });

    animateStatValue(el.statTotalDetected, scan.totalCount);
    animateStatValue(el.statTypesFound, activeTypesFound);
    animateStatValue(el.statRejected, scan.rejectedCount);
    animateStatValue(el.statSanitized, scan.totalCount);

    // Distribution bar
    el.distributionBar.textContent = '';
    if (scan.totalCount === 0) {
      const empty = document.createElement('div');
      empty.className = 'dist-empty';
      empty.textContent = 'No sensitive entities detected yet';
      el.distributionBar.appendChild(empty);
      return;
    }

    const order = ['EMAIL', 'PHONE', 'IP', 'PAN', 'AADHAAR', 'CREDIT_CARD'];
    order.forEach((type) => {
      const count = counts[type] || 0;
      if (count <= 0) return;
      const pct = (count / scan.totalCount) * 100;
      const seg = document.createElement('div');
      seg.className = 'dist-segment seg-' + type;
      seg.style.width = pct.toFixed(2) + '%';
      seg.title = ENTITY_META[type].label + ': ' + count + ' (' + pct.toFixed(1) + '%)';
      el.distributionBar.appendChild(seg);
    });
  }

  // ---------- Audit Tables (DOM-safe) ----------

  function createPill(type) {
    const span = document.createElement('span');
    span.className = 'entity-pill pill-' + type;
    span.textContent = ENTITY_META[type] ? ENTITY_META[type].label : type;
    return span;
  }

  function renderAuditTables(scan, redact) {
    el.tabCountDetails.textContent = String(redact.replacements.length);
    el.tabCountMapping.textContent = String(redact.mapping.length);
    el.tabCountValidation.textContent = String(scan.rejectedCount);

    const canExportMapping = state.mode === 'pseudonym' && redact.mapping.length > 0;
    el.downloadMappingBtn.disabled = !canExportMapping;
    el.downloadMappingBtn.title = canExportMapping
      ? 'Export in-memory pseudonym lookup table as JSON'
      : 'Switch to Pseudonym mode with detected entities to export mapping';

    // 1. Summary Table
    el.summaryTableBody.textContent = '';
    const summaryOrder = ['EMAIL', 'PHONE', 'IP', 'PAN', 'AADHAAR', 'CREDIT_CARD'];
    const sampleInputs = {
      EMAIL: 'jane.doe@company.io',
      PHONE: '+91 98765 43210',
      IP: '192.168.14.82',
      PAN: 'ABCPK1234F',
      AADHAAR: '2345 6789 0124',
      CREDIT_CARD: '4532 7562 7962 4585',
    };
    summaryOrder.forEach((type) => {
      const tr = document.createElement('tr');
      const c = scan.counts[type] || 0;
      const share = scan.totalCount > 0 ? ((c / scan.totalCount) * 100).toFixed(1) + '%' : '0%';

      const tdType = document.createElement('td');
      tdType.appendChild(createPill(type));
      tr.appendChild(tdType);

      const tdCount = document.createElement('td');
      tdCount.className = 'mono-cell';
      tdCount.textContent = String(c);
      tr.appendChild(tdCount);

      const tdShare = document.createElement('td');
      tdShare.className = 'mono-cell';
      tdShare.textContent = share;
      tr.appendChild(tdShare);

      const tdStrat = document.createElement('td');
      tdStrat.textContent = VALIDATION_STRATEGY_LABELS[type];
      tr.appendChild(tdStrat);

      const tdSample = document.createElement('td');
      tdSample.className = 'mono-cell';
      tdSample.textContent = formatPartial(type, sampleInputs[type]);
      tr.appendChild(tdSample);

      el.summaryTableBody.appendChild(tr);
    });

    // 2. Entity Details Table
    el.detailsTableBody.textContent = '';
    if (redact.replacements.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'table-empty';
      td.textContent = 'No detected entities to display.';
      tr.appendChild(td);
      el.detailsTableBody.appendChild(tr);
    } else {
      const limit = Math.min(redact.replacements.length, MAX_AUDIT_TABLE_ROWS);
      for (let i = 0; i < limit; i++) {
        const r = redact.replacements[i];
        const tr = document.createElement('tr');

        const tdIdx = document.createElement('td');
        tdIdx.className = 'mono-cell';
        tdIdx.textContent = String(i + 1);
        tr.appendChild(tdIdx);

        const tdType = document.createElement('td');
        tdType.appendChild(createPill(r.type));
        tr.appendChild(tdType);

        const tdSpan = document.createElement('td');
        tdSpan.className = 'mono-cell';
        tdSpan.textContent = r.start + '–' + r.end;
        tr.appendChild(tdSpan);

        const tdVal = document.createElement('td');
        const badge = document.createElement('span');
        badge.className = 'badge-valid';
        badge.textContent = r.validation || 'Valid';
        tdVal.appendChild(badge);
        tr.appendChild(tdVal);

        const tdOrig = document.createElement('td');
        tdOrig.className = 'mono-cell';
        tdOrig.textContent = state.revealDetails ? r.value : maskForAudit(r.value);
        tr.appendChild(tdOrig);

        const tdRep = document.createElement('td');
        tdRep.className = 'mono-cell';
        tdRep.textContent = r.replacement;
        tr.appendChild(tdRep);

        el.detailsTableBody.appendChild(tr);
      }
    }

    // 3. Pseudonym Mapping Table
    el.mappingTableBody.textContent = '';
    if (redact.mapping.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'table-empty';
      td.textContent =
        state.mode === 'pseudonym'
          ? 'No entities mapped yet.'
          : 'Switch Redaction Mode to "Pseudonym" to generate a consistent mapping table.';
      tr.appendChild(td);
      el.mappingTableBody.appendChild(tr);
    } else {
      redact.mapping.forEach((m) => {
        const tr = document.createElement('tr');

        const tdId = document.createElement('td');
        tdId.className = 'mono-cell';
        tdId.textContent = m.pseudonym;
        tr.appendChild(tdId);

        const tdType = document.createElement('td');
        tdType.appendChild(createPill(m.type));
        tr.appendChild(tdType);

        const tdNorm = document.createElement('td');
        tdNorm.className = 'mono-cell';
        tdNorm.textContent = state.revealMapping ? m.normalized : maskForAudit(m.normalized);
        tr.appendChild(tdNorm);

        const tdOcc = document.createElement('td');
        tdOcc.className = 'mono-cell';
        tdOcc.textContent = String(m.occurrences);
        tr.appendChild(tdOcc);

        const tdOrig = document.createElement('td');
        tdOrig.className = 'mono-cell';
        tdOrig.textContent = state.revealMapping ? m.sampleOriginal : maskForAudit(m.sampleOriginal);
        tr.appendChild(tdOrig);

        el.mappingTableBody.appendChild(tr);
      });
    }

    // 4. Validation Report Table
    el.validationTableBody.textContent = '';
    if (scan.rejectedItems.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'table-empty';
      td.textContent = 'No candidate patterns rejected by validation checks.';
      tr.appendChild(td);
      el.validationTableBody.appendChild(tr);
    } else {
      const limit = Math.min(scan.rejectedItems.length, MAX_AUDIT_TABLE_ROWS);
      for (let i = 0; i < limit; i++) {
        const rej = scan.rejectedItems[i];
        const tr = document.createElement('tr');

        const tdIdx = document.createElement('td');
        tdIdx.className = 'mono-cell';
        tdIdx.textContent = String(i + 1);
        tr.appendChild(tdIdx);

        const tdType = document.createElement('td');
        tdType.appendChild(createPill(rej.type));
        tr.appendChild(tdType);

        const tdOff = document.createElement('td');
        tdOff.className = 'mono-cell';
        tdOff.textContent = rej.start + '–' + rej.end;
        tr.appendChild(tdOff);

        const tdReason = document.createElement('td');
        tdReason.textContent = rej.reason;
        tr.appendChild(tdReason);

        const tdAction = document.createElement('td');
        const b = document.createElement('span');
        b.className = 'badge-rejected';
        b.textContent = 'Ignored (Not PII)';
        tdAction.appendChild(b);
        tr.appendChild(tdAction);

        el.validationTableBody.appendChild(tr);
      }
    }
  }

  // ---------- Tooltip Handling ----------

  function showTooltipForMark(mark, clientX, clientY) {
    if (!mark || !state.lastRedact) {
      el.entityTooltip.hidden = true;
      return;
    }
    const idx = Number(mark.dataset.idx);
    const item = state.lastRedact.replacements[idx];
    if (!item) {
      el.entityTooltip.hidden = true;
      return;
    }

    el.tooltipType.textContent = ENTITY_META[item.type] ? ENTITY_META[item.type].label : item.type;
    el.tooltipValidation.textContent = item.validation || 'Matched';
    el.tooltipReplacement.textContent = 'Sanitized -> ' + item.replacement;

    el.entityTooltip.hidden = false;
    const pad = 12;
    const rect = el.entityTooltip.getBoundingClientRect();
    let x = clientX + 14;
    let y = clientY + 16;
    if (x + rect.width + pad > window.innerWidth) {
      x = Math.max(pad, clientX - rect.width - 12);
    }
    if (y + rect.height + pad > window.innerHeight) {
      y = Math.max(pad, clientY - rect.height - 12);
    }
    el.entityTooltip.style.left = x + 'px';
    el.entityTooltip.style.top = y + 'px';
  }

  function hideTooltip() {
    el.entityTooltip.hidden = true;
  }

  // ---------- Synchronized Scrolling ----------

  function syncFromOriginal() {
    el.originalBackdrop.scrollTop = el.rawInput.scrollTop;
    el.originalBackdrop.scrollLeft = el.rawInput.scrollLeft;
    el.originalGutter.scrollTop = el.rawInput.scrollTop;

    if (scrollSyncing) return;
    scrollSyncing = true;
    el.sanitizedScroll.scrollTop = el.rawInput.scrollTop;
    el.sanitizedGutter.scrollTop = el.rawInput.scrollTop;
    requestAnimationFrame(() => {
      scrollSyncing = false;
    });
  }

  function syncFromSanitized() {
    el.sanitizedGutter.scrollTop = el.sanitizedScroll.scrollTop;

    if (scrollSyncing) return;
    scrollSyncing = true;
    el.rawInput.scrollTop = el.sanitizedScroll.scrollTop;
    el.originalBackdrop.scrollTop = el.sanitizedScroll.scrollTop;
    el.originalGutter.scrollTop = el.sanitizedScroll.scrollTop;
    requestAnimationFrame(() => {
      scrollSyncing = false;
    });
  }

  // ---------- File Handling ----------

  function handleFile(file) {
    if (!file) return;
    const match = file.name.match(/\.(txt|csv)$/i);
    if (!match) {
      showError('Unsupported file format. Please upload a TXT or CSV file.');
      return;
    }

    hideError();
    const ext = match[1].toLowerCase();
    const reader = new FileReader();
    reader.onload = function (ev) {
      state.rawText = typeof ev.target.result === 'string' ? ev.target.result : '';
      state.fileName = file.name;
      state.fileExt = ext;
      state.fileSizeBytes = file.size;
      el.rawInput.value = state.rawText;
      scheduleProcess(true);
      showToast('Loaded ' + file.name + ' locally', 'success');
    };
    reader.onerror = function () {
      showError('Could not read file. Please check file permissions and try again.');
    };
    reader.readAsText(file);
  }

  // ---------- Event Wiring ----------

  function bindEvents() {
    // Primary Navigation
    el.navLinks.forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetView = btn.dataset.view;
        el.navLinks.forEach((b) => b.classList.toggle('is-active', b === btn));
        Object.keys(el.views).forEach((key) => {
          el.views[key].hidden = key !== targetView;
        });
      });
    });

    // Theme Toggle
    el.themeToggleBtn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
    });

    el.dismissErrorBtn.addEventListener('click', hideError);

    // Sidebar collapse
    el.collapseSidebarBtn.addEventListener('click', () => {
      const collapsed = el.workspaceGrid.classList.toggle('is-sidebar-collapsed');
      el.collapseSidebarBtn.setAttribute('aria-expanded', String(!collapsed));
      el.collapseSidebarBtn.title = collapsed ? 'Expand configuration sidebar' : 'Collapse configuration sidebar';
    });

    // Entity checkboxes
    el.detectorInputs.forEach((cb) => {
      cb.addEventListener('change', () => {
        state.enabledTypes[cb.value] = cb.checked;
        scheduleProcess(true);
      });
    });

    el.toggleAllDetectorsBtn.addEventListener('click', () => {
      const allOn = ENTITY_TYPES.every((t) => state.enabledTypes[t]);
      const next = !allOn;
      el.detectorInputs.forEach((cb) => {
        cb.checked = next;
        state.enabledTypes[cb.value] = next;
      });
      scheduleProcess(true);
    });

    // Redaction mode segmented control
    el.segButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        state.mode = btn.dataset.mode;
        el.segButtons.forEach((b) => {
          const active = b === btn;
          b.classList.toggle('is-active', active);
          b.setAttribute('aria-checked', String(active));
        });
        updateModeInfo();
        scheduleProcess(true);
      });
    });

    // Typed token toggle
    el.typedTokenToggle.addEventListener('change', () => {
      state.typedTokens = el.typedTokenToggle.checked;
      scheduleProcess(true);
    });

    // Reset configuration
    el.resetConfigBtn.addEventListener('click', () => {
      state.mode = 'full';
      state.typedTokens = true;
      state.enabledTypes = { ...DEFAULT_ENABLED };
      el.detectorInputs.forEach((cb) => {
        cb.checked = true;
      });
      el.typedTokenToggle.checked = true;
      el.segButtons.forEach((b) => {
        const active = b.dataset.mode === 'full';
        b.classList.toggle('is-active', active);
        b.setAttribute('aria-checked', String(active));
      });
      updateModeInfo();
      scheduleProcess(true);
      showToast('Configuration reset to defaults', 'success');
    });

    // Mobile tabs
    el.mobileTabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const target = tab.dataset.pane;
        el.mobileTabs.forEach((t) => {
          const active = t === tab;
          t.classList.toggle('is-active', active);
          t.setAttribute('aria-selected', String(active));
        });
        el.originalPanel.classList.toggle('is-mobile-active', target === 'original');
        el.sanitizedPanel.classList.toggle('is-mobile-active', target === 'sanitized');
      });
    });

    // Input textarea
    el.rawInput.addEventListener('input', () => {
      state.rawText = el.rawInput.value;
      state.fileSizeBytes = new Blob([state.rawText]).size;
      if (state.fileName === 'Untitled input' && !state.rawText) {
        state.fileExt = 'txt';
      }
      scheduleProcess(false);
    });

    el.rawInput.addEventListener('scroll', syncFromOriginal);
    el.sanitizedScroll.addEventListener('scroll', syncFromSanitized);

    // Hover tooltips on Original (through transparent textarea via elementsFromPoint) & Sanitized
    el.rawInput.addEventListener('mousemove', (e) => {
      const els = document.elementsFromPoint(e.clientX, e.clientY);
      const mark = els.find((node) => node.classList && node.classList.contains('pii-mark'));
      showTooltipForMark(mark, e.clientX, e.clientY);
    });
    el.rawInput.addEventListener('mouseleave', hideTooltip);

    el.sanitizedOutput.addEventListener('mousemove', (e) => {
      const mark = e.target && e.target.closest ? e.target.closest('.pii-mark') : null;
      showTooltipForMark(mark, e.clientX, e.clientY);
    });
    el.sanitizedOutput.addEventListener('mouseleave', hideTooltip);

    // Load sample & Clear
    function loadSample() {
      hideError();
      state.rawText = SAMPLE_NOISY_TEXT;
      state.fileName = 'sample_noisy_ticket.txt';
      state.fileExt = 'txt';
      state.fileSizeBytes = new Blob([SAMPLE_NOISY_TEXT]).size;
      el.rawInput.value = SAMPLE_NOISY_TEXT;
      scheduleProcess(true);
      showToast('Sample noisy dataset loaded', 'success');
    }

    el.loadSampleBtn.addEventListener('click', loadSample);
    el.emptyLoadSampleBtn.addEventListener('click', loadSample);

    el.clearInputBtn.addEventListener('click', () => {
      hideError();
      state.rawText = '';
      state.fileName = 'Untitled input';
      state.fileExt = 'txt';
      state.fileSizeBytes = 0;
      el.rawInput.value = '';
      el.fileInput.value = '';
      scheduleProcess(true);
    });

    // File Upload button & Drag-and-Drop
    el.uploadFileBtn.addEventListener('click', () => el.fileInput.click());
    el.emptyUploadBtn.addEventListener('click', () => el.fileInput.click());
    el.fileInput.addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      handleFile(file);
      el.fileInput.value = '';
    });

    let dragDepth = 0;
    el.originalDropZone.addEventListener('dragenter', (e) => {
      e.preventDefault();
      dragDepth++;
      el.dragOverlay.hidden = false;
    });
    el.originalDropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
    });
    el.originalDropZone.addEventListener('dragleave', () => {
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) el.dragOverlay.hidden = true;
    });
    el.originalDropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dragDepth = 0;
      el.dragOverlay.hidden = true;
      const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      handleFile(file);
    });

    // Copy & Export buttons
    el.copyOutputBtn.addEventListener('click', async () => {
      if (!state.lastRedact) return;
      const output = state.lastRedact.redactedText;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(output);
        } else {
          const tmp = document.createElement('textarea');
          tmp.value = output;
          tmp.style.position = 'fixed';
          tmp.style.opacity = '0';
          document.body.appendChild(tmp);
          tmp.select();
          document.execCommand('copy');
          tmp.remove();
        }
        showToast('Sanitized output copied to clipboard', 'success');
      } catch (_err) {
        showToast('Clipboard copy blocked by browser settings', 'error');
      }
    });

    el.downloadSanitizedBtn.addEventListener('click', () => {
      if (!state.lastRedact) return;
      const filename = state.fileExt === 'csv' ? 'sanitized.csv' : 'sanitized.txt';
      const mime = state.fileExt === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8';
      triggerBlobDownload(state.lastRedact.redactedText, filename, mime);
      showToast('Downloaded ' + filename, 'success');
    });

    el.downloadAuditBtn.addEventListener('click', () => {
      if (!state.lastScan) return;
      // Zero-PII audit report: counts, mode, timestamp, and non-PII rejection reasons only
      const report = {
        tool: 'ZeroMask',
        generatedAt: new Date().toISOString(),
        mode: state.mode,
        typedTokens: state.mode === 'full' ? state.typedTokens : null,
        sourceFile: state.fileName,
        totalEntitiesDetected: state.lastScan.totalCount,
        countsByType: state.lastScan.counts,
        rejectedByValidation: state.lastScan.rejectedCount,
        rejectedByType: state.lastScan.rejectedByType,
        validationEvents: state.lastScan.rejectedItems.map((r) => ({
          type: r.type,
          span: r.start + '-' + r.end,
          reason: r.reason,
        })),
      };
      triggerBlobDownload(
        JSON.stringify(report, null, 2),
        'zeromask-audit-report.json',
        'application/json;charset=utf-8'
      );
      showToast('Downloaded zero-PII audit report', 'success');
    });

    // Audit section collapse & tabs
    el.toggleAuditBtn.addEventListener('click', () => {
      const collapsed = el.auditSection.classList.toggle('is-collapsed');
      el.toggleAuditBtn.setAttribute('aria-expanded', String(!collapsed));
    });

    el.auditTabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        state.activeAuditTab = tab.dataset.tab;
        el.auditTabs.forEach((t) => {
          const active = t === tab;
          t.classList.toggle('is-active', active);
          t.setAttribute('aria-selected', String(active));
        });
        Object.keys(el.auditPanes).forEach((k) => {
          el.auditPanes[k].hidden = k !== state.activeAuditTab;
        });
      });
    });

    el.revealValuesBtn.addEventListener('click', () => {
      state.revealDetails = !state.revealDetails;
      el.revealValuesBtn.setAttribute('aria-pressed', String(state.revealDetails));
      el.revealValuesBtn.textContent = state.revealDetails ? 'Hide Original Values' : 'Reveal Original Values';
      if (state.lastScan && state.lastRedact) renderAuditTables(state.lastScan, state.lastRedact);
    });

    el.revealMappingBtn.addEventListener('click', () => {
      state.revealMapping = !state.revealMapping;
      el.revealMappingBtn.setAttribute('aria-pressed', String(state.revealMapping));
      el.revealMappingBtn.textContent = state.revealMapping ? 'Hide Originals' : 'Reveal Originals';
      if (state.lastScan && state.lastRedact) renderAuditTables(state.lastScan, state.lastRedact);
    });

    // Pseudonym mapping export privacy warning modal
    el.downloadMappingBtn.addEventListener('click', () => {
      el.mappingWarningModal.hidden = false;
      el.cancelMappingExportBtn.focus();
    });
    el.cancelMappingExportBtn.addEventListener('click', () => {
      el.mappingWarningModal.hidden = true;
    });
    el.mappingWarningModal.addEventListener('click', (e) => {
      if (e.target === el.mappingWarningModal) el.mappingWarningModal.hidden = true;
    });
    el.confirmMappingExportBtn.addEventListener('click', () => {
      el.mappingWarningModal.hidden = true;
      if (!state.lastRedact || state.lastRedact.mapping.length === 0) return;
      const payload = {
        warning: 'SENSITIVE: Contains raw unredacted PII mappings. Store separately from sanitized output.',
        generatedAt: new Date().toISOString(),
        sourceFile: state.fileName,
        mapping: state.lastRedact.mapping.map((m) => ({
          pseudonym: m.pseudonym,
          type: m.type,
          normalized: m.normalized,
          originalValue: m.sampleOriginal,
          occurrences: m.occurrences,
        })),
      };
      triggerBlobDownload(
        JSON.stringify(payload, null, 2),
        'zeromask-pseudonym-mapping.json',
        'application/json;charset=utf-8'
      );
      showToast('Exported pseudonym mapping JSON', 'success');
    });
  }

  // Initialize
  updateModeInfo();
  bindEvents();
  processNow();
})();
