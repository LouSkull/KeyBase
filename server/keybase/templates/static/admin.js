var pendingConfirmAction = null;
var faqController = null;
var toastTimers = new WeakMap();

function ensureToastViewport() {
  var existing = document.querySelector('[data-toast-viewport]');
  if (existing) return existing;
  var viewport = document.createElement('section');
  viewport.className = 'toast-viewport';
  viewport.setAttribute('data-toast-viewport', '');
  viewport.setAttribute('aria-live', 'polite');
  viewport.setAttribute('aria-atomic', 'false');
  document.body.appendChild(viewport);
  return viewport;
}

function toastIcon(type) {
  if (type === 'success') return '✓';
  if (type === 'error') return '×';
  if (type === 'warning') return '!';
  return 'i';
}

function clearToastTimer(toast) {
  var timer = toastTimers.get(toast);
  if (timer) window.clearTimeout(timer);
  toastTimers.delete(toast);
}

function closeToast(toast) {
  if (!toast || toast.dataset.closing === '1') return;
  toast.dataset.closing = '1';
  clearToastTimer(toast);
  toast.classList.remove('is-visible');
  toast.classList.add('is-closing');
  window.setTimeout(function () {
    if (toast && toast.parentNode) toast.parentNode.removeChild(toast);
  }, 280);
}

function armToastTimer(toast) {
  clearToastTimer(toast);
  toastTimers.set(toast, window.setTimeout(function () {
    closeToast(toast);
  }, 5000));
}

function showToast(config) {
  if (!config || !config.message) return;
  var viewport = ensureToastViewport();
  var type = /^(success|error|warning|info)$/.test(config.type || '') ? config.type : 'info';
  var toast = document.createElement('article');
  toast.className = 'toast toast-' + type;
  toast.setAttribute('role', 'status');
  toast.innerHTML =
    '<div class="toast-icon" aria-hidden="true">' + toastIcon(type) + '</div>' +
    '<div class="toast-body">' +
      (config.title ? '<strong class="toast-title">' + escapeHtml(config.title) + '</strong>' : '') +
      '<div class="toast-message">' + escapeHtml(config.message) + '</div>' +
    '</div>' +
    '<button class="toast-close" type="button" aria-label="Close notification">×</button>';
  viewport.appendChild(toast);
  var closeButton = toast.querySelector('.toast-close');
  if (closeButton) {
    closeButton.addEventListener('click', function () {
      closeToast(toast);
    });
  }
  toast.addEventListener('mouseenter', function () {
    clearToastTimer(toast);
  });
  toast.addEventListener('mouseleave', function () {
    armToastTimer(toast);
  });
  window.requestAnimationFrame(function () {
    toast.classList.add('is-visible');
  });
  armToastTimer(toast);
}

function feedbackMessageForCopy(target) {
  var label = target.getAttribute('data-copy-label') || target.getAttribute('aria-label') || 'Value';
  label = String(label).replace(/^Copy\s+/i, '').trim() || 'Value';
  return label + ' copied.';
}

function flashCopyState(target) {
  target.classList.add('copied');
  var hint = target.querySelector('.copy-chip-hint');
  var oldHint = hint ? hint.textContent : '';
  if (hint) hint.textContent = 'copied';
  window.setTimeout(function () {
    target.classList.remove('copied');
    if (hint) hint.textContent = oldHint || 'copy';
  }, 1000);
}

function writeClipboardText(text, onDone) {
  function finish() {
    if (typeof onDone === 'function') onDone();
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(finish).catch(function () {
      finish();
    });
    return;
  }
  var textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  try { document.execCommand('copy'); } catch (err) {}
  document.body.removeChild(textarea);
  finish();
}

function valueFromCopySource(target) {
  var selector = target.getAttribute('data-copy-source') || '';
  if (!selector) return '';
  var source = document.querySelector(selector);
  if (!source) return '';
  if (typeof source.value === 'string') return source.value;
  return source.textContent || '';
}

function handleCopyTarget(target) {
  var text = target.hasAttribute('data-copy-source') ? valueFromCopySource(target) : (target.getAttribute('data-copy-value') || '');
  if (!String(text || '').length) {
    showToast({ type: 'warning', message: 'Nothing to copy yet.' });
    return;
  }
  writeClipboardText(text, function () {
    flashCopyState(target);
    showToast({ type: 'success', message: feedbackMessageForCopy(target) });
  });
}

function syncSecretFieldState(field) {
  if (!field) return;
  var input = field.querySelector('[data-secret-input]');
  var toggle = field.querySelector('[data-secret-toggle]');
  var copyButton = field.querySelector('[data-copy-source]');
  if (!input) return;
  var disabled = !!input.disabled;
  var empty = !String(input.value || '').length;
  field.classList.toggle('is-disabled', disabled);
  if (toggle) {
    toggle.disabled = disabled;
    toggle.textContent = input.type === 'text' ? (toggle.getAttribute('data-hide-label') || 'Hide') : (toggle.getAttribute('data-show-label') || 'Show');
  }
  if (copyButton) copyButton.disabled = disabled || empty;
}

function setupSecretField(field) {
  if (!field) return;
  var input = field.querySelector('[data-secret-input]');
  if (!input) return;
  if (input.dataset.secretBound !== '1') {
    input.dataset.secretBound = '1';
    input.addEventListener('input', function () {
      syncSecretFieldState(field);
    });
    input.addEventListener('change', function () {
      syncSecretFieldState(field);
    });
  }
  syncSecretFieldState(field);
}

function setupSecretModeForm(form) {
  var mode = form.querySelector('[data-secret-mode]');
  var group = form.querySelector('[data-secret-mode-group]');
  if (!mode || !group) return;
  var input = group.querySelector('[data-secret-input]');
  if (!input) return;
  var controls = group.querySelectorAll('input, button');

  function syncSecretMode() {
    var enabled = mode.value === 'replace';
    controls.forEach(function (node) {
      if (node === input) {
        node.disabled = !enabled;
        node.required = enabled;
      } else {
        node.disabled = !enabled;
      }
    });
    syncSecretFieldState(group.querySelector('[data-secret-field]') || group);
  }

  mode.addEventListener('change', syncSecretMode);
  syncSecretMode();
}

function showInitialToastsFromUrl() {
  if (!window.URLSearchParams) return;
  var params = new URLSearchParams(window.location.search || '');
  var messages = params.getAll('toast');
  if (!messages.length) return;
  var types = params.getAll('toast_type');
  messages.forEach(function (message, index) {
    showToast({ type: types[index] || types[0] || 'info', message: message });
  });
  params.delete('toast');
  params.delete('toast_type');
  var nextQuery = params.toString();
  var nextUrl = window.location.pathname + (nextQuery ? '?' + nextQuery : '') + window.location.hash;
  try { window.history.replaceState(null, '', nextUrl); } catch (err) {}
}

function showConfirmAction(config) {
  pendingConfirmAction = config;
  var modal = document.getElementById('confirm-action');
  var heading = document.getElementById('confirm-action-heading');
  var message = document.getElementById('confirm-action-message');
  var button = document.getElementById('confirm-action-continue');
  if (!modal || !button) return;
  if (heading) heading.textContent = config.title || 'Are you sure?';
  if (message) message.textContent = config.message || 'This action needs confirmation.';
  button.textContent = config.label || 'Continue';
  modal.hidden = false;
}

function closeModalFrom(target) {
  var modal = target.closest('.modal');
  if (modal) modal.hidden = true;
}

document.addEventListener('click', function (event) {
  var copyTarget = event.target.closest('[data-copy-value], [data-copy-source]');
  if (copyTarget) {
    event.preventDefault();
    event.stopPropagation();
    handleCopyTarget(copyTarget);
    return;
  }

  var secretToggle = event.target.closest('[data-secret-toggle]');
  if (secretToggle) {
    event.preventDefault();
    var secretField = secretToggle.closest('[data-secret-field]');
    var secretInput = secretField ? secretField.querySelector('[data-secret-input]') : null;
    if (!secretInput || secretInput.disabled) return;
    secretInput.type = secretInput.type === 'password' ? 'text' : 'password';
    syncSecretFieldState(secretField);
    return;
  }

  var confirmOpen = event.target.closest('[data-confirm-open-modal]');
  if (confirmOpen) {
    event.preventDefault();
    event.stopPropagation();
    showConfirmAction({
      kind: 'open',
      target: confirmOpen.getAttribute('data-confirm-open-modal'),
      title: confirmOpen.getAttribute('data-confirm-title'),
      message: confirmOpen.getAttribute('data-confirm-message'),
      label: confirmOpen.getAttribute('data-confirm-label')
    });
    return;
  }

  var open = event.target.closest('[data-open-modal]');
  if (open) {
    var modal = document.getElementById(open.getAttribute('data-open-modal'));
    if (modal) modal.hidden = false;
  }
  if (event.target.closest('[data-close-modal]')) {
    closeModalFrom(event.target);
  }

  var rowLink = event.target.closest('[data-row-link]');
  if (rowLink) {
    if (event.target.closest('a, button, input, select, textarea, label, summary, [data-open-modal], [data-copy-value]')) return;
    var href = rowLink.getAttribute('data-row-link');
    if (href) window.location.href = href;
  }
});

document.addEventListener('submit', function (event) {
  var form = event.target.closest('form[data-confirm-submit]');
  if (!form) return;
  if (form.dataset.confirmed === '1') {
    delete form.dataset.confirmed;
    return;
  }
  event.preventDefault();
  showConfirmAction({
    kind: 'submit',
    form: form,
    title: form.getAttribute('data-confirm-title'),
    message: form.getAttribute('data-confirm-message'),
    label: form.getAttribute('data-confirm-label')
  });
});

var confirmContinue = document.getElementById('confirm-action-continue');
if (confirmContinue) {
  confirmContinue.addEventListener('click', function () {
    var action = pendingConfirmAction;
    pendingConfirmAction = null;
    var confirmModal = document.getElementById('confirm-action');
    if (confirmModal) confirmModal.hidden = true;
    if (!action) return;
    if (action.kind === 'open') {
      var targetModal = document.getElementById(action.target);
      if (targetModal) targetModal.hidden = false;
      return;
    }
    if (action.kind === 'submit' && action.form) {
      action.form.dataset.confirmed = '1';
      if (action.form.requestSubmit) action.form.requestSubmit();
      else action.form.submit();
    }
  });
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('keybase-theme', theme); } catch (err) {}
}

var themeSelect = document.getElementById('theme-select');
if (themeSelect) {
  try { themeSelect.value = localStorage.getItem('keybase-theme') || 'classic'; } catch (err) { themeSelect.value = 'classic'; }
  themeSelect.addEventListener('change', function () { applyTheme(themeSelect.value); });
}

var langSelect = document.getElementById('lang-select');
if (langSelect) {
  langSelect.value = cookieValue('keybase-lang') || 'en';
  langSelect.addEventListener('change', function () {
    var exp = new Date();
    exp.setFullYear(exp.getFullYear() + 1);
    document.cookie = 'keybase-lang=' + langSelect.value + '; expires=' + exp.toUTCString() + '; path=/; samesite=lax';
    window.location.reload();
  });
}

function cookieValue(name) {
  try {
    return document.cookie.split(';').map(function (item) { return item.trim(); }).filter(function (item) { return item.indexOf(name + '=') === 0; }).map(function (item) { return item.slice(name.length + 1); })[0] || '';
  } catch (err) {
    return '';
  }
}

function passwordConfirmationActive() {
  var cookieName = window.KEYBASE_CONFIRM_UI_COOKIE_NAME || 'kb_confirm_until';
  var until = parseInt(cookieValue(cookieName), 10);
  return !!until && until * 1000 > Date.now();
}

function applyDangerPasswordState() {
  var active = passwordConfirmationActive();
  document.querySelectorAll('[data-danger-form]').forEach(function (form) {
    form.classList.toggle('password-confirmed', active);
    form.querySelectorAll('input[name="confirm_password"]').forEach(function (input) {
      input.disabled = active;
      input.required = !active;
      if (active) input.value = '';
    });
  });
}

function setupDurationForm(form) {
  var input = form.querySelector('[data-duration-value]');
  var unit = form.querySelector('[data-duration-unit]');
  if (!input || !unit) return;
  function syncDuration() {
    if (unit.value === 'lifetime') {
      if (input.value) input.dataset.previousValue = input.value;
      input.value = '';
      input.placeholder = 'Lifetime';
      input.disabled = true;
      input.closest('label').classList.add('muted');
    } else {
      input.disabled = false;
      input.closest('label').classList.remove('muted');
      if (!input.value) input.value = input.dataset.previousValue || '30';
      input.placeholder = '';
    }
  }
  unit.addEventListener('change', syncDuration);
  syncDuration();
}

function setupBanForm(form) {
  var kind = form.querySelector('[data-ban-kind]');
  var valueField = form.querySelector('[data-ban-value-field]');
  var valueInput = form.querySelector('[data-ban-value-input]');
  var countryField = form.querySelector('[data-country-field]');
  var countryHidden = form.querySelector('[data-country-hidden]');
  var trigger = form.querySelector('[data-country-trigger]');
  var popover = form.querySelector('[data-country-popover]');
  var menu = form.querySelector('[data-country-menu]');
  var label = form.querySelector('[data-country-label]');
  var search = form.querySelector('[data-country-search]');
  if (!kind || !trigger || !popover || !search) return;

  function placeCountryPopover() {
    if (popover.hidden) return;
    var rect = trigger.getBoundingClientRect();
    var viewportWidth = Math.max(document.documentElement.clientWidth || 0, window.innerWidth || 0);
    var viewportHeight = Math.max(document.documentElement.clientHeight || 0, window.innerHeight || 0);
    var width = Math.min(420, Math.max(rect.width, 260), viewportWidth - 24);
    var spaceBelow = window.innerHeight - rect.bottom - 8;
    var spaceAbove = rect.top - 8;
    var preferredHeight = 286;
    var openUp = spaceBelow < 220 && spaceAbove > spaceBelow;
    var availableHeight = Math.max(160, Math.min(preferredHeight, openUp ? spaceAbove - 10 : spaceBelow - 10));
    var left = Math.max(12, Math.min(rect.left, window.innerWidth - width - 12));
    var popoverHeight = Math.min(preferredHeight, availableHeight);
    var top = openUp ? Math.max(12, rect.top - popoverHeight - 8) : Math.min(rect.bottom + 6, viewportHeight - popoverHeight - 12);
    popover.style.left = left + 'px';
    popover.style.top = top + 'px';
    popover.style.width = width + 'px';
    popover.style.maxHeight = popoverHeight + 'px';
    if (menu) menu.style.maxHeight = Math.max(108, popoverHeight - 56) + 'px';
    popover.dataset.placement = openUp ? 'top' : 'bottom';
  }

  function openCountryPopover() {
    document.querySelectorAll('[data-country-popover]').forEach(function (item) {
      if (item !== popover) item.hidden = true;
    });
    popover.hidden = false;
    filterCountries();
    window.requestAnimationFrame(placeCountryPopover);
    search.focus();
    search.select();
  }

  function syncKind() {
    var countryMode = kind.value === 'country';
    valueField.hidden = countryMode;
    valueInput.disabled = countryMode;
    valueInput.required = !countryMode;
    countryField.hidden = !countryMode;
    countryHidden.disabled = !countryMode;
    countryHidden.required = countryMode;
    if (!countryMode && popover) popover.hidden = true;
  }

  function filterCountries() {
    var needle = (search.value || '').trim().toLowerCase();
    form.querySelectorAll('[data-country-option]').forEach(function (button) {
      var match = !needle || button.dataset.code.toLowerCase().indexOf(needle) >= 0 || button.dataset.name.indexOf(needle) >= 0;
      button.hidden = !match;
    });
  }

  kind.addEventListener('change', syncKind);
  trigger.addEventListener('click', function () {
    if (popover.hidden) openCountryPopover();
    else popover.hidden = true;
  });
  window.addEventListener('resize', placeCountryPopover);
  window.addEventListener('scroll', placeCountryPopover, true);
  search.addEventListener('input', filterCountries);
  form.querySelectorAll('[data-country-option]').forEach(function (button) {
    button.addEventListener('click', function () {
      countryHidden.value = button.dataset.code;
      trigger.querySelector('.country-code').textContent = button.dataset.code;
      label.textContent = button.getAttribute('data-label') || button.dataset.code;
      popover.hidden = true;
    });
  });
  form.addEventListener('submit', function (event) {
    if (kind.value === 'country' && !countryHidden.value) {
      event.preventDefault();
      openCountryPopover();
    }
  });
  syncKind();
}

function hasTwoPasswordClasses(value) {
  var classes = 0;
  if (/[a-z]/.test(value)) classes += 1;
  if (/[A-Z]/.test(value)) classes += 1;
  if (/\d/.test(value)) classes += 1;
  if (/[^A-Za-z0-9]/.test(value)) classes += 1;
  return classes >= 2;
}

function passwordPolicyMessage(value, username) {
  if (!value) return '';
  if (value !== value.trim()) return 'Password cannot start or end with spaces.';
  if (value.length < 6) return 'Password must be at least 6 characters.';
  if (value.length > 256) return 'Password must be 256 characters or less.';
  if (/[\x00-\x1F]/.test(value)) return 'Password cannot contain control characters.';
  if (username && value.toLowerCase() === username.toLowerCase()) return 'Password cannot match the username.';
  if (!hasTwoPasswordClasses(value)) return 'Password must mix at least two character types.';
  return '';
}

function setupPasswordValidation(form) {
  var usernameInput = form.querySelector('input[name="username"]');
  var passwordInput = form.querySelector('input[name="password"], input[name="new_password"]');
  var repeatInput = form.querySelector('input[name="password_confirm"], input[name="new_password_confirm"]');
  if (!passwordInput) return;

  function syncPasswordValidation() {
    var username = usernameInput ? (usernameInput.value || '').trim() : '';
    var password = passwordInput.value || '';
    var policyMessage = passwordPolicyMessage(password, username);
    passwordInput.setCustomValidity(policyMessage);
    if (repeatInput) {
      if (repeatInput.value && repeatInput.value !== password) repeatInput.setCustomValidity('Passwords do not match.');
      else repeatInput.setCustomValidity('');
    }
  }

  passwordInput.addEventListener('input', syncPasswordValidation);
  if (repeatInput) repeatInput.addEventListener('input', syncPasswordValidation);
  if (usernameInput) usernameInput.addEventListener('input', syncPasswordValidation);
  syncPasswordValidation();
}

function setupPatternValidation(input, pattern, message, normalize) {
  if (!input) return;
  function sync() {
    var value = input.value || '';
    if (normalize) value = normalize(value);
    input.setCustomValidity(value && !pattern.test(value) ? message : '');
  }
  input.addEventListener('input', sync);
  sync();
}

function setupSecretValidation(input) {
  if (!input) return;
  function sync() {
    var value = input.value || '';
    if (!value) {
      input.setCustomValidity('');
      return;
    }
    if (value !== value.trim()) {
      input.setCustomValidity('Secret cannot start or end with spaces.');
      return;
    }
    if (/[\x00-\x1F]/.test(value)) {
      input.setCustomValidity('Secret cannot contain control characters.');
      return;
    }
    if (value.length < 8) {
      input.setCustomValidity('Secret must be at least 8 characters.');
      return;
    }
    input.setCustomValidity('');
  }
  input.addEventListener('input', sync);
  sync();
}

function setupDurationValidation(form) {
  var input = form.querySelector('[data-duration-value]');
  var unit = form.querySelector('[data-duration-unit]');
  if (!input || !unit) return;
  function sync() {
    if (unit.value === 'lifetime') {
      input.setCustomValidity('');
      return;
    }
    var value = parseInt(input.value || '', 10);
    if (!String(input.value || '').trim()) {
      input.setCustomValidity('Duration value is required.');
      return;
    }
    if (Number.isNaN(value) || value < 1 || value > 36500) {
      input.setCustomValidity('Duration value must be between 1 and 36500.');
      return;
    }
    input.setCustomValidity('');
  }
  input.addEventListener('input', sync);
  unit.addEventListener('change', sync);
  sync();
}

// ── Validation helpers ─────────────────────────────────────────────────────

function getOrCreateErrorHint(input) {
  var parent = input.parentNode;
  if (!parent) return null;
  var hint = parent.querySelector('.field-error-hint');
  if (!hint) {
    hint = document.createElement('span');
    hint.className = 'field-error-hint';
    hint.setAttribute('role', 'alert');
    hint.hidden = true;
    parent.appendChild(hint);
  }
  return hint;
}

function showInputError(input, message) {
  var hint = getOrCreateErrorHint(input);
  if (!hint) return;
  var msg = message || '';
  hint.textContent = msg;
  hint.hidden = !msg;
  input.classList.toggle('input-invalid', !!msg);
}

function syncInputError(input) {
  var msg = input.validationMessage || '';
  showInputError(input, msg);
}

function setupFieldErrorDisplay(form) {
  var fields = [].slice.call(form.querySelectorAll(
    'input:not([type="hidden"]):not([type="radio"]):not([type="checkbox"]), select, textarea'));
  fields.forEach(function (field) {
    if (field.dataset.errorBound === '1') return;
    field.dataset.errorBound = '1';
    var touched = false;
    function check() { if (touched) syncInputError(field); }
    field.addEventListener('blur', function () { touched = true; check(); });
    field.addEventListener('input', function () { if (touched) check(); });
    field.addEventListener('change', function () { touched = true; check(); });
  });
}

function setupSubmitGuard(form) {
  function syncAll(force) {
    var allValid = true;
    var fields = [].slice.call(form.querySelectorAll(
      'input:not([type="hidden"]):not([type="radio"]):not([type="checkbox"]), select, textarea'));
    fields.forEach(function (field) {
      if (!field.validity.valid) allValid = false;
      if (force) syncInputError(field);
    });
    var btns = form.querySelectorAll('[type="submit"]');
    btns.forEach(function (btn) {
      if (!btn.dataset.noGuard) btn.disabled = !allValid;
    });
    return allValid;
  }

  form.addEventListener('input', function () { syncAll(false); });
  form.addEventListener('change', function () { syncAll(false); });

  form.addEventListener('submit', function (event) {
    if (!syncAll(true)) {
      event.preventDefault();
      var first = form.querySelector(':invalid:not(fieldset)');
      if (first) { first.focus(); first.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
    }
  }, true);

  syncAll(false);
}

function setupUsernameValidation(input) {
  if (!input) return;
  var MIN = parseInt(input.getAttribute('minlength') || '3', 10);
  var MAX = parseInt(input.getAttribute('maxlength') || '32', 10);
  function sync() {
    var value = (input.value || '').trim();
    if (!value) { input.setCustomValidity(input.required ? 'Username is required.' : ''); return; }
    if (value.length < MIN) { input.setCustomValidity('Username must be at least ' + MIN + ' characters.'); return; }
    if (value.length > MAX) { input.setCustomValidity('Username must be ' + MAX + ' characters or less.'); return; }
    if (!/^[A-Za-z0-9_.\-]+$/.test(value)) { input.setCustomValidity('Username may only contain letters, numbers, dot, dash, underscore.'); return; }
    input.setCustomValidity('');
  }
  input.addEventListener('input', sync);
  sync();
}

function setupUrlFieldValidation(input) {
  if (!input) return;
  var MAX = parseInt(input.getAttribute('maxlength') || '512', 10);
  function sync() {
    var value = (input.value || '').trim();
    if (!value) { input.setCustomValidity(input.required ? 'URL is required.' : ''); return; }
    if (!/^https?:\/\/.{1,}/.test(value)) { input.setCustomValidity('Must start with http:// or https://'); return; }
    if (value.length > MAX) { input.setCustomValidity('URL must be ' + MAX + ' characters or less.'); return; }
    input.setCustomValidity('');
  }
  input.addEventListener('input', sync);
  sync();
}

function setupIntRangeValidation(input) {
  if (!input || input.type !== 'number') return;
  var min = input.hasAttribute('min') ? parseInt(input.getAttribute('min'), 10) : null;
  var max = input.hasAttribute('max') ? parseInt(input.getAttribute('max'), 10) : null;
  function sync() {
    var raw = (input.value || '').trim();
    if (!raw) { input.setCustomValidity(input.required ? 'This field is required.' : ''); return; }
    var value = parseInt(raw, 10);
    if (isNaN(value) || String(value) !== raw) { input.setCustomValidity('Must be a whole number.'); return; }
    if (min !== null && value < min) { input.setCustomValidity('Minimum allowed value is ' + min + '.'); return; }
    if (max !== null && value > max) { input.setCustomValidity('Maximum allowed value is ' + max + '.'); return; }
    input.setCustomValidity('');
  }
  input.addEventListener('input', sync);
  sync();
}

function setupPortValidation(input) {
  if (!input) return;
  function sync() {
    var raw = (input.value || '').trim();
    if (!raw) { input.setCustomValidity(input.required ? 'Port is required.' : ''); return; }
    var v = parseInt(raw, 10);
    if (isNaN(v) || v < 1 || v > 65535) { input.setCustomValidity('Port must be between 1 and 65535.'); return; }
    input.setCustomValidity('');
  }
  input.addEventListener('input', sync);
  sync();
}

function setupTextLengthValidation(input) {
  if (!input) return;
  var min = input.hasAttribute('minlength') ? parseInt(input.getAttribute('minlength'), 10) : null;
  var max = input.hasAttribute('maxlength') ? parseInt(input.getAttribute('maxlength'), 10) : null;
  function sync() {
    var value = (input.value || '');
    if (!value && input.required) { input.setCustomValidity('This field is required.'); return; }
    if (value && min !== null && value.trim().length < min) {
      input.setCustomValidity('Must be at least ' + min + ' characters.'); return;
    }
    if (value && max !== null && value.length > max) {
      input.setCustomValidity('Must be ' + max + ' characters or less.'); return;
    }
    input.setCustomValidity('');
  }
  input.addEventListener('input', sync);
  sync();
}

function setupFormValidation(form) {
  setupPasswordValidation(form);
  setupDurationValidation(form);
  setupPatternValidation(form.querySelector('input[name="app_id"]'), /^[A-Za-z0-9_.-]{2,64}$/, 'App ID must be 2-64 characters: letters, numbers, dot, dash, underscore.');
  setupPatternValidation(form.querySelector('input[name="prefix"]'), /^[A-Za-z0-9]{1,8}$/, 'Prefix must be 1-8 letters or numbers.', function (value) { return value.trim(); });
  setupPatternValidation(form.querySelector('input[name="default_prefix"]'), /^[A-Za-z0-9]{1,8}$/, 'Default key prefix must be 1-8 letters or numbers.', function (value) { return value.trim(); });
  setupSecretValidation(form.querySelector('input[name="secret"]'));
  setupUsernameValidation(form.querySelector('input[name="username"]'));
  [].slice.call(form.querySelectorAll('input[name="url"], input[name="endpoint_url"], input[data-url-field]')).forEach(setupUrlFieldValidation);
  [].slice.call(form.querySelectorAll('input[type="number"]')).forEach(setupIntRangeValidation);
  [].slice.call(form.querySelectorAll('input[data-port-field]')).forEach(setupPortValidation);
  [].slice.call(form.querySelectorAll('input[type="text"][maxlength], input[type="text"][minlength], textarea[maxlength]')).forEach(setupTextLengthValidation);
  setupFieldErrorDisplay(form);
  setupSubmitGuard(form);
}

function setupFaqSearch(input) {
  var empty = document.querySelector('[data-faq-empty]');
  function syncFaqSearch() {
    var needle = (input.value || '').trim().toLowerCase();
    var visibleItems = 0;
    document.querySelectorAll('[data-faq-section]').forEach(function (section) {
      var sectionMatches = 0;
      section.querySelectorAll('[data-faq-item]').forEach(function (item) {
        var matches = !needle || item.textContent.toLowerCase().indexOf(needle) !== -1;
        item.hidden = !matches;
        if (matches) sectionMatches += 1;
      });
      section.dataset.matchCount = String(sectionMatches);
      visibleItems += sectionMatches;
    });
    if (empty) empty.hidden = !needle || visibleItems > 0;
    if (faqController && typeof faqController.refresh === 'function') faqController.refresh();
  }
  input.addEventListener('input', syncFaqSearch);
  syncFaqSearch();
}

function setupFaqAccordion() {
  var sections = [].slice.call(document.querySelectorAll('[data-faq-section]'));
  if (!sections.length) return;
  var tocLinks = [].slice.call(document.querySelectorAll('.help-toc a[href^="#"]'));
  var searchInput = document.querySelector('[data-faq-search]');
  var storageKey = 'keybase-faq-state';
  var state = { last: '', sections: {} };
  var activeApiTab = '';

  try {
    var saved = JSON.parse(sessionStorage.getItem(storageKey) || '{}');
    if (saved && typeof saved === 'object') {
      if (typeof saved.last === 'string') state.last = saved.last;
      if (saved.sections && typeof saved.sections === 'object') state.sections = saved.sections;
    }
  } catch (err) {}

  function getSectionById(sectionId) {
    for (var index = 0; index < sections.length; index += 1) {
      if (sections[index].id === sectionId) return sections[index];
    }
    return null;
  }

  function getSectionItems(section) {
    return [].slice.call(section.querySelectorAll('[data-faq-item]'));
  }

  function getCurrentApiTab() {
    if (activeApiTab) return activeApiTab;
    var apiSection = getSectionById('api');
    if (apiSection && apiSection.dataset && apiSection.dataset.apiDocsTab) {
      return apiSection.dataset.apiDocsTab;
    }
    var activeButton = document.querySelector('[data-api-docs-tab][aria-selected="true"]');
    return activeButton ? activeButton.dataset.apiDocsTab : '';
  }

  function getStoredIndex(sectionId) {
    var sectionsState = state.sections || {};
    var value = sectionsState[sectionId];
    var index = typeof value === 'number' ? value : parseInt(value, 10);
    return Number.isNaN(index) ? null : index;
  }

  function saveState(sectionId, itemIndex) {
    state.last = sectionId;
    if (!state.sections || typeof state.sections !== 'object') state.sections = {};
    state.sections[sectionId] = itemIndex;
    try {
      sessionStorage.setItem(storageKey, JSON.stringify(state));
    } catch (err) {}
  }

  function syncToc(sectionId, apiTab) {
    var currentApiTab = typeof apiTab === 'string' && apiTab ? apiTab : getCurrentApiTab();
    tocLinks.forEach(function (link) {
      var active = (link.getAttribute('href') || '') === '#' + sectionId;
      var linkTab = link.dataset ? String(link.dataset.apiDocsTabLink || '') : '';
      if (active && linkTab) active = linkTab === currentApiTab;
      link.classList.toggle('is-active', active);
      if (active) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    });
  }

  function itemForSection(section) {
    var items = getSectionItems(section);
    if (!items.length) return null;
    var visibleItems = [].slice.call(section.querySelectorAll('[data-faq-item]:not([hidden])'));
    var storedIndex = getStoredIndex(section.id);
    if (storedIndex !== null && items[storedIndex] && !items[storedIndex].hidden) return items[storedIndex];
    if (visibleItems.length) return visibleItems[0];
    if (storedIndex !== null && items[storedIndex]) return items[storedIndex];
    return items[0];
  }

  function searchActive() {
    return !!(searchInput && (searchInput.value || '').trim());
  }

  function sectionHasMatches(section) {
    return parseInt(section.dataset.matchCount || '0', 10) > 0;
  }

  function visibleSection(section) {
    return !searchActive() || sectionHasMatches(section);
  }

  function resolveVisibleSection(preferredId) {
    var preferred = preferredId ? getSectionById(preferredId) : null;
    if (preferred && visibleSection(preferred)) return preferred;
    for (var index = 0; index < sections.length; index += 1) {
      if (visibleSection(sections[index])) return sections[index];
    }
    return preferred || getSectionById('quick-start') || sections[0];
  }

  function syncSectionVisibility(section, updateUrl) {
    var targetSection = resolveVisibleSection(section ? section.id : '');
    if (!targetSection) return;
    var targetItem = itemForSection(targetSection);
    if (!targetItem && searchActive()) {
      sections.forEach(function (otherSection) {
        otherSection.hidden = true;
        otherSection.classList.remove('is-active');
      });
      return;
    }

    sections.forEach(function (otherSection) {
      var showSection = otherSection === targetSection && (!searchActive() || sectionHasMatches(otherSection));
      otherSection.hidden = !showSection;
      otherSection.classList.toggle('is-active', showSection);
    });

    if (targetItem) {
      sections.forEach(function (otherSection) {
        getSectionItems(otherSection).forEach(function (otherItem) {
          otherItem.open = otherItem === targetItem;
        });
      });
      saveState(targetSection.id, getSectionItems(targetSection).indexOf(targetItem));
    }

    syncToc(targetSection.id);
    if (updateUrl !== false) {
      try { history.replaceState(null, '', '#' + targetSection.id); } catch (err) {}
    }
  }

  function activateItem(item, updateUrl) {
    if (!item) return;
    var section = item.closest('[data-faq-section]');
    if (!section) return;
    var items = getSectionItems(section);
    var itemIndex = items.indexOf(item);
    if (itemIndex < 0) return;
    saveState(section.id, itemIndex);
    syncSectionVisibility(section, updateUrl);
  }

  function sectionFromLocation() {
    var hash = window.location.hash ? window.location.hash.slice(1) : '';
    if (hash) {
      var fromHash = getSectionById(hash);
      if (fromHash) return fromHash;
    }
    if (state.last) {
      var lastSection = getSectionById(state.last);
      if (lastSection) return lastSection;
    }
    return getSectionById('quick-start') || sections[0];
  }

  sections.forEach(function (section) {
    getSectionItems(section).forEach(function (item) {
      var summary = item.querySelector('summary');
      if (!summary) return;
      summary.addEventListener('click', function (event) {
        event.preventDefault();
        if (item.open && !item.hidden) return;
        activateItem(item);
      });
    });
  });

  tocLinks.forEach(function (link) {
    link.addEventListener('click', function (event) {
      var targetId = (link.getAttribute('href') || '').replace(/^#/, '');
      var section = getSectionById(targetId);
      if (!section) return;
      event.preventDefault();
      activateItem(itemForSection(section), true);
    });
  });

  window.addEventListener('hashchange', function () {
    var section = sectionFromLocation();
    if (!section) return;
    var targetItem = itemForSection(section);
    if (targetItem) activateItem(targetItem, false);
  });

  window.addEventListener('faq:api-tab-change', function (event) {
    var tab = event && event.detail && typeof event.detail.tab === 'string' ? event.detail.tab : '';
    if (!tab) return;
    activeApiTab = tab;
    var apiSection = getSectionById('api');
    if (apiSection) apiSection.dataset.apiDocsTab = tab;
    syncToc('api', tab);
  });

  var initialSection = sectionFromLocation();
  var initialItem = initialSection ? itemForSection(initialSection) : null;
  if (initialItem) activateItem(initialItem, false);
  activeApiTab = getCurrentApiTab();
  faqController = {
    refresh: function () {
      syncSectionVisibility(sectionFromLocation(), false);
    },
    setApiTab: function (tab) {
      if (!tab) return;
      activeApiTab = tab;
      var apiSection = getSectionById('api');
      if (apiSection) apiSection.dataset.apiDocsTab = tab;
      syncToc('api', tab);
    }
  };
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function splitConfigComment(line) {
  var quote = '';
  for (var index = 0; index < line.length; index += 1) {
    var char = line.charAt(index);
    var previous = index > 0 ? line.charAt(index - 1) : '';
    if (quote) {
      if (char === quote && previous !== '\\') quote = '';
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === '#') return [line.slice(0, index), line.slice(index)];
  }
  return [line, ''];
}

function wrapConfigSpan(className, value) {
  return '<span class="' + className + '">' + escapeHtml(value) + '</span>';
}

function configKeyClass(name) {
  var safe = String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-');
  return 'cfg-section cfg-section-' + safe;
}

function highlightConfigValue(value, keyName) {
  var raw = String(value || '');
  var lowerKey = String(keyName || '').toLowerCase();
  var tokenPattern = /(https?:\/\/[^\s#]+)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|\b(combined|split)\b|\b(true|false)\b|\b(null)\b|\b\d+\b|([\[\]\{\},])/gi;
  var highlighted = '';
  var lastIndex = 0;

  raw.replace(tokenPattern, function (match, url, quoted, mode, boolValue, nullValue, punctuation, offset) {
    highlighted += escapeHtml(raw.slice(lastIndex, offset));
    var className = 'cfg-string';
    if (url) className = 'cfg-url';
    else if (quoted) className = /(token|secret|password)/.test(lowerKey) ? 'cfg-secret' : 'cfg-string';
    else if (mode) className = 'cfg-mode';
    else if (boolValue) className = 'cfg-bool';
    else if (nullValue) className = 'cfg-null';
    else if (punctuation) className = 'cfg-punc';
    else if (/^\d+$/.test(match)) className = /(port|minutes|hours|limit|max_|keep_last|interval|duration|size|length|count|devices|min_)/.test(lowerKey) ? 'cfg-port' : 'cfg-number';
    highlighted += wrapConfigSpan(className, match);
    lastIndex = offset + match.length;
    return match;
  });
  highlighted += escapeHtml(raw.slice(lastIndex));

  if (!highlighted.trim()) return highlighted;
  if (/(token|secret|password)/.test(lowerKey)) return '<span class="cfg-secret">' + highlighted + '</span>';
  if (/header/.test(lowerKey)) return '<span class="cfg-header">' + highlighted + '</span>';
  if (/(host|public_base_url|geoip_url)/.test(lowerKey)) return '<span class="cfg-host">' + highlighted + '</span>';
  return highlighted;
}

function highlightConfigLine(line) {
  if (!line) return '&nbsp;';
  if (/^\s*#/.test(line)) return wrapConfigSpan('cfg-comment', line);

  var parts = splitConfigComment(line);
  var content = parts[0];
  var comment = parts[1];
  var match = content.match(/^(\s*)([A-Za-z0-9_.-]+):(.*)$/);
  var html = '';

  if (match) {
    var indent = escapeHtml(match[1] || '');
    var key = match[2] || '';
    var rest = match[3] || '';
    var isRootSection = !(match[1] || '').length && !rest.trim();
    html += indent;
    html += '<span class="' + (isRootSection ? configKeyClass(key) : 'cfg-key') + '">' + escapeHtml(key) + '</span>';
    html += '<span class="cfg-colon">:</span>';
    if (rest) html += highlightConfigValue(rest, key);
  } else {
    html = highlightConfigValue(content, '');
  }

  if (comment) html += '<span class="cfg-comment">' + escapeHtml(comment) + '</span>';
  return html;
}

function buildConfigHighlight(value) {
  return String(value || '').split('\n').map(highlightConfigLine).join('\n');
}

function buildConfigGutter(value) {
  var lineCount = Math.max(String(value || '').split('\n').length, 1);
  var rows = [];
  for (var index = 1; index <= lineCount; index += 1) {
    rows.push('<span>' + index + '</span>');
  }
  return rows.join('');
}

function setupConfigEditor(root) {
  var textarea = root.querySelector('[data-config-input]');
  var highlight = root.querySelector('[data-config-highlight]');
  var gutter = root.querySelector('[data-config-gutter]');
  var form = root.closest('[data-config-save-form]');
  if (!textarea || !highlight || !gutter || !form) return;

  var statusNode = form.querySelector('[data-config-status]');
  var cursorNode = form.querySelector('[data-config-cursor]');
  var resetButton = form.querySelector('[data-config-reset]');
  var initialValue = textarea.value || '';
  textarea.dataset.cfgInitial = initialValue;
  var modalId = form.closest('.modal') ? form.closest('.modal').id : '';
  var pendingJump = '';

  function syncScroll() {
    highlight.scrollTop = textarea.scrollTop;
    highlight.scrollLeft = textarea.scrollLeft;
    gutter.scrollTop = textarea.scrollTop;
  }

  function updateCursor() {
    if (!cursorNode) return;
    var position = textarea.selectionStart || 0;
    var before = textarea.value.slice(0, position).split('\n');
    var line = before.length;
    var column = before[before.length - 1].length + 1;
    cursorNode.textContent = 'Ln ' + line + ', Col ' + column;
  }

  function updateStatus() {
    if (!statusNode) return;
    var changed = textarea.value !== initialValue;
    var lineCount = Math.max((textarea.value || '').split('\n').length, 1);
    statusNode.classList.toggle('is-dirty', changed);
    statusNode.textContent = changed ? ('Unsaved changes · ' + lineCount + ' lines') : ('Live file · ' + lineCount + ' lines');
  }

  function renderEditor() {
    highlight.innerHTML = buildConfigHighlight(textarea.value);
    gutter.innerHTML = buildConfigGutter(textarea.value);
    syncScroll();
    updateCursor();
    updateStatus();
  }

  function jumpToSection(sectionName) {
    var value = textarea.value || '';
    var pattern = new RegExp('(^|\\n)' + sectionName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ':\\s*(\\n|$)', 'i');
    var found = pattern.exec(value);
    if (!found) return;
    var start = found.index === 0 ? 0 : found.index + 1;
    textarea.focus();
    textarea.setSelectionRange(start, start);
    window.requestAnimationFrame(function () {
      var lineHeight = parseFloat(window.getComputedStyle(textarea).lineHeight) || 22;
      var lineNumber = value.slice(0, start).split('\n').length - 1;
      textarea.scrollTop = Math.max(0, lineNumber * lineHeight - lineHeight * 2);
      syncScroll();
      updateCursor();
    });
  }

  textarea.addEventListener('input', renderEditor);
  textarea.addEventListener('scroll', syncScroll);
  textarea.addEventListener('click', updateCursor);
  textarea.addEventListener('keyup', updateCursor);
  textarea.addEventListener('focus', updateCursor);
  textarea.addEventListener('keydown', function (event) {
    if (event.key === 'Tab') {
      event.preventDefault();
      var start = textarea.selectionStart || 0;
      var end = textarea.selectionEnd || 0;
      var value = textarea.value || '';
      textarea.value = value.slice(0, start) + '  ' + value.slice(end);
      textarea.setSelectionRange(start + 2, start + 2);
      renderEditor();
      return;
    }
    if ((event.ctrlKey || event.metaKey) && String(event.key || '').toLowerCase() === 's') {
      event.preventDefault();
      triggerConfigSave(form);
    }
  });

  if (resetButton) {
    resetButton.addEventListener('click', function () {
      textarea.value = initialValue;
      renderEditor();
      textarea.focus();
    });
  }

  form.querySelectorAll('[data-config-jump]').forEach(function (button) {
    button.addEventListener('click', function () {
      jumpToSection(button.getAttribute('data-config-jump') || '');
    });
  });

  document.querySelectorAll('[data-open-modal="' + modalId + '"]').forEach(function (button) {
    button.addEventListener('click', function () {
      pendingJump = button.getAttribute('data-config-open-jump') || '';
      window.setTimeout(function () {
        renderEditor();
        textarea.focus();
        if (pendingJump) {
          jumpToSection(pendingJump);
          pendingJump = '';
        }
      }, 40);
    });
  });

  document.querySelectorAll('.config-jump-static [data-config-jump]').forEach(function (button) {
    button.addEventListener('click', function () {
      pendingJump = button.getAttribute('data-config-jump') || '';
      var modal = document.getElementById(modalId);
      if (modal) modal.hidden = false;
      window.setTimeout(function () {
        renderEditor();
        textarea.focus();
        if (pendingJump) {
          jumpToSection(pendingJump);
          pendingJump = '';
        }
      }, 40);
    });
  });

  var saveBtn = form.querySelector('[data-config-save-btn]');
  if (saveBtn) {
    saveBtn.addEventListener('click', function () { triggerConfigSave(form); });
  }

  window.addEventListener('beforeunload', function (e) {
    if (textarea.value !== (textarea.dataset.cfgInitial || initialValue)) {
      e.preventDefault();
      e.returnValue = '';
    }
  });

  renderEditor();
}

function triggerConfigSave(form) {
  if (!form) return;
  if (typeof passwordConfirmationActive === 'function' && passwordConfirmationActive()) {
    var hiddenPwd = form.querySelector('[data-cfg-pwd-hidden]');
    if (hiddenPwd) hiddenPwd.value = '';
    var ta = form.querySelector('[data-config-input]');
    if (ta) ta.dataset.cfgInitial = ta.value;
    form.submit();
    return;
  }
  var popup = document.getElementById('cfg-save-popup');
  if (!popup) { form.submit(); return; }
  popup.hidden = false;
  var pwdInput = popup.querySelector('input[name="confirm_password"]');
  if (pwdInput) { pwdInput.value = ''; window.setTimeout(function () { pwdInput.focus(); }, 50); }
}

// ── Panic Mode countdown ──────────────────────────────────────────────────────

function setupPanicCountdown() {
  var el = document.querySelector('[data-panic-countdown]');
  if (!el) return;
  var remaining = parseInt(el.getAttribute('data-panic-countdown'), 10);
  if (isNaN(remaining) || remaining <= 0) return;

  function update() {
    if (remaining <= 0) {
      window.location.reload();
      return;
    }
    var m = Math.floor(remaining / 60);
    var s = remaining % 60;
    el.textContent = m + 'm ' + (s < 10 ? '0' + s : s) + 's remaining';
    remaining--;
  }
  update();
  window.setInterval(update, 1000);
}

// ── Bulk selection ────────────────────────────────────────────────────────────

function setupBulkTables() {
  document.querySelectorAll('[data-bulk-table]').forEach(function (table) {
    var tableType = table.getAttribute('data-bulk-table');
    var bar = table.previousElementSibling;
    while (bar && !bar.hasAttribute('data-bulk-bar')) {
      bar = bar.previousElementSibling;
    }
    if (!bar) return;
    setupBulkTable(table, bar, tableType);
  });
}

function setupBulkTable(table, bar, tableType) {
  var selected = new Set();
  var selecting = false;

  var toggleBtn = bar.querySelector('[data-bulk-toggle]');
  var countEl = bar.querySelector('[data-bulk-count]');
  var allBtn = bar.querySelector('[data-bulk-all]');
  var clearBtn = bar.querySelector('[data-bulk-clear]');
  var sepEl = bar.querySelector('.bulk-sep');
  var actionBtns = bar.querySelectorAll('[data-bulk-action]');
  var endpoint = bar.getAttribute('data-bulk-endpoint') || '';
  var exportUrl = bar.getAttribute('data-bulk-export') || '';
  var toggleLabel = toggleBtn ? toggleBtn.textContent.trim() : 'Select';
  var doneLabel = bar.getAttribute('data-bulk-done-label') || 'Done';
  var countTemplate = bar.getAttribute('data-bulk-selected-template') || '__count__ selected';
  var confirmTemplate = bar.getAttribute('data-bulk-confirm-template') || '__action__: __count__ item(s)?';
  var exportTemplate = bar.getAttribute('data-bulk-export-template') || 'Exporting __count__ item(s).';
  var requestFailedMessage = bar.getAttribute('data-bulk-request-failed') || 'Request failed.';
  var rowLabel = bar.getAttribute('data-bulk-row-label') || 'Select row';

  function getRows() { return Array.from(table.querySelectorAll('tr[data-bulk-id]')); }
  function setToggleLabel(label) {
    if (!toggleBtn) return;
    var textNode = toggleBtn.querySelector('span');
    if (textNode) {
      textNode.textContent = label;
    } else {
      toggleBtn.textContent = label;
    }
  }
  function renderTemplate(template, replacements) {
    var text = String(template || '');
    Object.keys(replacements || {}).forEach(function (key) {
      text = text.replace(new RegExp(key, 'g'), String(replacements[key]));
    });
    return text;
  }

  function updateBar() {
    countEl.hidden = !selecting;
    allBtn.hidden = !selecting;
    clearBtn.hidden = !selecting;
    if (sepEl) sepEl.hidden = !selecting || selected.size === 0;
    actionBtns.forEach(function (btn) {
      btn.hidden = !selecting || selected.size === 0;
      btn.disabled = !selecting || selected.size === 0;
    });
    if (selecting) {
      countEl.textContent = renderTemplate(countTemplate, { '__count__': selected.size });
    }
    setToggleLabel(selecting ? doneLabel : toggleLabel);
    table.querySelectorAll('tr[data-bulk-id]').forEach(function (tr) {
      var cb = tr.querySelector('.bulk-cb');
      if (cb) cb.checked = selected.has(tr.getAttribute('data-bulk-id'));
      if (selected.has(tr.getAttribute('data-bulk-id'))) {
        tr.classList.add('bulk-selected');
      } else {
        tr.classList.remove('bulk-selected');
      }
    });
  }

  function enterSelect() {
    if (selecting) return;
    selecting = true;
    table.classList.add('bulk-selecting');
    var headerRow = table.querySelector('tr:first-child');
    if (headerRow) {
      var th = document.createElement('th');
      th.className = 'bulk-cb-col';
      headerRow.insertBefore(th, headerRow.firstChild);
    }
    getRows().forEach(function (tr) {
      var td = document.createElement('td');
      td.className = 'bulk-cb-cell';
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'bulk-cb';
      cb.setAttribute('aria-label', rowLabel);
      td.appendChild(cb);
      tr.insertBefore(td, tr.firstChild);
    });
    table.addEventListener('click', clickInterceptor, true);
    updateBar();
  }

  function exitSelect() {
    selecting = false;
    selected.clear();
    table.classList.remove('bulk-selecting');
    var headerRow = table.querySelector('tr:first-child');
    if (headerRow) {
      var th = headerRow.querySelector('.bulk-cb-col');
      if (th) headerRow.removeChild(th);
    }
    getRows().forEach(function (tr) {
      var td = tr.querySelector('.bulk-cb-cell');
      if (td) tr.removeChild(td);
      tr.classList.remove('bulk-selected');
    });
    table.removeEventListener('click', clickInterceptor, true);
    updateBar();
  }

  function clickInterceptor(e) {
    var tr = e.target.closest('tr[data-bulk-id]');
    if (!tr) return;
    var id = tr.getAttribute('data-bulk-id');
    e.stopPropagation();
    e.preventDefault();
    if (selected.has(id)) { selected.delete(id); } else { selected.add(id); }
    updateBar();
  }

  toggleBtn.addEventListener('click', function () {
    if (selecting) { exitSelect(); } else { enterSelect(); }
  });

  if (allBtn) allBtn.addEventListener('click', function () {
    getRows().forEach(function (tr) { selected.add(tr.getAttribute('data-bulk-id')); });
    updateBar();
  });

  if (clearBtn) clearBtn.addEventListener('click', function () {
    selected.clear();
    updateBar();
  });

  actionBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      var action = btn.getAttribute('data-bulk-action');
      var actionLabel = btn.textContent.trim() || action;
      var ids = Array.from(selected);
      if (!ids.length) return;
      if (action === 'export') {
        bulkExport(exportUrl, ids);
        showToast({ type: 'info', message: renderTemplate(exportTemplate, { '__count__': ids.length }) });
        exitSelect();
        return;
      }
      var needsPassword = (action === 'delete' || action === 'unban');
      bulkConfirm(table, bar, tableType, ids, action, actionLabel, confirmTemplate, needsPassword, requestFailedMessage, function (count) {
        if (count > 0) { exitSelect(); }
      });
    });
  });
}

function bulkConfirm(table, bar, tableType, ids, action, actionLabel, confirmTemplate, needsPassword, requestFailedMessage, onDone) {
  var modalId = 'bulk-confirm-' + tableType;
  var modal = document.getElementById(modalId);
  if (!modal) return;
  var msgEl = modal.querySelector('[data-bulk-confirm-msg]');
  var okBtn = modal.querySelector('[data-bulk-confirm-ok]');
  var pwdWrap = modal.querySelector('.confirm-password-section');
  var pwdInput = modal.querySelector('input[name="confirm_password"]');
  var confirmedNote = modal.querySelector('.password-confirmed-note');

  if (msgEl) {
    msgEl.textContent = String(confirmTemplate || '__action__: __count__ item(s)?')
      .replace(/__action__/g, actionLabel || action)
      .replace(/__count__/g, String(ids.length));
  }

  var shouldShowPwd = needsPassword && !passwordConfirmationActive();
  if (pwdWrap) pwdWrap.hidden = !shouldShowPwd;
  if (confirmedNote) confirmedNote.hidden = shouldShowPwd;
  if (pwdInput && shouldShowPwd) pwdInput.value = '';

  modal.hidden = false;
  if (pwdInput && shouldShowPwd) window.setTimeout(function () { pwdInput.focus(); }, 50);

  var endpoint = bar.getAttribute('data-bulk-endpoint') || '';

  function doAction() {
    var password = '';
    if (needsPassword && !passwordConfirmationActive()) {
      if (pwdInput) password = pwdInput.value.trim();
    }
    modal.hidden = true;
    bulkFetch(endpoint, ids, action, password, requestFailedMessage, function (ok, count, msg, level) {
      var toastType = level || (ok ? 'success' : 'error');
      if (ok) {
        if (needsPassword && pwdInput && pwdInput.value) {
          applyDangerPasswordState();
        }
        onDone(count);
        showToast({ type: toastType, message: msg || (count + ' item(s) updated.') });
      } else {
        showToast({ type: toastType, message: msg || 'Action failed.' });
      }
    });
  }

  if (okBtn) {
    var newOk = okBtn.cloneNode(true);
    okBtn.parentNode.replaceChild(newOk, okBtn);
    newOk.addEventListener('click', doAction);
  }
}

function bulkFetch(endpoint, ids, action, password, requestFailedMessage, callback) {
  var fd = new FormData();
  fd.append('action', action);
  ids.forEach(function (id) { fd.append('ids[]', id); });
  if (password) fd.append('confirm_password', password);
  fetch(endpoint, { method: 'POST', body: fd, credentials: 'same-origin' })
    .then(function (r) { return r.json(); })
    .then(function (j) { callback(!!j.ok, j.count || 0, j.message || '', j.type || ''); })
    .catch(function () { callback(false, 0, requestFailedMessage || 'Request failed.', 'error'); });
}

function bulkExport(url, ids) {
  var form = document.createElement('form');
  form.method = 'POST';
  form.action = url;
  ids.forEach(function (id) {
    var inp = document.createElement('input');
    inp.type = 'hidden';
    inp.name = 'ids[]';
    inp.value = id;
    form.appendChild(inp);
  });
  document.body.appendChild(form);
  form.submit();
  window.setTimeout(function () { document.body.removeChild(form); }, 1000);
}

function setupConfigSave() {
  var popup = document.getElementById('cfg-save-popup');
  if (!popup) return;
  var confirmBtn = document.getElementById('cfg-save-confirm-btn');
  if (!confirmBtn) return;
  async function doSave() {
    var form = document.querySelector('[data-config-save-form]');
    if (!form) return;
    var hiddenPwd = form.querySelector('[data-cfg-pwd-hidden]');
    var popupPwd = popup.querySelector('input[name="confirm_password"]');
    if (hiddenPwd && popupPwd) hiddenPwd.value = popupPwd.value;
    var ta = form.querySelector('[data-config-input]');
    if (ta) ta.dataset.cfgInitial = ta.value;
    popup.hidden = true;
    var saveBtn = form.querySelector('[data-config-save-btn]');
    var btnHTML = saveBtn ? saveBtn.innerHTML : '';
    if (saveBtn) saveBtn.disabled = true;
    function showSaveError(msg) {
      var el = form.querySelector('[data-config-save-error]');
      if (!el) {
        el = document.createElement('div');
        el.setAttribute('data-config-save-error', '');
        el.style.cssText = 'color:var(--error,#c0392b);font-size:13px;padding:6px 0 2px;';
        var footer = form.querySelector('.config-editor-footer');
        if (footer) footer.insertBefore(el, footer.firstChild);
        else form.appendChild(el);
      }
      el.textContent = msg;
      if (saveBtn) { saveBtn.disabled = false; saveBtn.innerHTML = btnHTML; }
    }
    try {
      var fd = new FormData(form);
      var resp = await fetch(form.action, { method: 'POST', headers: { 'Accept': 'application/json' }, body: fd });
      var data = await resp.json();
      if (data.type === 'error') {
        showSaveError(data.message || 'Save failed');
      } else {
        location.reload();
      }
    } catch (e) {
      showSaveError('Network error: ' + e.message);
    }
  }
  confirmBtn.addEventListener('click', doSave);
  popup.querySelectorAll('input[name="confirm_password"]').forEach(function (inp) {
    inp.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); doSave(); }
    });
  });
}

function updateApiRuntimeRoot(root, data) {
  root._apiRuntimeData = data;
  root.querySelectorAll('[data-api-text]').forEach(function (node) {
    var key = node.getAttribute('data-api-text');
    if (!key || typeof data[key] === 'undefined' || data[key] === null) return;
    if (node.hasAttribute('data-api-sensitive')) {
      node.innerHTML = '<span class="stat-blur">' + escapeHtml(String(data[key])) + '</span>';
    } else {
      node.textContent = String(data[key]);
    }
  });

  var consoleBox = root.querySelector('[data-api-console]');
  if (consoleBox && typeof data.console_text !== 'undefined') {
    var isFirst = !root._apiConsoleReady;
    var stickToBottom = isFirst || (consoleBox.scrollTop + consoleBox.clientHeight >= consoleBox.scrollHeight - 64);
    consoleBox.textContent = data.console_text || '';
    if (stickToBottom) consoleBox.scrollTop = consoleBox.scrollHeight;
    root._apiConsoleReady = true;
  }

  var recentBox = root.querySelector('[data-api-recent]');
  if (recentBox && typeof data.recent_events_text !== 'undefined') {
    recentBox.textContent = data.recent_events_text || 'No verify events yet.';
  }

  applyApiScope(root, data);
}

function applyApiScope(root, data) {
  var scope = root.getAttribute('data-api-scope') === 'system' ? 'system' : 'process';
  root.querySelectorAll('[data-api-scope-label], [data-api-scope-value], [data-api-scope-detail]').forEach(function (node) {
    var key = node.getAttribute(scope === 'system' ? 'data-system-key' : 'data-process-key');
    if (!key || typeof data[key] === 'undefined' || data[key] === null) return;
    node.textContent = String(data[key]);
  });
  root.querySelectorAll('[data-api-scope-button]').forEach(function (button) {
    button.classList.toggle('active', button.getAttribute('data-scope') === scope);
  });
}

function updateReleaseBannerRoot(root, data) {
  if (!root || !data) return;
  root._releaseData = data;
  var state = String(data.status || (data.available ? 'available' : 'unavailable'));
  var enabled = data.banner_enabled !== false;
  var shouldShow = enabled && !!data.available;
  var title = root.querySelector('[data-release-title]');
  var text = root.querySelector('[data-release-text]');
  root.dataset.releaseState = state;
  root.dataset.releaseEnabled = enabled ? '1' : '0';
  if (title && data.latest_version) title.textContent = 'Update available';
  if (text && data.latest_version) {
    text.textContent = 'Latest: v' + data.latest_version + ' · install it through Builder.';
  }
  root.hidden = !shouldShow;
  root.setAttribute('aria-hidden', shouldShow ? 'false' : 'true');
}

function setupReleaseBanner(root) {
  var url = root.getAttribute('data-release-status-url');
  if (!url) return;
  var busy = false;
  var intervalMs = parseInt(root.getAttribute('data-release-poll') || '60000', 10);
  if (isNaN(intervalMs) || intervalMs < 10000) intervalMs = 30000;

  function syncReleaseBanner() {
    if (busy) return;
    busy = true;
    var requestUrl = url + (url.indexOf('?') === -1 ? '?' : '&') + 't=' + Date.now();
    fetch(requestUrl, {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      cache: 'no-store'
    })
      .then(function (response) {
        if (!response.ok) throw new Error('Release request failed');
        return response.json();
      })
      .then(function (data) {
        if (!data || data.ok === false) return;
        updateReleaseBannerRoot(root, data);
      })
      .catch(function () {})
      .finally(function () {
        busy = false;
      });
  }

  syncReleaseBanner();
  window.setInterval(syncReleaseBanner, intervalMs);
  window.addEventListener('focus', syncReleaseBanner);
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) syncReleaseBanner();
  });
}

function setupApiRuntime(root) {
  var url = root.getAttribute('data-api-runtime-url');
  if (!url) return;
  var busy = false;

  root.querySelectorAll('[data-api-scope-button]').forEach(function (button) {
    button.addEventListener('click', function () {
      var scope = button.getAttribute('data-scope') === 'system' ? 'system' : 'process';
      root.setAttribute('data-api-scope', scope);
      try { localStorage.setItem('keybase-api-scope', scope); } catch (err) {}
      applyApiScope(root, root._apiRuntimeData || {});
    });
  });
  try {
    var savedScope = localStorage.getItem('keybase-api-scope');
    if (savedScope === 'system' || savedScope === 'process') root.setAttribute('data-api-scope', savedScope);
  } catch (err) {}

  function syncApiRuntime() {
    if (busy) return;
    busy = true;
    fetch(url, {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' }
    })
      .then(function (response) {
        if (!response.ok) throw new Error('Runtime request failed');
        return response.json();
      })
      .then(function (data) {
        if (!data || data.ok === false) return;
        updateApiRuntimeRoot(root, data);
      })
      .catch(function () {})
      .finally(function () {
        busy = false;
      });
  }

  syncApiRuntime();
  window.setInterval(syncApiRuntime, 3000);
}

document.querySelectorAll('form').forEach(setupDurationForm);
document.querySelectorAll('[data-ban-form]').forEach(setupBanForm);
document.querySelectorAll('form').forEach(setupFormValidation);
document.querySelectorAll('form').forEach(setupSecretModeForm);
document.querySelectorAll('[data-secret-field]').forEach(setupSecretField);
setupFaqAccordion();
document.querySelectorAll('[data-faq-search]').forEach(setupFaqSearch);
document.querySelectorAll('[data-config-editor-root]').forEach(setupConfigEditor);
document.querySelectorAll('[data-release-banner-root]').forEach(setupReleaseBanner);
setupPanicCountdown();
setupConfigSave();
setupBulkTables();
document.querySelectorAll('[data-api-runtime-root]').forEach(setupApiRuntime);
showInitialToastsFromUrl();
document.addEventListener('click', function (event) {
  if (!event.target.closest('[data-country-field]')) {
    document.querySelectorAll('[data-country-popover]').forEach(function (popover) { popover.hidden = true; });
  }
});
document.addEventListener('keydown', function (event) {
  var rowLink = event.target.closest('[data-row-link]');
  if (!rowLink) return;
  if (event.key !== 'Enter' && event.key !== ' ') return;
  if (event.target.closest('a, button, input, select, textarea, label, summary')) return;
  var href = rowLink.getAttribute('data-row-link');
  if (!href) return;
  event.preventDefault();
  window.location.href = href;
});
applyDangerPasswordState();
document.addEventListener('keydown', function (event) {
  if (event.key === 'Escape') {
    document.querySelectorAll('.modal').forEach(function (modal) { modal.hidden = true; });
  }
});

// Preserve ?limit= across filter/search form submissions so page-size choice survives filters
document.addEventListener('submit', function (e) {
  var form = e.target;
  if (!form || (form.method || '').toUpperCase() === 'POST') return;
  if (form.classList.contains('pagination-size') || form.classList.contains('pagination-jump')) return;
  if (form.querySelector('[name="limit"]')) return;
  var currentLimit = new URLSearchParams(window.location.search).get('limit');
  if (!currentLimit) return;
  var inp = document.createElement('input');
  inp.type = 'hidden';
  inp.name = 'limit';
  inp.value = currentLimit;
  form.appendChild(inp);
});
