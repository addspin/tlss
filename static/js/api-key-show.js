function showAPIKeyOnce(key, name) {
  Swal.fire({
    showClass: { popup: 'animate__animated animate__fadeInUp animate__fast' },
    hideClass: { popup: 'animate__animated animate__fadeOutDown animate__fast' },
    customClass: 'custom-alert',
    icon: 'success',
    title: 'API key created: ' + name,
    html:
      '<p style="margin-bottom: 8px;"><strong>Save this key now &mdash; it will not be shown again.</strong></p>' +
      '<div style="display:flex; gap:6px; align-items:center;">' +
      '  <input id="api-key-value" type="text" readonly value="' + key + '" ' +
      '    style="flex:1; font-family: monospace; font-size: 12px; padding: 6px; background:#222; color:#eee; border:1px solid #555; border-radius:4px;">' +
      '  <button type="button" id="api-key-copy" class="btn-custom" style="padding: 6px 10px; font-size: 12px;">Copy</button>' +
      '</div>',
    confirmButtonColor: '#3085d6',
    confirmButtonText: 'I saved it',
    allowOutsideClick: false,
    didOpen: function() {
      var copyBtn = document.getElementById('api-key-copy');
      var input = document.getElementById('api-key-value');
      copyBtn.addEventListener('click', function() {
        input.select();
        navigator.clipboard.writeText(input.value).then(function() {
          copyBtn.textContent = 'Copied!';
          setTimeout(function() { copyBtn.textContent = 'Copy'; }, 1500);
        });
      });
    }
  });
}
