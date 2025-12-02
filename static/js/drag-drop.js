(function() {

  // Делегирование клика на drop-zone
  document.addEventListener('click', function(e) {
    const dropZone = e.target.closest('#drop-zone');
    if (dropZone) {
      const fileInput = document.getElementById('cert-file-input');
      if (fileInput) {
        fileInput.click();
      }
    }
  });

  // Делегирование для предотвращения стандартного поведения drag
  document.addEventListener('dragenter', function(e) {
    const dropZone = e.target.closest('#drop-zone');
    if (dropZone) {
      e.preventDefault();
      e.stopPropagation();
      dropZone.style.borderColor = '#3182CE';
      dropZone.style.background = 'rgba(49, 130, 206, 0.1)';
    }
  }, true);

  document.addEventListener('dragover', function(e) {
    const dropZone = e.target.closest('#drop-zone');
    if (dropZone) {
      e.preventDefault();
      e.stopPropagation();
      dropZone.style.borderColor = '#3182CE';
      dropZone.style.background = 'rgba(49, 130, 206, 0.1)';
    }
  }, true);

  document.addEventListener('dragleave', function(e) {
    const dropZone = e.target.closest('#drop-zone');
    if (dropZone && !dropZone.contains(e.relatedTarget)) {
      dropZone.style.borderColor = '#4A5568';
      dropZone.style.background = 'rgba(74, 85, 104, 0.1)';
    }
  }, true);

  document.addEventListener('drop', function(e) {
    const dropZone = e.target.closest('#drop-zone');
    if (dropZone) {
      e.preventDefault();
      e.stopPropagation();
      
      dropZone.style.borderColor = '#4A5568';
      dropZone.style.background = 'rgba(74, 85, 104, 0.1)';
      
      const dt = e.dataTransfer;
      const files = dt.files;
      
      if (files.length > 0) {
        const fileInput = document.getElementById('cert-file-input');
        const form = document.getElementById('cert-upload-form');
        
        if (fileInput && form) {
          fileInput.files = files;
          htmx.trigger(form, 'submit');
        }
      }
    }
  }, true);

  // Обработчик изменения файла через input
  document.addEventListener('change', function(e) {
    if (e.target.id === 'cert-file-input') {
      if (e.target.files.length > 0) {
        const form = document.getElementById('cert-upload-form');
        if (form) {
          htmx.trigger(form, 'submit');
        }
      }
    }
  });

})();
