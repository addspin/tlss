(function() {

  function initExtCAUpload() {
    var dropZone = document.getElementById('ext-ca-drop-zone');
    if (!dropZone || dropZone.dataset.initialized) return;
    dropZone.dataset.initialized = 'true';

    var fileInput = document.getElementById('ext-ca-file-input');
    var form = document.getElementById('ext-ca-form');
    var clearBtn = document.getElementById('ext-ca-clear-btn');
    var submitBtn = document.getElementById('ext-ca-submit-btn');
    var defaultView = document.getElementById('ext-ca-drop-zone-default');
    var filesView = document.getElementById('ext-ca-drop-zone-files');
    var fileList = document.getElementById('ext-ca-file-list');

    var uploadedFiles = null;

    function setFiles(files) {
      uploadedFiles = files;
      fileList.innerHTML = '';
      for (var i = 0; i < files.length; i++) {
        var div = document.createElement('div');
        div.textContent = files[i].name;
        div.style.fontWeight = '500';
        fileList.appendChild(div);
      }
      defaultView.style.display = 'none';
      filesView.style.display = '';
      submitBtn.disabled = false;
    }

    function clearFiles() {
      uploadedFiles = null;
      fileInput.value = '';
      fileList.innerHTML = '';
      defaultView.style.display = '';
      filesView.style.display = 'none';
      submitBtn.disabled = true;
    }

    function handleFiles(files) {
      if (files.length < 2) {
        Swal.fire({
          customClass: 'custom-alert',
          icon: 'warning',
          title: 'Not enough files',
          text: 'Upload at least 2 files: certificate(s) and private key(s)',
          confirmButtonColor: '#3085d6'
        });
        return;
      }
      setFiles(files);
    }

    form.addEventListener('submit', function(e) {
      e.preventDefault();

      if (!uploadedFiles || uploadedFiles.length < 2) {
        Swal.fire({
          customClass: 'custom-alert',
          icon: 'warning',
          title: 'No files',
          text: 'Please upload PEM files first',
          confirmButtonColor: '#3085d6'
        });
        return;
      }

      var entitySelect = document.getElementById('ext-ca-entity');
      if (!entitySelect.value) {
        Swal.fire({
          customClass: 'custom-alert',
          icon: 'warning',
          title: 'Entity CA required',
          text: 'Please select an Entity CA',
          confirmButtonColor: '#3085d6'
        });
        return;
      }

      var fd = new FormData();
      fd.append('entity_ca_id', entitySelect.value);
      for (var i = 0; i < uploadedFiles.length; i++) {
        fd.append('ca_files', uploadedFiles[i]);
      }

      submitBtn.disabled = true;
      var indicator = submitBtn.querySelector('.htmx-indicator');
      if (indicator) indicator.style.opacity = '1';

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/ext_ca');
      xhr.setRequestHeader('HX-Request', 'true');
      xhr.onload = function() {
        submitBtn.disabled = false;
        if (indicator) indicator.style.opacity = '';

        try {
          var response = JSON.parse(xhr.responseText);
          if (response.status === 'error') {
            Swal.fire({
              showClass: { popup: 'animate__animated animate__fadeInUp animate__fast' },
              hideClass: { popup: 'animate__animated animate__fadeOutDown animate__fast' },
              customClass: 'custom-alert',
              icon: 'error',
              title: 'Error',
              text: response.message,
              confirmButtonColor: '#3085d6'
            });
          } else if (response.status === 'success') {
            Swal.fire({
              showClass: { popup: 'animate__animated animate__fadeInUp animate__fast' },
              hideClass: { popup: 'animate__animated animate__fadeOutDown animate__fast' },
              customClass: 'custom-alert',
              icon: 'success',
              title: 'Success',
              text: response.message,
              confirmButtonColor: '#3085d6'
            }).then(function() {
              htmx.ajax('GET', '/ext_ca_list', {
                target: '#response',
                swap: 'innerHTML'
              });
              clearFiles();
            });
          }
        } catch(err) {}
      };
      xhr.onerror = function() {
        submitBtn.disabled = false;
        if (indicator) indicator.style.opacity = '';
      };
      xhr.send(fd);
    });

    dropZone.addEventListener('click', function(e) {
      if (e.target.id === 'ext-ca-clear-btn' || e.target.closest('#ext-ca-clear-btn')) return;
      fileInput.click();
    });

    fileInput.addEventListener('change', function() {
      if (fileInput.files.length > 0) {
        handleFiles(fileInput.files);
      }
    });

    clearBtn.addEventListener('click', function(e) {
      e.stopPropagation();
      clearFiles();
    });

    dropZone.addEventListener('dragenter', function(e) {
      e.preventDefault();
      e.stopPropagation();
      dropZone.style.borderColor = '#3182CE';
      dropZone.style.background = 'rgba(49, 130, 206, 0.1)';
    });

    dropZone.addEventListener('dragover', function(e) {
      e.preventDefault();
      e.stopPropagation();
    });

    dropZone.addEventListener('dragleave', function(e) {
      if (!dropZone.contains(e.relatedTarget)) {
        dropZone.style.borderColor = '';
        dropZone.style.background = '';
      }
    });

    dropZone.addEventListener('drop', function(e) {
      e.preventDefault();
      e.stopPropagation();
      dropZone.style.borderColor = '';
      dropZone.style.background = '';
      handleFiles(e.dataTransfer.files);
    });
  }

  document.addEventListener('DOMContentLoaded', initExtCAUpload);
  document.addEventListener('htmx:afterSwap', initExtCAUpload);
  document.addEventListener('htmx:load', initExtCAUpload);

})();
