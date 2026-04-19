(function() {

  function initSSHUpload() {
    var dropZone = document.getElementById('ssh-drop-zone');
    if (!dropZone || dropZone.dataset.initialized) return;
    dropZone.dataset.initialized = 'true';

    var fileInput = document.getElementById('ssh-file-input');
    var form = document.getElementById('add-ssh-key-form');
    var clearBtn = document.getElementById('ssh-clear-files');
    var defaultView = document.getElementById('ssh-drop-zone-default');
    var filesView = document.getElementById('ssh-drop-zone-files');
    var file1Name = document.getElementById('ssh-file1-name');
    var file2Name = document.getElementById('ssh-file2-name');

    // Поля формы генерации
    var algorithmSelect = document.getElementById('select-type');
    var rsaSelect = document.getElementById('select-key-length-rsa');
    var ed25519Select = document.getElementById('select-key-length-ed25519');

    var uploadedFiles = null;

    function setUploadMode(files) {
      uploadedFiles = files;
      file1Name.textContent = files[0].name;
      file2Name.textContent = files[1].name;
      defaultView.style.display = 'none';
      filesView.style.display = '';

      if (algorithmSelect) algorithmSelect.disabled = true;
      if (rsaSelect) rsaSelect.disabled = true;
      if (ed25519Select) ed25519Select.disabled = true;

      form.removeAttribute('hx-ext');
      form.removeAttribute('parse-types');
      form.setAttribute('hx-encoding', 'multipart/form-data');
      htmx.process(form);
    }

    function setGenerateMode() {
      uploadedFiles = null;
      fileInput.value = '';
      defaultView.style.display = '';
      filesView.style.display = 'none';

      if (algorithmSelect) algorithmSelect.disabled = false;
      if (rsaSelect) rsaSelect.disabled = false;
      if (ed25519Select) ed25519Select.disabled = false;

      form.setAttribute('hx-ext', 'json-enc-custom');
      form.setAttribute('parse-types', 'true');
      form.removeAttribute('hx-encoding');
      htmx.process(form);
    }

    function handleFiles(files) {
      if (files.length !== 2) {
        Swal.fire({
          customClass: 'custom-alert',
          icon: 'warning',
          title: 'Need 2 files',
          text: 'Drop both files: private key and public key',
          confirmButtonColor: '#3085d6'
        });
        return;
      }
      setUploadMode(files);
    }

    // Перехватываем submit для отправки файлов
    form.addEventListener('htmx:configRequest', function(e) {
      if (!uploadedFiles) return;

      e.preventDefault();

      var fd = new FormData();
      fd.append('nameSSHKey', document.getElementById('nameSSHKey').value);
      fd.append('ssh_file_1', uploadedFiles[0]);
      fd.append('ssh_file_2', uploadedFiles[1]);

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/add_ssh_key');
      xhr.setRequestHeader('HX-Request', 'true');
      xhr.onload = function() {
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
              htmx.ajax('GET', '/ssh_key_list', {
                target: '#response',
                swap: 'innerHTML'
              });
              document.getElementById('nameSSHKey').value = '';
              setGenerateMode();
            });
          }
        } catch(err) {}
      };
      xhr.send(fd);
    });

    dropZone.addEventListener('click', function(e) {
      if (e.target.id === 'ssh-clear-files' || e.target.closest('#ssh-clear-files')) return;
      fileInput.click();
    });

    fileInput.addEventListener('change', function() {
      if (fileInput.files.length > 0) {
        handleFiles(fileInput.files);
      }
    });

    clearBtn.addEventListener('click', function(e) {
      e.stopPropagation();
      setGenerateMode();
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

  document.addEventListener('DOMContentLoaded', initSSHUpload);
  document.addEventListener('htmx:afterSwap', initSSHUpload);
  document.addEventListener('htmx:load', initSSHUpload);

})();
