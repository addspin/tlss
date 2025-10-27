// Функция для управления селектами Key Length
function initKeyLengthControl() {
  const algorithmSelect = document.getElementById('select-type');
  const keyLengthHiddenInput = document.getElementById('key-length-value');
  
  // Проверяем, что элементы существуют
  if (!algorithmSelect || !keyLengthHiddenInput) {
    return;
  }
  
  // Получаем все селекты для key length
  const rsaSelect = document.getElementById('select-key-length-rsa');
  const ecdsaSelect = document.getElementById('select-key-length-ecdsa');
  const ed25519Select = document.getElementById('select-key-length-ed25519');
  
  // Функция обновления видимости селектов
  function updateKeyLengthSelects() {
    const algorithm = algorithmSelect.value;
    
    console.log('Выбран алгоритм:', algorithm);
    
    // Скрываем все селекты
    if (rsaSelect) rsaSelect.style.display = 'none';
    if (ecdsaSelect) ecdsaSelect.style.display = 'none';
    if (ed25519Select) ed25519Select.style.display = 'none';
    
    // Показываем нужный селект и обновляем hidden input
    if (algorithm === 'RSA' && rsaSelect) {
      rsaSelect.style.display = '';
      keyLengthHiddenInput.value = rsaSelect.value;
    } else if (algorithm === 'ECDSA' && ecdsaSelect) {
      ecdsaSelect.style.display = '';
      keyLengthHiddenInput.value = ecdsaSelect.value;
    } else if (algorithm === 'ED25519' && ed25519Select) {
      ed25519Select.style.display = '';
      keyLengthHiddenInput.value = ed25519Select.value;
    }
    
    console.log('Key Length:', keyLengthHiddenInput.value);
  }
  
  // Обновляем hidden input при изменении любого селекта
  if (rsaSelect) {
    rsaSelect.addEventListener('change', function() {
      keyLengthHiddenInput.value = this.value;
    });
  }
  if (ecdsaSelect) {
    ecdsaSelect.addEventListener('change', function() {
      keyLengthHiddenInput.value = this.value;
    });
  }
  if (ed25519Select) {
    ed25519Select.addEventListener('change', function() {
      keyLengthHiddenInput.value = this.value;
    });
  }
  
  // Слушаем изменение алгоритма
  algorithmSelect.addEventListener('change', updateKeyLengthSelects);
  
  // Инициализируем состояние
  updateKeyLengthSelects();
}

// Запускаем при первой загрузке страницы
document.addEventListener('DOMContentLoaded', initKeyLengthControl);

// Запускаем после каждой загрузки контента через HTMX
document.addEventListener('htmx:afterSwap', initKeyLengthControl);

// Запускаем когда HTMX полностью обработал новый контент
document.addEventListener('htmx:load', initKeyLengthControl);