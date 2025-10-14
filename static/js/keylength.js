// Функция инициализации для работы с Key Length
function initKeyLengthControl() {
    const algorithmSelect = document.getElementById('select-type');
    const keyLengthSelect = document.getElementById('select-key-length');
    
    // Проверяем, что элементы существуют (для страниц, где их нет)
    if (!algorithmSelect || !keyLengthSelect) {
      return;
    }
    
    // Функция для обновления состояния поля Key Length
    function updateKeyLengthState() {
      const algorithm = algorithmSelect.value;
      
      if (algorithm === 'ED25519') {
        // Блокируем выбор и устанавливаем 256
        keyLengthSelect.disabled = true;
        keyLengthSelect.value = '256';
        keyLengthSelect.style.opacity = '0.6';
        keyLengthSelect.style.cursor = 'not-allowed';
        
        // Показываем опцию 256 и скрываем остальные
        Array.from(keyLengthSelect.options).forEach(option => {
          if (option.value === '256') {
            option.style.display = 'block';
            option.selected = true;
          } else {
            option.style.display = 'none';
          }
        });
      } else {
        // Разблокируем для RSA
        keyLengthSelect.disabled = false;
        keyLengthSelect.style.opacity = '1';
        keyLengthSelect.style.cursor = 'pointer';
        
        // Скрываем опцию 256 и показываем RSA опции
        Array.from(keyLengthSelect.options).forEach(option => {
          if (option.value === '256') {
            option.style.display = 'none';
          } else {
            option.style.display = 'block';
          }
        });
        
        // Восстанавливаем значение по умолчанию (4096)
        if (keyLengthSelect.value === '256') {
          keyLengthSelect.value = '4096';
        }
      }
    }
    
    // Удаляем старый обработчик, если он был (чтобы избежать дублей)
    algorithmSelect.removeEventListener('change', updateKeyLengthState);
    
    // Слушаем изменение алгоритма
    algorithmSelect.addEventListener('change', updateKeyLengthState);
    
    // Инициализируем состояние
    updateKeyLengthState();
  }
  
  // Запускаем при первой загрузке страницы
  document.addEventListener('DOMContentLoaded', initKeyLengthControl);
  
  // Запускаем после каждой загрузки контента через HTMX
  document.addEventListener('htmx:afterSwap', initKeyLengthControl);
  
  // Альтернативно/дополнительно - когда HTMX полностью обработал новый контент
  document.addEventListener('htmx:load', initKeyLengthControl);