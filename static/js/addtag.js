
// Функция для добавления тега
function addTag() {
  const input = document.getElementById('san-input');
  const tagsContainer = document.getElementById('san-tags');
  const value = input.value.trim();
  
  if (value) {
    // Проверка на дубликаты
    const existingTags = Array.from(tagsContainer.querySelectorAll('.tag-text'))
      .map(tag => tag.textContent.trim());
    
    if (!existingTags.includes(value)) {
      // Создаем элемент тега
      const tagElement = document.createElement('div');
      tagElement.className = 'tag';
      
      // Добавляем текст тега
      const tagText = document.createElement('span');
      tagText.className = 'tag-text';
      tagText.textContent = value;
      tagElement.appendChild(tagText);
      
      // Добавляем кнопку закрытия
      const closeButton = document.createElement('span');
      closeButton.className = 'close';
      closeButton.innerHTML = '&times;';
      closeButton.addEventListener('click', function() {
        tagElement.remove();
        updateHiddenField();
      });
      tagElement.appendChild(closeButton);
      
      // Добавляем тег в контейнер
      tagsContainer.appendChild(tagElement);
      
      // Очищаем поле ввода
      input.value = '';
      
      // Обновляем скрытое поле
      updateHiddenField();
    } else {
      // Если такой тег уже существует, можно показать сообщение
      alert('Этот домен уже добавлен!');
    }
  }
}

// Функция для обновления скрытого поля с данными тегов
function updateHiddenField() {
  const tags = document.querySelectorAll('#san-tags .tag-text');
  const values = Array.from(tags).map(tag => tag.textContent.trim());
  // Сохраняем как JSON массив
  document.getElementById('san-values').value = JSON.stringify(values);
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
  // Инициализируем поле SAN как пустой массив
  document.getElementById('san-values').value = JSON.stringify([]);
  
  // Добавляем обработчик события перед отправкой формы
  document.querySelector('form').addEventListener('htmx:beforeRequest', function(event) {
    // Проверяем, что поле SAN существует и имеет значение
    const sanField = document.getElementById('san-values');
    if (sanField && sanField.value === '') {
      // Если поле пустое, устанавливаем его как пустой массив
      sanField.value = JSON.stringify([]);
    }
  });
});
