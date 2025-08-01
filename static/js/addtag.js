
// Функция для добавления тега
function addTag(inputId, tagsContainerId, hiddenFieldId, duplicateMessage) {
  console.log('addTag called with:', inputId, tagsContainerId, hiddenFieldId);
  const input = document.getElementById(inputId);
  const tagsContainer = document.getElementById(tagsContainerId);
  
  if (!input) {
    console.error('Input element not found:', inputId);
    return;
  }
  if (!tagsContainer) {
    console.error('Tags container not found:', tagsContainerId);
    return;
  }
  
  const value = input.value.trim();
  console.log('Input value:', value);
  
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
        updateHiddenField(tagsContainerId, hiddenFieldId);
      });
      tagElement.appendChild(closeButton);
      
      // Добавляем тег в контейнер
      tagsContainer.appendChild(tagElement);
      
      // Очищаем поле ввода
      input.value = '';
      
      // Обновляем скрытое поле
      updateHiddenField(tagsContainerId, hiddenFieldId);
    } else {
      // Если такой тег уже существует, можно показать сообщение
      alert(duplicateMessage);
    }
  }
}

// Обертки для конкретных полей
function addSanTag() {
  addTag('san-input', 'san-tags', 'san-values', 'Этот домен уже добавлен!');
}

function addOidTag() {
  addTag('oid-input', 'oid-tags', 'oid-values', 'Это значение OID уже добавлено!');
}

// Функция для обновления скрытого поля с данными тегов
function updateHiddenField(tagsContainerId, hiddenFieldId) {
  const tags = document.querySelectorAll(`#${tagsContainerId} .tag-text`);
  const values = Array.from(tags).map(tag => tag.textContent.trim());
  // Сохраняем как строку через запятую
  document.getElementById(hiddenFieldId).value = values.join(',');
}

// Обертки для конкретных полей
function updateSanField() {
  updateHiddenField('san-tags', 'san-values');
}

function updateOidField() {
  updateHiddenField('oid-tags', 'oid-values');
}

// Функция инициализации полей с тегами
function initializeTagFields() {
  console.log('Initializing tag fields...');
  
  // Инициализируем поля как пустые строки
  const sanValues = document.getElementById('san-values');
  const oidValues = document.getElementById('oid-values');
  
  if (sanValues) sanValues.value = '';
  if (oidValues) oidValues.value = '';
  
  console.log('Tag fields found:', !!sanValues, !!oidValues);
}

// Глобальный обработчик клавиш с делегированием событий
document.addEventListener('keydown', function(event) {
  if (event.key === 'Enter') {
    const target = event.target;
    
    if (target.id === 'san-input') {
      console.log('Enter pressed in SAN input');
      event.preventDefault();
      addSanTag();
      return false;
    }
    
    if (target.id === 'oid-input') {
      console.log('Enter pressed in OID input');
      event.preventDefault();
      addOidTag();
      return false;
    }
  }
});

// Глобальный обработчик для HTMX запросов
document.addEventListener('htmx:beforeRequest', function(event) {
  console.log('HTMX before request');
  // Обновляем поля перед отправкой
  const sanValues = document.getElementById('san-values');
  const oidValues = document.getElementById('oid-values');
  
  if (sanValues) updateSanField();
  if (oidValues) updateOidField();
});

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
  console.log('DOMContentLoaded fired');
  initializeTagFields();
});

// Инициализация после HTMX загрузки контента в #body
document.body.addEventListener('htmx:afterSwap', function(event) {
  console.log('HTMX content swapped in body, target:', event.target);
  if (event.target.id === 'body') {
    console.log('Body content swapped, reinitializing...');
    setTimeout(initializeTagFields, 50);
  }
});

// Дополнительный обработчик для afterSettle
document.body.addEventListener('htmx:afterSettle', function(event) {
  console.log('HTMX settled in body, target:', event.target);
  if (event.target.id === 'body') {
    console.log('Body settled, checking initialization...');
    initializeTagFields();
  }
});

// Дополнительный обработчик для загрузки нового контента
document.addEventListener('htmx:load', function(event) {
  console.log('HTMX load event fired, target:', event.target);
  setTimeout(initializeTagFields, 50);
});

