/**
 * Table Sorting Utility
 * 
 * Использование:
 * 1. Добавьте class="sortable-header" к <th> элементам
 * 2. Добавьте onclick="sortTable(columnIndex, 'tableId')" к заголовкам
 * 3. Добавьте <span class="sort-arrow" id="arrow-{columnIndex}">▼</span> внутрь <th>
 * 4. Убедитесь, что у таблицы есть id
 * 
 * Пример:
 * <th class="sortable-header" onclick="sortTable(0, 'myTable')">
 *   Название
 *   <span class="sort-arrow" id="arrow-0">▼</span>
 * </th>
 */

// Хранение направлений сортировки для разных таблиц
let tableSortDirections = {};

/**
 * Сортирует таблицу по указанной колонке
 * @param {number} columnIndex - Индекс колонки для сортировки (начиная с 0)
 * @param {string} tableId - ID таблицы
 * @param {string} locale - Локаль для сортировки (по умолчанию 'ru')
 */
function sortTable(columnIndex, tableId, locale = 'ru') {
  const table = document.getElementById(tableId);
  if (!table) {
    console.error(`Таблица с id "${tableId}" не найдена`);
    return;
  }

  const tbody = table.querySelector('tbody');
  if (!tbody) {
    console.error(`tbody не найден в таблице "${tableId}"`);
    return;
  }

  const rows = Array.from(tbody.querySelectorAll('tr'));
  
  // Инициализируем объект для хранения направлений этой таблицы
  if (!tableSortDirections[tableId]) {
    tableSortDirections[tableId] = {};
  }
  
  // Определяем направление сортировки
  if (!tableSortDirections[tableId][columnIndex]) {
    tableSortDirections[tableId][columnIndex] = 'asc';
  } else {
    tableSortDirections[tableId][columnIndex] = 
      tableSortDirections[tableId][columnIndex] === 'asc' ? 'desc' : 'asc';
  }
  
  const direction = tableSortDirections[tableId][columnIndex];
  
  // Сортируем строки
  rows.sort((a, b) => {
    const aCell = a.cells[columnIndex];
    const bCell = b.cells[columnIndex];
    
    if (!aCell || !bCell) {
      return 0;
    }
    
    const aValue = aCell.textContent.trim().toLowerCase();
    const bValue = bCell.textContent.trim().toLowerCase();
    
    if (direction === 'asc') {
      return aValue.localeCompare(bValue, locale);
    } else {
      return bValue.localeCompare(aValue, locale);
    }
  });
  
  // Очищаем tbody и добавляем отсортированные строки
  tbody.innerHTML = '';
  rows.forEach(row => tbody.appendChild(row));
  
  // Обновляем стрелки
  updateSortArrows(columnIndex, direction, tableId);
}

/**
 * Обновляет визуальные индикаторы стрелок сортировки
 * @param {number} activeColumn - Активная колонка
 * @param {string} direction - Направление ('asc' или 'desc')
 * @param {string} tableId - ID таблицы
 */
function updateSortArrows(activeColumn, direction, tableId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  
  // Сбрасываем все стрелки в этой таблице
  table.querySelectorAll('.sort-arrow').forEach(arrow => {
    arrow.classList.remove('active');
    arrow.textContent = '▼';
  });
  
  // Устанавливаем активную стрелку
  const activeArrow = table.querySelector(`#arrow-${activeColumn}`);
  if (activeArrow) {
    activeArrow.classList.add('active');
    activeArrow.textContent = direction === 'asc' ? '▲' : '▼';
  }
}

/**
 * Сбрасывает сортировку таблицы к исходному состоянию
 * @param {string} tableId - ID таблицы
 */
function resetTableSort(tableId) {
  if (tableSortDirections[tableId]) {
    tableSortDirections[tableId] = {};
  }
  
  const table = document.getElementById(tableId);
  if (!table) return;
  
  table.querySelectorAll('.sort-arrow').forEach(arrow => {
    arrow.classList.remove('active');
    arrow.textContent = '▼';
  });
}

