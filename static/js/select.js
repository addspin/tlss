// Ждем загрузки DOM
document.addEventListener('DOMContentLoaded', function() {
    // Находим все select элементы с атрибутом data-placeholder
    const selectElements = document.querySelectorAll('select[data-placeholder]');
    
    selectElements.forEach(function(selectElement) {
        // Устанавливаем начальное состояние при загрузке страницы
        if (selectElement.value === '') {
            selectElement.setAttribute('data-placeholder', 'true');
        } else {
            selectElement.setAttribute('data-placeholder', 'false');
        }
        
        // Обработчик изменения значения
        selectElement.addEventListener('change', function() {
            if (this.value === '') {
                this.setAttribute('data-placeholder', 'true');
            } else {
                this.setAttribute('data-placeholder', 'false');
            }
        });
    });
});