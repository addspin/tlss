function initializeOIDSelect() {
    const selectElements = document.querySelectorAll('select[data-placeholder]');
    
    selectElements.forEach(function(selectElement) {
        if (selectElement.value === '') {
            selectElement.setAttribute('data-placeholder', 'true');
        } else {
            selectElement.setAttribute('data-placeholder', 'false');
        }
        
        selectElement.removeEventListener('change', handleSelectChange);
        selectElement.addEventListener('change', handleSelectChange);
    });
}

function handleSelectChange() {
    if (this.value === '') {
        this.setAttribute('data-placeholder', 'true');
    } else {
        this.setAttribute('data-placeholder', 'false');
    }
}

// Инициализация при загрузке
document.addEventListener('DOMContentLoaded', initializeOIDSelect);

// Реинициализация после HTMX обновлений
document.body.addEventListener('htmx:afterSwap', function(event) {
    if (event.target.id === 'body') {
        setTimeout(initializeOIDSelect, 50);
    }
});

document.body.addEventListener('htmx:afterSettle', function(event) {
    if (event.target.id === 'body') {
        initializeOIDSelect();
    }
});