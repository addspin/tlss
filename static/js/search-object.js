// Универсальная функция поиска с делегированием событий
function setupSearchDelegation() {
    // Функция поиска для серверов в левой панели
    function searchInServerList(value) {
        // Ищем по ID (для Add certs)
        const serverContainer = document.getElementById('server-list-container');
        if (serverContainer) {
            const serverButtons = serverContainer.querySelectorAll('.row-auto');
            serverButtons.forEach(function(button) {
                const text = button.textContent.toLowerCase();
                button.style.display = text.indexOf(value) > -1 ? '' : 'none';
            });
        }
        
        // Ищем по классу (для Revoke разделов)
        const serverContainers = document.querySelectorAll('.server-list-container .row-auto');
        serverContainers.forEach(function(button) {
            const text = button.textContent.toLowerCase();
            button.style.display = text.indexOf(value) > -1 ? '' : 'none';
        });
    }

    // Функция поиска в таблицах серверов
    function searchInServerTable(value) {
        const tableRows = document.querySelectorAll('.servers_table table tbody tr');
        tableRows.forEach(function(row) {
            const text = row.textContent.toLowerCase();
            row.style.display = text.indexOf(value) > -1 ? '' : 'none';
        });
    }

    // Функция поиска сертификатов
    function searchInCertTables(value) {
        const certTables = document.querySelectorAll('.server-cert-tables table tbody tr, .certs_revoke_table table tbody tr');
        certTables.forEach(function(row) {
            const text = row.textContent.toLowerCase();
            row.style.display = text.indexOf(value) > -1 ? '' : 'none';
        });
    }

    // Функция поиска сущностей
    function searchInEntityList(value) {
        const entityButtons = document.querySelectorAll('.server-list-container .row-auto');
        entityButtons.forEach(function(button) {
            const text = button.textContent.toLowerCase();
            button.style.display = text.indexOf(value) > -1 ? '' : 'none';
        });
    }

    // Делегирование событий на документ для всех типов поиска
    document.addEventListener('input', function(e) {
        const target = e.target;
        
        // Проверяем класс и имя для определения типа поиска
        if (target.classList.contains('search-input')) {
            const value = target.value.toLowerCase();
            const name = target.getAttribute('name');
            
            switch(name) {
                case 'search-server':
                    searchInServerList(value);
                    break;
                case 'search-servers':
                    searchInServerTable(value);
                    break;
                case 'search-certs':
                    searchInCertTables(value);
                    break;
                case 'search-entity':
                    searchInEntityList(value);
                    break;
            }
        }
    });
}

// Инициализация только один раз при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
    setupSearchDelegation();
});