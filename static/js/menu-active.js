// Обновление активного пункта меню при HTMX навигации
document.addEventListener('DOMContentLoaded', function() {
  // Функция для обновления активного пункта меню
  function updateActiveMenuItem() {
    // Получаем текущий URL
    const currentPath = window.location.pathname;
    
    // Убираем класс active у всех ссылок меню
    document.querySelectorAll('.link-menu-left').forEach(link => {
      link.classList.remove('active');
    });
    
    // Находим ссылку, соответствующую текущему URL
    const activeLink = document.querySelector(`.link-menu-left[hx-get="${currentPath}"]`);
    if (activeLink) {
      activeLink.classList.add('active');
    }
  }
  
  // Обновляем при загрузке страницы
  updateActiveMenuItem();
  
  // Слушаем событие HTMX после успешной замены контента
  document.body.addEventListener('htmx:afterSwap', function(event) {
    // Проверяем, что это навигация по меню (target - main-content)
    if (event.detail.target && event.detail.target.id === 'main-content') {
      updateActiveMenuItem();
    }
  });
});

