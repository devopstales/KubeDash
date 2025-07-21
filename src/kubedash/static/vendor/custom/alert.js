// Notification functions
function removeNotification(id) {
  const notification = document.getElementById(id);
  if (notification) {
      notification.style.opacity = '0';
      setTimeout(() => {
          notification.remove();
          updateNotificationBadge();
          checkEmptyNotifications();
      }, 300);
  }
}

function clearAllNotifications() {
    const notifications = document.querySelectorAll('.notification-item');
    notifications.forEach(notification => {
        notification.style.opacity = '0';
        setTimeout(() => {
            notification.remove();
        }, 300);
    });
    setTimeout(() => {
        updateNotificationBadge();
        checkEmptyNotifications();
    }, 350);
}

function checkEmptyNotifications() {
    const notificationList = document.getElementById('notificationList');
    if (notificationList.querySelectorAll('.notification-item').length === 0) {
        notificationList.innerHTML = '<li class="px-3 py-2 text-center text-muted small">No notifications</li>';
    }
}

function updateNotificationBadge() {
    const count = document.querySelectorAll('.notification-item').length;
    const badge = document.querySelector('.position-relative .badge');
    
    if (count > 0) {
        if (!badge) {
            // Create badge if it doesn't exist
            const newBadge = document.createElement('span');
            newBadge.className = 'position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger';
            newBadge.innerHTML = `${count}${count >= 9 ? '+' : ''}<span class="visually-hidden">unread messages</span>`;
            document.querySelector('.position-relative').appendChild(newBadge);
        } else {
            // Update existing badge
            badge.innerHTML = `${count}${count >= 9 ? '+' : ''}<span class="visually-hidden">unread messages</span>`;
        }
    } else if (badge) {
        // Remove badge if no notifications
        badge.remove();
    }
}

// Format time function
function formatTime(date) {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
