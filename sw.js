

self.addEventListener('push', function (event) {
  const data = event.data.json();

  const options = {
    body: data.body,
    icon: '/pfp.ico', // Optional
    badge: '/badge.png', // Optional
    data: {
      url: 'http://127.0.0.1:5500/index.html'  // 👈 Set your website URL here
    }
  };

  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close(); // Close notification

  event.waitUntil(
    clients.matchAll({ type: 'window' }).then(windowClients => {
      // If site is already open, focus it
      for (let client of windowClients) {
        if (client.url === event.notification.data.url && 'focus' in client) {
          return client.focus();
        }
      }

      // Otherwise, open a new tab
      if (clients.openWindow) {
        return clients.openWindow(event.notification.data.url);
      }
    })
  );
});
