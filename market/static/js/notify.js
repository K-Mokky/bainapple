// Live notification alerts (favorites + incoming DMs), loaded on every page
// for logged-in users. Static asset => satisfies the strict CSP
// (script-src 'self'); all dynamic text goes through textContent, never HTML.
(function () {
  const badge = document.getElementById('notif-badge');
  if (!badge || typeof io !== 'function') return;

  // One shared connection per page; chat_list.js / dm.js reuse it.
  const socket = (window.appSocket = window.appSocket || io());

  function toastContainer() {
    let el = document.getElementById('toasts');
    if (!el) {
      el = document.createElement('div');
      el.id = 'toasts';
      document.body.appendChild(el);
    }
    return el;
  }

  socket.on('notification', (data) => {
    if (!data) return;
    if (typeof data.unread_count === 'number') {
      badge.textContent = data.unread_count;
      badge.hidden = data.unread_count === 0;
    }
    const toast = document.createElement('div');
    toast.className = 'toast';
    const title = document.createElement('strong');
    title.textContent =
      data.type === 'favorite' ? '찜 알림' : (data.username || '') + '님의 새 메시지';
    const body = document.createElement('span');
    body.textContent = data.content || '';
    toast.append(title, body);
    if (data.url) {
      toast.addEventListener('click', () => { window.location.href = data.url; });
    }
    toastContainer().appendChild(toast);
    setTimeout(() => toast.remove(), 6000);
  });
})();
