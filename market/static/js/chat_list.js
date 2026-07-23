// Live conversation list: when someone DMs me, the room jumps to (or appears
// at) the top of the list without a page reload.
(function () {
  const list = document.getElementById('chat-list');
  const empty = document.getElementById('chat-empty');
  if (!list) return;

  const socket = window.appSocket || io();

  socket.on('dm_notify', (data) => {
    if (!data || !data.peer_id) return;
    let item = list.querySelector('.chat-item[data-peer="' + CSS.escape(data.peer_id) + '"]');
    if (!item) {
      item = document.createElement('a');
      item.className = 'chat-item';
      item.dataset.peer = data.peer_id;
      item.href = '/chat/' + encodeURIComponent(data.peer_id);
      const from = document.createElement('span');
      from.className = 'from';
      const preview = document.createElement('span');
      preview.className = 'preview';
      const time = document.createElement('span');
      time.className = 'muted small';
      item.append(from, preview, time);
    }
    item.querySelector('.from').textContent = data.username;      // textContent => no HTML injection
    item.querySelector('.preview').textContent = data.message;
    item.querySelector('.muted').textContent = data.created_at;
    list.prepend(item);
    if (empty) empty.hidden = true;
  });
})();
