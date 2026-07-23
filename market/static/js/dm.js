// 1:1 chat page. All configuration comes from data-* attributes so this file
// stays a static asset and satisfies the strict CSP (script-src 'self':
// inline scripts are blocked by the browser).
(function () {
  const box = document.getElementById('messages');
  const form = document.getElementById('dm-form');
  const input = document.getElementById('dm-input');
  const accountBtn = document.getElementById('send-account');
  if (!box || !form) return;

  const me = form.dataset.me;
  const peer = form.dataset.peer;
  const ACCOUNT_PREFIX = form.dataset.accountPrefix;

  const socket = window.appSocket || io();

  function addMessage(message, mine, isAccount) {
    const div = document.createElement('div');
    div.className = 'msg' + (mine ? ' mine' : '') + (isAccount ? ' account' : '');
    if (isAccount) div.title = '클릭하면 계좌 정보가 복사됩니다';
    div.textContent = message;            // textContent => no HTML injection
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
  }

  box.scrollTop = box.scrollHeight;
  // The shared socket (notify.js) may already be connected, in which case the
  // 'connect' event has fired before this script ran — join immediately then.
  const joinRoom = () => socket.emit('join_dm', { peer_id: peer });
  if (socket.connected) joinRoom();
  socket.on('connect', joinRoom);
  socket.on('new_dm', (data) => addMessage(
    data.message, data.sender_id === me,
    data.is_account || (data.message || '').startsWith(ACCOUNT_PREFIX)
  ));
  socket.on('rate_limited', () => addMessage('메시지를 너무 빠르게 보내고 있습니다.', false, false));
  socket.on('account_missing', () => alert('저장된 계좌가 없습니다. 내 계좌 페이지에서 먼저 등록하세요.'));

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const msg = input.value.trim();
    if (!msg) return;
    socket.emit('dm_message', { peer_id: peer, message: msg });
    input.value = '';
  });

  if (accountBtn) {
    accountBtn.addEventListener('click', () => {
      socket.emit('send_account', { peer_id: peer });
    });
  }

  // Clicking an account message copies "은행명 계좌번호 예금주" to the clipboard.
  box.addEventListener('click', (e) => {
    const el = e.target.closest('.msg.account');
    if (!el) return;
    const text = el.textContent.replace(ACCOUNT_PREFIX, '').trim();
    navigator.clipboard.writeText(text).then(
      () => alert('계좌 정보가 클립보드에 복사되었습니다.\n' + text),
      () => alert('클립보드 복사에 실패했습니다.')
    );
  });
})();
