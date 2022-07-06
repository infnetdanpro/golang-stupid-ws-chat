# golang-stupid-ws-chat

1. Request POST `/auth` with payload: `{"username":"test"}` and save token
2. Get list of subscibed channels: `/sub?token=...`
3. Create and subsribe user to channel: `/sub` POST with payload: `{"token": "...", "channel_name": "..."}`
4. Connect to WS (`/ws`) and do the first request to websocket for auth: `{"token": "...", "is_login": true}`
5. Example payload to write message (send to ws): `{"token": "...", "channel_name": "...", "message": {"message_type": "text", "message_text": "..."}}`
