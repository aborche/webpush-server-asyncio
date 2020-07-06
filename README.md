## AsyncIo WebPush mini server for Mozilla Firefox

1. clone Repo
2. change nginx config to your certificate and docroot directory
3. put nginx config to your system. Reload nginx
4. change SERVERNAME in **ws_server.py**
5. move context of web directory to your docroot directory
6. create virtualenv or install python requirements to system with **pip install -r requirements**
7. run **python3 ws_server.py** from console or run **python3 ws_daemon.py** for daemonize
7. change **dom.push.serverURL** in your browser(about:config) to **wss://your_server/ws**
8. check ws_server.log for browser connection and hello phase
9. open your browser **https://your_server/indexpush.html**
10. check browser console for errors
11. if not errors detected - push 'Check Push Notify' button

## supported URL's
WebPush сервер поддерживает следующие вызовы :
* POST https://webpush.example.net/wpush/channelId - save crypto keys(register phase)
* GET https://webpush.example.net/wpush/channelId - get notification message
* GET https://webpush.example.net/subscription - subscribe(register/subscription phase)
* POST https://webpush.example.net/pushdata - send JSON body as message to browser
```
{
            "url": "http://github.com/", // Target URL 
            "recipient": login, // User Login or another UserId. (look USERIDHEADERNAME in ws_server.py)
            "title": "Message Title",
            "body": "Message Body", 
            "icon": "/static/images/new-notification.png", // message Icon
            "version": uuid, // message id
            "tag": uuid, // tag ID
            "mtime": parseInt(new Date().getTime()/1000) // Timestamp
}
```
* GET https://webpush.example.net/getdata - Get messages queue
* POST https://webpush.example.net/notify/login - send notify message without body to login
* POST https://webpush.example.net/notifychannel/channelId - send notify message without body to channel
