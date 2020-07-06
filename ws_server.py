#!/usr/bin/env python
# -*- coding: utf8 -*-

# AsyncIO WebPush server example
# (c) aborche 2020

import asyncio
import json
import time
import pathlib
import ssl
import uuid
import logging
import websockets
import base64
import random
import traceback

from collections import deque
from aiohttp import web
from log import *

import http_ece
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

SERVERNAME='webpush.example.net'
USERIDHEADERNAME='X-Remote-Addr'

# Время жизни сообщений в очереди
TTL=10
# вебсокеты
WS = set()
# каналы
CHANNELS = dict()
# привязка каналов к вебсокету
CHANNELWSPAIR = dict()
# привязка ключей шифрования канала к вебсокету
CHANNELKEYS = dict()
# привязка имён пользователей из строки авторизации к каналам
LOGINS_IN_CHANNELS = dict()
# Очередь сообщений для текущих подключений
MESSAGESDICT = dict()
GLOBALQUEUE = deque([])

VAPID_PUBLIC_KEY = 'BO_C-Ou-wXR_LbJUEtXEfOcVcVrbU8gNOzsL0dSKET9PRtB0wq21YtgWEzKu2U4HZ9XeElUIdRfc6EBbRudAjq4'

class CaseInsensitiveDict(dict):
    """A dictionary that has case-insensitive keys"""

    def __init__(self, data={}, **kwargs):
        for key in data:
            dict.__setitem__(self, key.lower(), data[key])
        self.update(kwargs)

    def __contains__(self, key):
        return dict.__contains__(self, key.lower())

    def __setitem__(self, key, value):
        dict.__setitem__(self, key.lower(), value)

    def __getitem__(self, key):
        return dict.__getitem__(self, key.lower())

    def __delitem__(self, key):
        dict.__delitem__(self, key.lower())

    def get(self, key, default=None):
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def update(self, data):
        for key in data:
            self.__setitem__(key, data[key])


class PushConnectionHandler(object):
    valid_encodings = [
        # "aesgcm128",  # this is draft-0, but DO NOT USE.
        "aesgcm",  # draft-httpbis-encryption-encoding-01
        "aes128gcm"  # RFC8188 Standard encoding
    ]
    
    def __init__(self, websocket, *args, **kwargs):
        self.websocket = websocket
        self.uaid = None
        self.pushkeys = {}
        self.username = None
        self.mqueue = deque([])
        self.auth_key = self.receiver_key = None
        self.broadcasts = {}
        self.server_public_key = None
        self.channel_id = None
    
    def register_broadcasts(self, broadcasts):
        self.broadcasts.update(broadcasts)
    
    def register_keys(self, keypair):
        self.pushkeys.update(keypair)
        self.auth_key = self.receiver_key = None
        for k in ['p256dh', 'auth']:
            if self.pushkeys.get(k) is None:
                raise WebPushException("Missing keys value: {}".format(k))
            if isinstance(self.pushkeys[k], str):
                self.pushkeys[k] = bytes(self.pushkeys[k].encode('utf8'))
        receiver_raw = base64.urlsafe_b64decode(
           self._repad(self.pushkeys['p256dh']))
        if len(receiver_raw) != 65 and receiver_raw[0] != "\x04":
            raise WebPushException("Invalid p256dh key specified")
        self.receiver_key = receiver_raw
        self.auth_key = base64.urlsafe_b64decode(
            self._repad(self.pushkeys['auth']))
        logger.debug('Receiver key: %s' % self.receiver_key)
        logger.debug('Auth key: %s' % self.auth_key)
    
    async def send_push_message(self, body=None, version=None):
        logger.debug('send push body: %s' % body)
        if version is not None:
            self.mqueue.append(version)
        else:
            version = '%s' % uuid.uuid4()
        message = {
            "messageType": "notification",
            "channelID": "%s" % self.channel_id,
            "version": "%s" % version
        }
        encoded = None
        if body is not None:
            if self.auth_key is not None and self.receiver_key is not None:
                encoded = self.encrypt_message(body)
                if 'data' in encoded:
                    message.update(encoded)
        try:
            await self.websocket.send(json.dumps(message))
        except Exception as ex:
                logger.error('PushConnectionHandler: Send Push Message exception occured: %s. Channel: %s' % (vars(ex), channel))
        
    def handle_ack(self, data):
        pass
        
    def handle_unack(self, data):
        pass
    
    def _repad(self, data):
        """Add base64 padding to the end of a string, if required"""
        return data + b"===="[:len(data) % 4]
        
    def encrypt_message(self, data, content_encoding="aes128gcm"):
        """Encrypt the data.

        :param data: A serialized block of byte data (String, JSON, bit array,
            etc.) Make sure that whatever you send, your client knows how
            to understand it.
        :type data: str
        :param content_encoding: The content_encoding type to use to encrypt
            the data. Defaults to RFC8188 "aes128gcm". The previous draft-01 is
            "aesgcm", however this format is now deprecated.
        :type content_encoding: enum("aesgcm", "aes128gcm")

        """
        # Salt is a random 16 byte array.
        if not data:
            logger.error("PushEncryptMessage: No data found...")
            return
        if not self.auth_key or not self.receiver_key:
            raise WebPushException("No keys specified in subscription info")
        logger.debug("PushEncryptMessage: Encoding data...")
        salt = None
        if content_encoding not in self.valid_encodings:
            raise WebPushException("Invalid content encoding specified. "
                                   "Select from " +
                                   json.dumps(self.valid_encodings))
        if content_encoding == "aesgcm":
            logger.debug("PushEncryptMessage: Generating salt for aesgcm...")
            salt = os.urandom(16)
        # The server key is an ephemeral ECDH key used only for this
        # transaction
        server_key = ec.generate_private_key(ec.SECP256R1, default_backend())
        crypto_key = server_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        if isinstance(data, str):
            data = bytes(data.encode('utf8'))
        if content_encoding == "aes128gcm":
            logger.debug("Encrypting to aes128gcm...")
            encrypted = http_ece.encrypt(
                data,
                salt=salt,
                private_key=server_key,
                dh=self.receiver_key,
                auth_secret=self.auth_key,
                version=content_encoding)
            reply = CaseInsensitiveDict({
                'data': base64.urlsafe_b64encode(encrypted).decode()
            })
        else:
            logger.debug("Encrypting to aesgcm...")
            crypto_key = base64.urlsafe_b64encode(crypto_key).strip(b'=')
            encrypted = http_ece.encrypt(
                data,
                salt=salt,
                private_key=server_key,
                keyid=crypto_key.decode(),
                dh=self.receiver_key,
                auth_secret=self.auth_key,
                version=content_encoding)
            reply = CaseInsensitiveDict({
                'crypto_key': crypto_key,
                'data': base64.urlsafe_b64encode(encrypted).decode()
            })
            if salt:
                reply['salt'] = base64.urlsafe_b64encode(salt).strip(b'=')

        reply['headers'] = { 'encoding': content_encoding }
        return reply


async def send_push_notification(username, bodydata=None):
    logger.debug('send_push_notification: %s'%LOGINS_IN_CHANNELS)
    if username not in LOGINS_IN_CHANNELS:
        return False
    for channel in LOGINS_IN_CHANNELS[username].keys():
        if channel in CHANNELS:
            logger.debug('Send notification to channel: %s' % channel)
            logger.debug('BodyData: %s => %s'%(type(bodydata), bodydata))
            logger.debug('Send notification to websocket.handler: %s' % CHANNELS[channel])
            try:
                try:
                    jbodydata = json.loads(bodydata)
                    if 'version' in jbodydata:
                        version = jbodydata['version']
                        jbodydata.remove('version')
                        bodydata = json.dumps(jbodydata)
                        await CHANNELS[channel].send_push_message(bodydata, version=version)
                    else:
                        raise
                except:
                    await CHANNELS[channel].send_push_message(bodydata)
            except Exception as ex:
                traceback.print_exc()
                logger.error('Send Push Notification exception occured: %s. Channel: %s' % (ex, channel))
    return True

async def send_push_notification_channel(channel, bodydata=None):
    if channel not in CHANNELS:
        return False
    else:
        logger.debug('Send notification to channel: %s' % channel)
        logger.debug('BodyData: %s => %s'%(type(bodydata), bodydata))
        logger.debug('Send notification to websocket.handler: %s' % CHANNELS[channel])
        try:
            try:
                jbodydata = json.loads(bodydata)
                if 'version' in jbodydata:
                    version = jbodydata['version']
                    jbodydata.remove('version')
                    bodydata = json.dumps(jbodydata)
                    logger.debug('CHANNELS: %s' % CHANNELS)
                    await CHANNELS[channel].send_push_message(bodydata, version=version)
                else:
                    raise
            except:
                logger.debug('CHANNELS: %s' % CHANNELS)
                await CHANNELS[channel].send_push_message(bodydata)
        except Exception as ex:
            traceback.print_exc()
            logger.error('Send Push Notification exception occured: %s. Channel: %s' % (ex, channel))
    return True


async def send_broadcast_message(data):
    #    bcast = dict((k,'v%s'%random.randint(0,1000)) for k,v in CHANNELS[ws]['broadcasts'].items())
    #    logger.debug('Change broadcast version for channel: [%s] to [%s]'%(ws, bcast))
    #    message = {
    #        "messageType": "broadcast",
    #        'broadcasts': bcast
    #    }
    #    await ws.send(json.dumps(message))
    pass


async def update_channel_keys(request, data):
    channel = request.path.replace('wpush','').replace('/','')
    logger.debug('update channel keys data: %s'%data)
    logger.debug('Update Channel keys Headers: %s' % request.headers)
    if USERIDHEADERNAME not in set(request.headers):
        return False
    basiclogin = request.headers[USERIDHEADERNAME]
    logger.debug('Login %s' % basiclogin)
    if basiclogin not in LOGINS_IN_CHANNELS:
        LOGINS_IN_CHANNELS.update({ '%s'%basiclogin : {} })
    LOGINS_IN_CHANNELS['%s'%basiclogin].update({'%s' % channel : {} })
    logger.debug('LOGINS_IN_CHANNELS: %s' % LOGINS_IN_CHANNELS)
    try:
        jdata = json.loads(data)
        if 'endpoint' in jdata and 'keys' in jdata: 
            logger.debug('Saving Keys for Channel: %s => %s' % (channel, jdata))
            CHANNELS[channel].register_keys(jdata['keys'])
            logger.debug('Registered channel keys %s:' % vars(CHANNELS[channel]))
        return True
    except Exception as ex:
        logger.error('Exception %s'%ex)
        return False

async def ping_reply():
    await asyncio.wait()

async def register(websocket):
    try:
        WS.add(websocket)
        websocket.handler = PushConnectionHandler(websocket)
    except Exception as ex:
        logger.error('Register exception: %s' % ex)

async def unregister(websocket):
    try:
        del CHANNELS[websocket.handler.channel_id]
        del WS[websocket]
        logger.debug('UnregisterWebsocket[websocket]: %s'%websocket)
    except Exception as ex:
        pass
        logger.error('Unregister exception: %s' % ex)

async def pushserver(websocket, path):
    await register(websocket)
    try:
        await websocket.send(json.dumps({}))
        async for message in websocket:
            data = json.loads(message)
            logger.info('Incoming message[data]: %s => %s '%(message, data))
            if message == '{}':
                await websocket.send(json.dumps({}))
            elif 'messageType' in data:
                logger.info('Processing WebSocket Data')
                # Подключение к вебсокету из браузера
                if data['messageType'] == 'hello':
                    # Если это первичное подключение, то нужно задать идентификатор подключения и вернуть его браузеру
                    if 'uaid' not in data:
                        data['uaid'] = '%s' % uuid.uuid4()
                    # Принудительно включить webpush
                    if 'use_webpush' not in data:
                        data['use_webpush'] = True
                    helloreturn = {
                        "messageType": "hello",
                        "status": 200,
                        "uaid": data['uaid'],
                        "use_webpush": data['use_webpush']
                        }
                    websocket.handler.uaid = data['uaid']
                    if 'broadcasts' in data:
                        websocket.handler.register_broadcasts(data['broadcasts'])
                    logger.debug('Hello websocket: %s' % vars(websocket.handler))
                    CHANNELS.update({ data['uaid'] : websocket.handler })
                    await websocket.send(json.dumps(helloreturn))
                elif data['messageType'] == 'register':
                    # Регистрация serviceWorker
                    logger.debug('Register[data]: %s'%data)
                    registerreturn = {
                        "messageType": "register",
                        "channelID": data['channelID'],
                        "status": 200,
                        "pushEndpoint": "https://%s/wpush/%s/" % (SERVERNAME,data['channelID']),
                        "scope": "https://%s/" % SERVERNAME
                    }
                    websocket.handler.channel_id = data['channelID']
                    if 'key' in data:
                        websocket.handler.server_public_key = data['key']
                    logger.debug('Register[registerreturn]: %s'%registerreturn)
                    CHANNELS.update({ data['channelID'] : websocket.handler })
                    await websocket.send(json.dumps(registerreturn))
                elif data['messageType'] == 'unregister':
                    unregisterreturn = {
                        "messageType": "unregister",
                        "channelID": data['channelID'],
                        "status": 200
                    }
                    if data['channelID'] in CHANNELS:
                        del CHANNELS[data['channelID']]
                    logger.debug('Unregister[unregisterreturn]: %s'%unregisterreturn)
                    logger.debug('Unregister[CHANNELS]: %s'%CHANNELS)
                    await websocket.send(json.dumps(unregisterreturn))
                elif data['messageType'] == 'ack':
                    logger.debug('Ack: %s' % data)
                    for update in data['updates']:
                        if CHANNELS[update['channelID']].mqueue.count(update['version']) > 0:
                            CHANNELS[update['channelID']].mqueue.remove(update['version'])
                    logger.debug('Mqueue for channel %s is %s' % (websocket.handler.channel_id, websocket.handler.mqueue))
                    await websocket.send('{}')
                elif data['messageType'] == 'nack':
                    await websocket.send('{}')
            else:
                logger.error("unsupported event: {}", data)
    finally:
        await unregister(websocket)


async def requeue_messages():
    while True:
        logger.debug('Refresh messages queue every 60 seconds')
        try:
            TMPMDICT = {}
            TMPMDICT.update(MESSAGESDICT);
            # Очистка буферов канала
            for channel in CHANNELS:
                channelqueue = CHANNELS[channel].mqueue
                for messageid in channelqueue:
                    if messageid in MESSAGESDICT:
                        if int(MESSAGESDICT[messageid]['mtime'])+TTL*60 < int(time.time()):
                            channelqueue.remove(messageid)
            for messageid in TMPMDICT:
                if int(TMPMDICT[messageid]['mtime'])+TTL*60 < int(time.time()):
                    GLOBALQUEUE.remove(messageid)
                    del MESSAGESDICT[messageid]
                    logger.debug('Drop expired message %s: '%(messageid))

            chanlist = set([ channel for channel in CHANNELS ])
            wschannels = set([ websocket.handler.channel_id for websocket in WS ])
            if len(chanlist.difference(wschannels)) > 0:
                logger.debug('Channels vs WSChannels diff: %s'%chanlist.difference(wschannels))
                logger.debug('Channels array: %s'%chanlist)
                logger.debug('WS Channels: %s'%wschannels)
                for deletechannel in chanlist.difference(wschannels):
                    logger.debug('Remove orphaned channel: %s' % deletechannel)
                    del CHANNELS[deletechannel]
            for login in LOGINS_IN_CHANNELS.keys():
                for deletechannel in set(LOGINS_IN_CHANNELS[login]).difference(wschannels):
                    logger.debug('Processing login: %s => %s'%(login,LOGINS_IN_CHANNELS[login]))
                    if deletechannel in LOGINS_IN_CHANNELS[login].keys():
                        logger.debug('Orphaned channel %s found for USER %s in channel list %s'%(deletechannel, login, LOGINS_IN_CHANNELS[login]))
                        del LOGINS_IN_CHANNELS[login][deletechannel]
            await asyncio.sleep(15)
        except Exception as ex:
            logger.error('Requeue Messages Exception: %s'%ex)
            raise


async def process_push_data(request, data):
    logger.debug('Process push data: %s' % data)
    try:
        dataid = '%s' % uuid.uuid4()
        jdata = json.loads(data)
        jdata.update({'version': dataid, 'tag': dataid, 'mtime': '%s'%int(time.time()) })
        GLOBALQUEUE.append(dataid)
        MESSAGESDICT.update({ dataid: jdata })
        await send_push_notification(jdata['recipient'], json.dumps(jdata))
        logger.error('MESSAGESDICT: %s. GLOBALQUEUE: %s' % (MESSAGESDICT,GLOBALQUEUE))
    except Exception as ex:
        logger.error('Pushdata error: %s' % ex)


async def handler(request):
    await request.post()
    data = await request.read()
    if request.path.startswith('/wpush'):
            logger.error('WWW Handler for path %s[%s]'%(request.path,request.method))
            if request.method == 'POST':
                result = await update_channel_keys(request,data)
                if result:
                    return web.Response(text=json.dumps([{'title':'Nobody knowns\n','body':'This is my body'}]), content_type="application/json")
                else:
                    path = request.path.replace('wpush','').replace('/','')
                    return web.Response(status=403)
            else:
                jsondata = json.dumps({'title':'Fire! Fire! Fire!','body':'This is my body','tag':'%s' % uuid.uuid4()})
                logger.debug('Path: %s => %s' %(request.path, jsondata))
                return web.Response(text=jsondata, content_type="application/json")
    elif request.path.startswith('/subscription'):
        logger.debug('Request Subscription')
        if request.method == 'GET':
            return web.Response(text=json.dumps({"public_key": VAPID_PUBLIC_KEY}),
                     headers={"Access-Control-Allow-Origin": "*"}, content_type="application/json")
        elif request.method == 'POST':
            return web.Response(status=201, content_type="application/json")
    elif request.path.startswith('/pushdata'):
        await process_push_data(request, data)
    elif request.path.startswith('/getdata'):
        return web.Response(content_type="application/json", text=json.dumps({'GLOBALQUEUE': list(GLOBALQUEUE), 'MESSAGESDICT': MESSAGESDICT}))
    elif request.path.startswith('/notifychannel'):
        result = await send_push_notification_channel(request.path.replace('/notifychannel','').replace('/',''), data.decode())
        if not result:
            return web.Response(text='Channel for notification not found')
    elif request.path.startswith('/notify'):
        result = await send_push_notification(request.path.replace('/notify','').replace('/',''), data.decode())
        if not result:
            return web.Response(text='Users for notification not found')
    return web.Response(text="OK")


async def http_server():
    server = web.Server(handler)
    runner = web.ServerRunner(server)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 8090)
    await site.start()
    await asyncio.sleep(100*3600)

def main():
    start_server = websockets.serve(pushserver, '127.0.0.1', 6789)
    asyncio.get_event_loop().create_task(requeue_messages())
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_until_complete(http_server())
    asyncio.get_event_loop().run_forever()

if __name__ == '__main__':
	main()
