'use strict';

/* eslint-disable max-len */

/* eslint-enable max-len */

function urlB64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding)
    .replace(/\-/g, '+')
    .replace(/_/g, '/');

  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);

  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function getEndpoint() {
  return self.registration.pushManager.getSubscription()
  .then(function(subscription) {
    if (subscription) {
      return subscription.endpoint;
    }
    throw new Error('User not subscribed');
  });
}

self.popNotification = function(title, body, tag, icon, url) {
  console.debug('Popup data:', tag, body, title, icon, url);

  self.registration.showNotification(title, {
      body: body,
      tag: tag,
      icon: icon
    });

  self.onnotificationclick = function(event){
      console.debug('On notification click: ', event.notification.tag);
      event.notification.close();
      event.waitUntil(
        clients.openWindow(url)
      );
  };
}

var wait = ms => new Promise((r, j)=>setTimeout(r, ms));

self.addEventListener('push', function(event) { 
  console.log('[Push]', event);
  if (event.data) {
    var data = event.data.json();
    var evtag = data.tag || 'notag';
    self.popNotification(data.title || 'Default title', data.body || 'Body is not present', evtag, data.icon || '/static/images/default.svg', data.url || '/getevent?tag='+evtag);
  }
  else {
    event.waitUntil(
      getEndpoint().then(function(endpoint) {
        return fetch(endpoint);
      }).then(function(response) {
          return response.json();
      }).then(function(payload) {
          console.debug('Payload',JSON.stringify(payload), payload.length);
          var evtag = payload.tag || 'notag';
          self.popNotification(payload.title || 'Default title', payload.body || 'Body is not present', payload.tag || 'notag', payload.icon || '/static/images/default.svg', payload.url || '/getevent?tag='+evtag);
      })
    );
  }
});

self.addEventListener('pushsubscriptionchange', function(event) {
  console.log('[Service Worker]: \'pushsubscriptionchange\' event fired.');
  const applicationServerPublicKey = localStorage.getItem('applicationServerPublicKey');
  const applicationServerKey = urlB64ToUint8Array(applicationServerPublicKey);
  event.waitUntil(
    self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: applicationServerKey
    })
    .then(function(newSubscription) {
      // TODO: Send to application server
      console.log('[Service Worker] New subscription: ', newSubscription);
    })
  );
});
