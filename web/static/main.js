'use strict';

//const pushButton = document.querySelector('.js-push-btn');

let isSubscribed = false;
let swRegistration = null;
var wait = ms => new Promise((r, j)=>setTimeout(r, ms));

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

function subscribeUser() {
	const applicationServerPublicKey = localStorage.getItem('applicationServerPublicKey');
	const applicationServerKey = urlB64ToUint8Array(applicationServerPublicKey);
	swRegistration.pushManager.subscribe({
			userVisibleOnly: true,
			applicationServerKey: applicationServerKey
		})
		.then(function(subscription) {
			console.log('User is subscribed.', JSON.stringify(subscription));
			localStorage.setItem('sub_token',JSON.stringify(subscription));
			isSubscribed = true;
			
			fetch(subscription.endpoint, {
				method: 'POST',
				cache: 'no-cache',
				body: JSON.stringify(subscription)
			})
			.then(function(response) {
				console.log('Push keys Update Response: ' + JSON.stringify(response));
			})
		})
		.catch(function(err) {
			console.log('Failed to subscribe the user: ', err);
		});
}

function unsubscribeUser() {
	swRegistration.pushManager.getSubscription()
		.then(function(subscription) {
			if (subscription) {
				return subscription.unsubscribe();
			}
		})
		.catch(function(error) {
			console.log('Error unsubscribing', error);
		})
		.then(function() {
			console.log('User is unsubscribed.');
			isSubscribed = false;
		});
}

function initializeUI() {
	// Set the initial subscription value
	swRegistration.pushManager.getSubscription()
		.then(function(subscription) {
			isSubscribed = !(subscription === null);
			if (isSubscribed) {
				console.log('User IS subscribed. Unsubscribing.');
				subscription.unsubscribe();
			} else {
				console.log('User is NOT subscribed. Subscribing.');
				subscribeUser();
			}
		});
	(async () => {
	await wait(2000);
	console.warn('Wait for operation is ok'); 
        swRegistration.pushManager.getSubscription()
                .then(function(subscription) {
                        isSubscribed = !(subscription === null);
                        if (!isSubscribed) {
                                console.log('ReSubscribe user');
                                subscribeUser();
                        }
                })
	})()

}

console.log(navigator);
console.log(window);

if ('serviceWorker' in navigator && 'PushManager' in window) {
	console.log('Service Worker and Push is supported');

	navigator.serviceWorker.register("/sw.js")
		.then(function(swReg) {
			console.log('Service Worker is registered', swReg);

			swRegistration = swReg;
			initializeUI();
		})
		.catch(function(error) {
			console.error('Service Worker Error', error);
		});
} else {
	console.warn('Push messaging application ServerPublicKey is not supported');
}

$(document).ready(function(){
	$.ajax({
		type:"GET",
		url:'/subscription/',
		success:function(response){
			console.log("response",response);
			localStorage.setItem('applicationServerPublicKey',response.public_key);
		}
	})
});
