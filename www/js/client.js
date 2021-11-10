/*
 ██████ ██      ██ ███████ ███    ██ ████████ 
██      ██      ██ ██      ████   ██    ██    
██      ██      ██ █████   ██ ██  ██    ██    
██      ██      ██ ██      ██  ██ ██    ██    
 ██████ ███████ ██ ███████ ██   ████    ██   

MiroTalk Browser Client
Copyright (C) 2021 Miroslav Pejic <miroslav.pejic.85@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

'use strict';
//const { response } = require("express");

 // https://www.w3schools.com/js/js_strict.asp

const signalingServerPort = 7500; // must be the same to server.js PORT
const signalingServer = getSignalingServer();
const roomId = getRoomId();
const peerInfo = getPeerInfo();

const peerLoockupUrl = 'https://extreme-ip-lookup.com/json/';
const avatarApiUrl = 'https://eu.ui-avatars.com/api';

//images 
const welcomeImg = '../css/Cognimeet_Assets/Join/Group 2307.png';
const shareUrlImg = '../css/Cognimeet_Assets/Join/Group 2307.png';
const leaveRoomImg = '../css/Cognimeet_Assets/Livemeeting/leave_end.png';
const confirmImg = '../css/Cognimeet_Assets/Join/Group 2307.png';
const fileSharingImg = '../css/Cognimeet_Assets/Join/Group 2307.png';

// nice free icon: https://www.iconfinder.com
const roomLockedImg = '../images/locked.png';
const camOffImg = '../css/Cognimeet_Assets/Livemeeting/video.png';
const audioOffImg = '../css/Cognimeet_Assets/Livemeeting/mic.png';
const deleteImg = '../images/delete.png';
const kickedOutImg = '../images/leave-room.png';
const aboutImg = '../css/Cognimeet_Assets/Join/Group 2307.png';

const notifyBySound = true; // turn on - off sound notifications
const fileSharingInput = '*'; // allow all file extensions

//backbg
const backbg = "../css/Cognimeet_Assets/Enter/Group 2305.png"

const isWebRTCSupported = DetectRTC.isWebRTCSupported;
const isMobileDevice = DetectRTC.isMobileDevice;
const myBrowserName = DetectRTC.browser.name;

// video cam - screen max frame rate
let videoMaxFrameRate = 30;
let screenMaxFrameRate = 30;
let leftChatAvatar;
let rightChatAvatar;
let callStartTime;
let callElapsedTime;
let recStartTime;
let recElapsedTime;
let mirotalkTheme = 'neon'; // neon - dark - forest - ghost ...
let swalBackground = '#16171b'; // black - #16171b - transparent ...
let peerGeo;
let peerConnection;
let myPeerName;
let useAudio = true;
let useVideo = true;
let camera = 'user';
let roomLocked = false;
let myVideoChange = false;
let myHandStatus = false;
let myVideoStatus = true;
let myAudioStatus = true;
let isScreenStreaming = false;
let isChatRoomVisible = false;
let isChatEmojiVisible = false;
let isButtonsVisible = false;
let isMySettingsVisible = false;
let isVideoOnFullScreen = false;
let isDocumentOnFullScreen = false;
let isWhiteboardFs = false;
let signalingSocket; // socket.io connection to our webserver
let localMediaStream; // my microphone / webcam
let remoteMediaStream; // peers microphone / webcam
let remoteMediaControls = false; // enable - disable peers video player controls (default false)
let peerConnections = {}; // keep track of our peer connections, indexed by peer_id == socket.io id
let chatDataChannels = {}; // keep track of our peer chat data channels
let fileDataChannels = {}; // keep track of our peer file sharing data channels
let peerMediaElements = {}; // keep track of our peer <video> tags, indexed by peer_id
let chatMessages = []; // collect chat messages to save it later if want
let backupIceServers = [{ urls: 'stun:stun.l.google.com:19302' }]; // backup iceServers

let chatInputEmoji = {
    '<3': '\u2764\uFE0F',
    '</3': '\uD83D\uDC94',
    ':D': '\uD83D\uDE00',
    ':)': '\uD83D\uDE03',
    ';)': '\uD83D\uDE09',
    ':(': '\uD83D\uDE12',
    ':p': '\uD83D\uDE1B',
    ';p': '\uD83D\uDE1C',
    ":'(": '\uD83D\uDE22',
    ':+1:': '\uD83D\uDC4D',
}; // https://github.com/wooorm/gemoji/blob/main/support.md

let bannerImg;
let countTime;
// init audio-video
let initAudioBtn;
let initVideoBtn;

// options container and also bg-image (not present in html)
let optionsContainer;
let imgOptions = document.querySelectorAll('li');
let img = document.getElementById('bg-image');
let isImgDivOpen = false;

// left buttons
let leftButtons;
let shareRoomBtn;
let audioBtn;
let videoBtn;
let swapCameraBtn;
let screenShareBtn;
let recordStreamBtn;
//let fullScreenBtn;
let chatRoomBtn;
let myHandBtn;
//let whiteboardBtn;
let ReportBtn;
//let setBgImgBtn;
let fileShareBtn;
let mySettingsBtn;
let aboutBtn;
let leaveRoomBtn;

// chat room elements
let msgerDraggable;
let msgerHeader;
let msgerTheme;
let msgerCPBtn;
let msgerClean;
let msgerSaveBtn;
let msgerClose;
let msgerChat;
let msgerEmojiBtn;
let msgerInput;
let msgerSendBtn;

// chat room connected peers
let msgerCP;
let msgerCPHeader;
let msgerCPCloseBtn;
let msgerCPList;

// chat room emoji picker
let msgerEmojiPicker;
let msgerEmojiHeader;
let msgerCloseEmojiBtn;
let emojiPicker;

// my settings
let mySettings;
let mySettingsHeader;
let tabDevicesBtn;
let tabBandwidthBtn;
let tabRoomBtn;
let tabThemeBtn;
let mySettingsCloseBtn;
let myPeerNameSet;
let myPeerNameSetBtn;
let audioInputSelect;
let audioOutputSelect;
let videoSelect;
let videoQualitySelect;
let videoFpsSelect;
let screenFpsSelect;
let themeSelect;
let selectors;

// my video element
let myVideo;

// let myVideoAvatarImage;
// name && hand video audio status
let myVideoParagraph;
let myHandStatusIcon;
let myVideoStatusIcon;
let myAudioStatusIcon;

// record Media Stream
let mediaRecorder;
let recordedBlobs;
let isStreamRecording = false;

// whiteboard init
let whiteboardCont;
let whiteboardHeader;
let whiteboardColorPicker;
let whiteboardCloseBtn;
let whiteboardFsBtn;
let whiteboardCleanBtn;
let whiteboardSaveBtn;
let whiteboardEraserBtn;
let isWhiteboardVisible = false;
//let canvas;
//let ctx;

// whiteboard settings
let isDrawing = 0;
let x = 0;
let y = 0;
let color = '#000000';
let drawsize = 3;

// room actions btns
let muteEveryoneBtn;
let hideEveryoneBtn;
let lockUnlockRoomBtn;

// file transfer settings
let fileToSend;
let fileReader;
let receiveBuffer = [];
let receivedSize = 0;
let incomingFileInfo;
let incomingFileData;
let sendFileDiv;
let sendFileInfo;
let sendProgress;
let sendAbortBtn;
let sendInProgress = false;

// MTU 1kb to prevent drop.
const chunkSize = 1024;

/**
 * Load all Html elements by Id
 */
function getHtmlElementsById() {
    //bannerImg = getId('tableBanner');
    //console.log(bannerImg);
    //console.log('from gethtml elements func')
    countTime = getId('countTime');
    // my video
    myVideo = getId('myVideo');
    // myVideoAvatarImage = getId('myVideoAvatarImage');
    optionsContainer = getId('options');
    // left buttons
    leftButtons = getId('leftButtons');
    shareRoomBtn = getId('shareRoomBtn');
    audioBtn = getId('audioBtn');
    videoBtn = getId('videoBtn');
    swapCameraBtn = getId('swapCameraBtn');
    screenShareBtn = getId('screenShareBtn');
    recordStreamBtn = getId('recordStreamBtn');
    //fullScreenBtn = getId('fullScreenBtn');
    chatRoomBtn = getId('chatRoomBtn');
    //whiteboardBtn = getId('whiteboardBtn'); 
    ReportBtn = getId('start');
    //setBgImgBtn = getId('setBgImgBtn');
    fileShareBtn = getId('fileShareBtn');
    myHandBtn = getId('myHandBtn');
    mySettingsBtn = getId('mySettingsBtn');
    aboutBtn = getId('aboutBtn');
    leaveRoomBtn = getId('leaveRoomBtn');

    // chat Room elements
    msgerDraggable = getId('msgerDraggable');
    msgerHeader = getId('msgerHeader');
    msgerTheme = getId('msgerTheme');
    msgerCPBtn = getId('msgerCPBtn');
    msgerClean = getId('msgerClean');
    msgerSaveBtn = getId('msgerSaveBtn');
    msgerClose = getId('msgerClose');
    msgerChat = getId('msgerChat');
    msgerEmojiBtn = getId('msgerEmojiBtn');
    msgerInput = getId('msgerInput');
    msgerSendBtn = getId('msgerSendBtn');

    // chat room connected peers
    msgerCP = getId('msgerCP');
    msgerCPHeader = getId('msgerCPHeader');
    msgerCPCloseBtn = getId('msgerCPCloseBtn');
    msgerCPList = getId('msgerCPList');

    // chat room emoji picker
    msgerEmojiPicker = getId('msgerEmojiPicker');
    msgerEmojiHeader = getId('msgerEmojiHeader');
    msgerCloseEmojiBtn = getId('msgerCloseEmojiBtn');
    emojiPicker = getSl('emoji-picker');

    // my settings
    mySettings = getId('mySettings');
    mySettingsHeader = getId('mySettingsHeader');
    tabDevicesBtn = getId('tabDevicesBtn');
    tabBandwidthBtn = getId('tabBandwidthBtn');
    tabRoomBtn = getId('tabRoomBtn');
    tabThemeBtn = getId('tabThemeBtn');
    mySettingsCloseBtn = getId('mySettingsCloseBtn');
    myPeerNameSet = getId('myPeerNameSet');
    myPeerNameSetBtn = getId('myPeerNameSetBtn');
    audioInputSelect = getId('audioSource');
    audioOutputSelect = getId('audioOutput');
    videoSelect = getId('videoSource');
    videoQualitySelect = getId('videoQuality');
    videoFpsSelect = getId('videoFps');
    screenFpsSelect = getId('screenFps');
    themeSelect = getId('mirotalkTheme');

    // my conference name, hand, video - audio status
    myVideoParagraph = getId('myVideoParagraph');
    myHandStatusIcon = getId('myHandStatusIcon');
    myVideoStatusIcon = getId('myVideoStatusIcon');
    myAudioStatusIcon = getId('myAudioStatusIcon');

    // my whiteboard
    whiteboardCont = getSl('.whiteboard-cont');
    whiteboardHeader = getSl('.colors-cont');
    whiteboardCloseBtn = getId('whiteboardCloseBtn');
    whiteboardFsBtn = getId('whiteboardFsBtn');
    whiteboardColorPicker = getId('whiteboardColorPicker');
    whiteboardSaveBtn = getId('whiteboardSaveBtn');
    whiteboardEraserBtn = getId('whiteboardEraserBtn');
    whiteboardCleanBtn = getId('whiteboardCleanBtn');
    //canvas = getId('whiteboard');
    //ctx = canvas.getContext('2d');

    // room actions buttons
    muteEveryoneBtn = getId('muteEveryoneBtn');
    hideEveryoneBtn = getId('hideEveryoneBtn');
    lockUnlockRoomBtn = getId('lockUnlockRoomBtn');

    // file send progress
    sendFileDiv = getId('sendFileDiv');
    sendFileInfo = getId('sendFileInfo');
    sendProgress = getId('sendProgress');
    sendAbortBtn = getId('sendAbortBtn');
}

/**
 * Using tippy aka very nice tooltip!
 * https://atomiks.github.io/tippyjs/
 */
function setButtonsTitle() {
    // not need for mobile
    if (isMobileDevice) return;

    // left buttons
    tippy(shareRoomBtn, {
        content: 'Invite people to join',
        placement: 'right-start',
    });
    tippy(audioBtn, {
        content: 'Click to audio OFF',
        placement: 'right-start',
    });
    tippy(videoBtn, {
        content: 'Click to video OFF',
        placement: 'right-start',
    });
    tippy(screenShareBtn, {
        content: 'START screen sharing',
        placement: 'right-start',
    });
    tippy(recordStreamBtn, {
        content: 'START recording',
        placement: 'right-start',
    });
    /*tippy(fullScreenBtn, {
        content: 'VIEW full screen',
        placement: 'right-start',
    });*/
    tippy(chatRoomBtn, {
        content: 'OPEN the chat',
        placement: 'right-start',
    });
    tippy(myHandBtn, {
        content: 'RAISE your hand',
        placement: 'right-start',
    });
    /*
    tippy(whiteboardBtn, {
        content: 'OPEN the whiteboard',
        placement: 'right-start',
    });
    */
    tippy(ReportBtn, {
        content: 'Generate the Report!',
        placement: 'right-start',
    });
    /* tippy(setBgImgBtn, {
        content: 'Set Background Image',
        placement: 'right-start',
    });*/
    tippy(fileShareBtn, {
        content: 'SHARE the file',
        placement: 'right-start',
    });
    tippy(mySettingsBtn, {
        content: 'Show settings',
        placement: 'right-start',
    });
    tippy(aboutBtn, {
        content: 'Show about',
        placement: 'right-start',
    });
    tippy(leaveRoomBtn, {
        content: 'Leave this room',
        placement: 'right-start',
    });

    // chat room buttons
    tippy(msgerTheme, {
        content: 'Ghost theme',
    });
    tippy(msgerCPBtn, {
        content: 'Private messages',
    });
    tippy(msgerClean, {
        content: 'Clean messages',
    });
    tippy(msgerSaveBtn, {
        content: 'Save messages',
    });
    tippy(msgerClose, {
        content: 'Close the chat',
    });
    tippy(msgerEmojiBtn, {
        content: 'Emoji',
    });
    tippy(msgerSendBtn, {
        content: 'Send',
    });

    // emoji picker
    tippy(msgerCloseEmojiBtn, {
        content: 'Close emoji',
    });

    // settings
    tippy(mySettingsCloseBtn, {
        content: 'Close settings',
    });
    tippy(myPeerNameSetBtn, {
        content: 'Change name',
    });

    // whiteboard btns
    tippy(whiteboardCloseBtn, {
        content: 'CLOSE the whiteboard',
        placement: 'bottom',
    });
    tippy(whiteboardFsBtn, {
        content: 'VIEW full screen',
        placement: 'bottom',
    });
    tippy(whiteboardColorPicker, {
        content: 'COLOR picker',
        placement: 'bottom',
    });
    tippy(whiteboardSaveBtn, {
        content: 'SAVE the board',
        placement: 'bottom',
    });
    tippy(whiteboardEraserBtn, {
        content: 'ERASE the board',
        placement: 'bottom',
    });
    tippy(whiteboardCleanBtn, {
        content: 'CLEAN the board',
        placement: 'bottom',
    });

    // room actions btn
    tippy(muteEveryoneBtn, {
        content: 'MUTE everyone except yourself',
        placement: 'top',
    });
    tippy(hideEveryoneBtn, {
        content: 'HIDE everyone except yourself',
        placement: 'top',
    });

    // Suspend File transfer btn
    tippy(sendAbortBtn, {
        content: 'ABORT file transfer',
        placement: 'right-start',
    });
}

/**
 * Get peer info using DetecRTC
 * https://github.com/muaz-khan/DetectRTC
 * @return Obj peer info
 */
function getPeerInfo() {
    return {
        detectRTCversion: DetectRTC.version,
        isWebRTCSupported: DetectRTC.isWebRTCSupported,
        isMobileDevice: DetectRTC.isMobileDevice,
        osName: DetectRTC.osName,
        osVersion: DetectRTC.osVersion,
        browserName: DetectRTC.browser.name,
        browserVersion: DetectRTC.browser.version,
    };
}

/**
 * Get approximative peer geolocation
 * @return json
 */
function getPeerGeoLocation() {
    fetch(peerLoockupUrl)
        .then((res) => res.json())
        .then((outJson) => {
            peerGeo = outJson;
        })
        .catch((err) => console.error(err));
}

/**
 * Get Signaling server URL
 * @return Signaling server URL
 */
function getSignalingServer() {
    return (
        'http' +
        (location.hostname == 'localhost' ? '' : 's') +
        '://' +
        location.hostname +
        (location.hostname == 'localhost' ? ':' + signalingServerPort : '')
    );
}

/**
 * Generate random Room id
 * @return Room Id
 */
function getRoomId() {
    // skip /join/
    let roomId = location.pathname.substring(6);
    // if not specified room id, create one random
    if (roomId == '') {
        roomId = makeId(12);
        const newurl = signalingServer + '/join/' + roomId;
        window.history.pushState({ url: newurl }, roomId, newurl);
    }
    return roomId;
}

/**
 * Generate random Id
 * @param {*} length
 * @returns random id
 */
function makeId(length) {
    let result = '';
    let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

/**
 * Check if there is peer connections
 * @return true, false otherwise
 */
function thereIsPeerConnections() {
    if (Object.keys(peerConnections).length === 0) return false;
    return true;
}

/**
 * On body load Get started
 */
function initClientPeer() {
    //setTheme(mirotalkTheme);
    //var dbgdata =  localStorage.getItem('defaultbg');
    //trying to change the background-image of body by localdb
    var defaultbgname =  localStorage.getItem('defaultbgname');
    //console.log(defaultbgname)
    let bannerImg = document.querySelectorAll('#bodytableBanner');
    var bg_replacement = "background-image: url("+"'"+defaultbgname+"'"+');'
    //console.log(bg_replacement)
    bannerImg[0].style = bg_replacement;
    //bannerImg[0].height = 738;
    //console.log(bannerImg[0])
    //console.log(localStorage.getItem('defaultbgname'))
    /*
    document.getElementById('bodyid').style.backgroundImage = 'url('+'"'+dbgdata+'"'+');';//will load  with default background
    document.getElementById('bodyid').style.backgroundSize = "cover"
    console.log(document.getElementById('bodyid').style.backgroundImage)
    */
    
    // chnage the src of img element with default bg 
    //let bannerImg = document.querySelectorAll('#tableBanner');
    //bannerImg[0].src = dbgdata;


    //document.body.style.backgroundSize = "cover"
   /*
    let bodybgimg = document.querySelectorAll('#bodyid')
    console.log(bodybgimg)
    console.log(bodybgimg[0].style.backgroundImage)
    bodybgimg[0].style.backgroundImage = dbgdata;
    document.body.style.backgroundSize = "cover"
    */

    //var dataImage = localStorage.getItem('imgData');
    //console.log(dbgdata);
    //document.body.style.backgroundImage = `url(localStorage.getItem('defaultbg');)`; 
    //document.body.style.backgroundImage = `url('../uploads/loaders_dribble_original5.gif')`; 
    //document.body.style.backgroundImage = `url('../images/defaultbg/defaultbg.jpg')`; //will load  with default background
    //document.body.style.backgroundImage = dbgdata;
    /*
    bannerImg = document.getElementById('bodyid');
    bannerImg.style.backgroundImage = "data:image/png;base64," + dbgdata;
    document.body.style.backgroundSize = "cover"
    */

    if (!isWebRTCSupported) {
        userLog('error', 'This browser seems not supported WebRTC!');
        return;
    }

    console.log('Connecting to signaling server');
    signalingSocket = io(signalingServer);
    
    signalingSocket.on('connect', handleConnect);
    signalingSocket.on('roomIsLocked', handleRoomLocked);
    signalingSocket.on('roomStatus', handleRoomStatus);
    signalingSocket.on('addPeer', handleAddPeer);
    signalingSocket.on('sessionDescription', handleSessionDescription);
    signalingSocket.on('iceCandidate', handleIceCandidate);
    signalingSocket.on('peerName', handlePeerName);
    signalingSocket.on('peerStatus', handlePeerStatus);
    signalingSocket.on('peerAction', handlePeerAction);
    signalingSocket.on('wb', handleWhiteboard);
    signalingSocket.on('kickOut', handleKickedOut);
    signalingSocket.on('fileInfo', handleFileInfo);
    signalingSocket.on('fileAbort', handleFileAbort);
    signalingSocket.on('disconnect', handleDisconnect);
    signalingSocket.on('removePeer', handleRemovePeer);
} // end [initClientPeer]



/**
 * Connected to Signaling Server. Once the user has given us access to their
 * microphone/cam, join the channel and start peering up
 */
function handleConnect() {
    console.log('Connected to signaling server');
    if (localMediaStream) joinToChannel();
    else
        setupLocalMedia(() => {
            whoAreYou();
        });
}

/**
 * set your name for the conference
 */
function whoAreYou() {
    // playSound('newMessage');

    Swal.fire({
        allowOutsideClick: false,
        allowEscapeKey: false,
        background: swalBackground,
        position: 'center',
        imageAlt: 'Cognimeet-name',
        imageUrl: welcomeImg,
        title: 'Enter your name',
        input: 'text',
        html: `<br>
        <button id="initAudioBtn" class="fas fa-microphone" onclick="handleAudio(event, true)"></button>
        <button id="initVideoBtn" class="fas fa-video" onclick="handleVideo(event, true)"></button>`,
        confirmButtonText: `Join meeting`,
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
        inputValidator: (value) => {
            if (!value) return 'Please enter your name';

            myPeerName = value;
            myVideoParagraph.innerHTML = myPeerName + ' (me)';
            // setPeerAvatarImgName('myVideoAvatarImage', myPeerName);
            setPeerChatAvatarImgName('right', myPeerName);
            joinToChannel();
        },
    }).then(() => {
        welcomeUser();
    });

    if (isMobileDevice) return;

    initAudioBtn = getId('initAudioBtn');
    initVideoBtn = getId('initVideoBtn');

    tippy(initAudioBtn, {
        content: 'Click to audio OFF',
        placement: 'top',
    });

    tippy(initVideoBtn, {
        content: 'Click to video OFF',
        placement: 'top',
    });
}

/**
 * join to chennel and send some peer info
 */
function joinToChannel() {
    console.log('join to channel', roomId);
    signalingSocket.emit('join', {
        channel: roomId,
        peer_info: peerInfo,
        peer_geo: peerGeo,
        peer_name: myPeerName,
        peer_video: myVideoStatus,
        peer_audio: myAudioStatus,
        peer_hand: myHandStatus,
    });
}

 

/**
 * welcome message
 */
function welcomeUser() {
    const myRoomUrl = window.location.href;
    // playSound('newMessage');
    Swal.fire({
        background: swalBackground,
        position: 'center',
        title: '<strong>Welcome ' + myPeerName + '</strong>',
        imageAlt: 'mirotalk-welcome',
        imageUrl: welcomeImg,
        html:
            `
        <br/> 
        <p style="color:white;">Share this meeting invite others to join.</p>
        <p style="color:rgb(8, 189, 89);">` +
            myRoomUrl +
            `</p>`,
        showDenyButton: true,
        showCancelButton: true,
        confirmButtonText: `Copy meeting URL`,
        denyButtonText: `Email invite`,
        cancelButtonText: `Close`,
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
    }).then((result) => {
        if (result.isConfirmed) {
            copyRoomURL();
        } else if (result.isDenied) {
            let message = {
                email: '',
                subject: 'Please join our MiroTalk Video Chat Meeting',
                body: 'Click to join: ' + myRoomUrl,
            };
            shareRoomByEmail(message);
        }
    });
}

/**
 * When we join a group, our signaling server will send out 'addPeer' events to each pair of users in the group (creating a fully-connected graph of users,
 * ie if there are 6 people in the channel you will connect directly to the other 5, so there will be a total of 15 connections in the network).
 *
 * @param {*} config
 */
function handleAddPeer(config) {
    // console.log("addPeer", JSON.stringify(config));

    let peer_id = config.peer_id;
    let peers = config.peers;
    let should_create_offer = config.should_create_offer;
    let iceServers = config.iceServers;

    if (peer_id in peerConnections) {
        // This could happen if the user joins multiple channels where the other peer is also in.
        console.log('Already connected to peer', peer_id);
        return;
    }

    if (!iceServers) iceServers = backupIceServers;
    console.log('iceServers', iceServers[0]);

    // https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection
    peerConnection = new RTCPeerConnection({ iceServers: iceServers });
    peerConnections[peer_id] = peerConnection;

    msgerAddPeers(peers);
    handleOnIceCandidate(peer_id);
    handleOnTrack(peer_id, peers);
    handleAddTracks(peer_id);
    handleRTCDataChannels(peer_id);

    if (should_create_offer) handleRtcOffer(peer_id);

    playSound('addPeer');
}

/**
 * https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/onicecandidate
 *
 * @param {*} peer_id
 */
function handleOnIceCandidate(peer_id) {
    peerConnections[peer_id].onicecandidate = (event) => {
        if (!event.candidate) return;
        signalingSocket.emit('relayICE', {
            peer_id: peer_id,
            ice_candidate: {
                sdpMLineIndex: event.candidate.sdpMLineIndex,
                candidate: event.candidate.candidate,
            },
        });
    };
}

/**
 * https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/ontrack
 *
 * @param {*} peer_id
 * @param {*} peers
 */
function handleOnTrack(peer_id, peers) {
    let ontrackCount = 0;
    peerConnections[peer_id].ontrack = (event) => {
        console.log('handleOnTrack', event);
        ontrackCount++;
        // 2 means audio + video
        if (ontrackCount === 2) loadRemoteMediaStream(event.streams[0], peers, peer_id);
        //if (ontrackCount === 2) save_recording_on_load(event.streams[0],peer_id);
    };
}

/**
 * https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/addTrack
 *
 * @param {*} peer_id
 */
function handleAddTracks(peer_id) {
    localMediaStream.getTracks().forEach((track) => {
        peerConnections[peer_id].addTrack(track, localMediaStream);
    });
}

/**
 * Secure RTC Data Channel
 * https://developer.mozilla.org/en-US/docs/Web/API/RTCDataChannel
 * https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/createDataChannel
 * https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/ondatachannel
 * https://developer.mozilla.org/en-US/docs/Web/API/RTCDataChannel/onmessage
 *
 * @param {*} peer_id
 */
function handleRTCDataChannels(peer_id) {
    peerConnections[peer_id].ondatachannel = (event) => {
        console.log('handleRTCDataChannels ' + peer_id, event);
        event.channel.onmessage = (msg) => {
            switch (event.channel.label) {
                case 'mirotalk_chat_channel':
                    try {
                        let dataMessage = JSON.parse(msg.data);
                        handleDataChannelChat(dataMessage);
                    } catch (err) {
                        console.error('handleDataChannelChat', err);
                    }
                    break;
                case 'mirotalk_file_sharing_channel':
                    try {
                        let dataFile = msg.data;
                        handleDataChannelFileSharing(dataFile);
                    } catch (err) {
                        console.error('handleDataChannelFS', err);
                    }
                    break;
            }
        };
    };
    createChatDataChannel(peer_id);
    createFileSharingDataChannel(peer_id);
}

/**
 * Only one side of the peer connection should create the offer, the signaling server picks one to be the offerer.
 * The other user will get a 'sessionDescription' event and will create an offer, then send back an answer 'sessionDescription' to us
 *
 * @param {*} peer_id
 */
function handleRtcOffer(peer_id) {
    console.log('Creating RTC offer to', peer_id);
    // https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/createOffer
    peerConnections[peer_id]
        .createOffer()
        .then((local_description) => {
            console.log('Local offer description is', local_description);
            // https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/setLocalDescription
            peerConnections[peer_id]
                .setLocalDescription(local_description)
                .then(() => {
                    signalingSocket.emit('relaySDP', {
                        peer_id: peer_id,
                        session_description: local_description,
                    });
                    console.log('Offer setLocalDescription done!');
                })
                .catch((err) => {
                    console.error('[Error] offer setLocalDescription', err);
                    userLog('error', 'Offer setLocalDescription failed ' + err);
                });
        })
        .catch((err) => {
            console.error('[Error] sending offer', err);
        });
}

/**
 * Peers exchange session descriptions which contains information about their audio / video settings and that sort of stuff. First
 * the 'offerer' sends a description to the 'answerer' (with type "offer"), then the answerer sends one back (with type "answer").
 *
 * @param {*} config
 */
function handleSessionDescription(config) {
    console.log('Remote Session Description', config);

    let peer_id = config.peer_id;
    let remote_description = config.session_description;

    // https://developer.mozilla.org/en-US/docs/Web/API/RTCSessionDescription
    let description = new RTCSessionDescription(remote_description);

    // https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/setRemoteDescription
    peerConnections[peer_id]
        .setRemoteDescription(description)
        .then(() => {
            console.log('setRemoteDescription done!');
            if (remote_description.type == 'offer') {
                console.log('Creating answer');
                // https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/createAnswer
                peerConnections[peer_id]
                    .createAnswer()
                    .then((local_description) => {
                        console.log('Answer description is: ', local_description);
                        // https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/setLocalDescription
                        peerConnections[peer_id]
                            .setLocalDescription(local_description)
                            .then(() => {
                                signalingSocket.emit('relaySDP', {
                                    peer_id: peer_id,
                                    session_description: local_description,
                                });
                                console.log('Answer setLocalDescription done!');
                            })
                            .catch((err) => {
                                console.error('[Error] answer setLocalDescription', err);
                                userLog('error', 'Answer setLocalDescription failed ' + err);
                            });
                    })
                    .catch((err) => {
                        console.error('[Error] creating answer', err);
                    });
            } // end [if type offer]
        })
        .catch((err) => {
            console.error('[Error] setRemoteDescription', err);
        });
}

/**
 * The offerer will send a number of ICE Candidate blobs to the answerer so they
 * can begin trying to find the best path to one another on the net.
 *
 * @param {*} config
 */
function handleIceCandidate(config) {
    let peer_id = config.peer_id;
    let ice_candidate = config.ice_candidate;
    // https://developer.mozilla.org/en-US/docs/Web/API/RTCIceCandidate
    peerConnections[peer_id].addIceCandidate(new RTCIceCandidate(ice_candidate)).catch((err) => {
        console.error('[Error] addIceCandidate', err);
        userLog('error', 'addIceCandidate failed ' + err);
    });
}

/**
 * Disconnected from Signaling Server. Tear down all of our peer connections
 * and remove all the media divs when we disconnect from signaling server
 */
function handleDisconnect() {
    console.log('Disconnected from signaling server');
    for (let peer_id in peerMediaElements) {
        document.body.removeChild(peerMediaElements[peer_id].parentNode);
        resizeVideos();
    }
    for (let peer_id in peerConnections) {
        peerConnections[peer_id].close();
        msgerRemovePeer(peer_id);
    }
    chatDataChannels = {};
    fileDataChannels = {};
    peerConnections = {};
    peerMediaElements = {};
}

/**
 * When a user leaves a channel (or is disconnected from the signaling server) everyone will recieve a 'removePeer' message
 * telling them to trash the media channels they have open for those that peer. If it was this client that left a channel,
 * they'll also receive the removePeers. If this client was disconnected, they wont receive removePeers, but rather the
 * signaling_socket.on('disconnect') code will kick in and tear down all the peer sessions.
 *
 * @param {*} config
 */
function handleRemovePeer(config) {
    console.log('Signaling server said to remove peer:', config);

    let peer_id = config.peer_id;

    if (peer_id in peerMediaElements) {
        document.body.removeChild(peerMediaElements[peer_id].parentNode);
        resizeVideos();
    }
    if (peer_id in peerConnections) peerConnections[peer_id].close();

    msgerRemovePeer(peer_id);

    delete chatDataChannels[peer_id];
    delete fileDataChannels[peer_id];
    delete peerConnections[peer_id];
    delete peerMediaElements[peer_id];

    playSound('removePeer');
}

/**
 * Set mirotalk theme neon | dark | forest | sky | ghost | ...
 * @param {*} theme
 */
function setTheme(theme) {
    if (!theme) return;
    mirotalkTheme = theme;
    switch (mirotalkTheme) {
        case 'neon':
            // neon theme
            swalBackground = 'rgba(0, 0, 0, 0.7)';
            //document.body.style.backgroundImage = "url('/Cognimeet_Assets/Loading/Group 2306.png')";
           // document.documentElement.style.setProperty('--body-bg-image','../css/Cognimeet_Assets/Loading/Group 2306.png'); 
            //document.documentElement.style.setProperty('--body-bg', 'transparent');
            document.documentElement.style.setProperty('--msger-bg', 'black');
            document.documentElement.style.setProperty('--msger-private-bg', 'black');
            document.documentElement.style.setProperty('--left-msg-bg', '#da05f3');
            document.documentElement.style.setProperty('--private-msg-bg', '#f77070');
            document.documentElement.style.setProperty('--right-msg-bg', '#579ffb');
            document.documentElement.style.setProperty('--wb-bg', '#000000');
            document.documentElement.style.setProperty('--wb-hbg', '#000000');
            document.documentElement.style.setProperty('--btn-bg', 'black');
            document.documentElement.style.setProperty('--btn-color', 'white');
            document.documentElement.style.setProperty('--btn-opc', '1');
            document.documentElement.style.setProperty('--btns-left', '20px');
            document.documentElement.style.setProperty('--my-settings-label-color', 'limegreen');
            document.documentElement.style.setProperty('--box-shadow', '3px 3px 6px #0500ff, -3px -3px 6px #da05f3');
            break;
        case 'dark':
            // dark theme
            swalBackground = 'rgba(0, 0, 0, 0.7)';
            document.documentElement.style.setProperty('--body-bg', '#16171b');
            document.documentElement.style.setProperty('--msger-bg', '#16171b');
            document.documentElement.style.setProperty('--msger-private-bg', '#16171b');
            document.documentElement.style.setProperty('--left-msg-bg', '#222328');
            document.documentElement.style.setProperty('--private-msg-bg', '#f77070');
            document.documentElement.style.setProperty('--right-msg-bg', '#0a0b0c');
            document.documentElement.style.setProperty('--wb-bg', '#000000');
            document.documentElement.style.setProperty('--wb-hbg', '#000000');
            document.documentElement.style.setProperty('--btn-bg', 'white');
            document.documentElement.style.setProperty('--btn-color', 'black');
            document.documentElement.style.setProperty('--btn-opc', '1');
            document.documentElement.style.setProperty('--btns-left', '20px');
            document.documentElement.style.setProperty('--my-settings-label-color', 'limegreen');
            document.documentElement.style.setProperty('--box-shadow', '3px 3px 6px #0a0b0c, -3px -3px 6px #222328');
            break;
        case 'forest':
            // forest theme
            swalBackground = 'rgba(0, 0, 0, 0.7)';
            document.documentElement.style.setProperty('--body-bg', 'black');
            document.documentElement.style.setProperty('--msger-bg', 'black');
            document.documentElement.style.setProperty('--msger-private-bg', 'black');
            document.documentElement.style.setProperty('--left-msg-bg', '#2e3500');
            document.documentElement.style.setProperty('--private-msg-bg', '#f77070');
            document.documentElement.style.setProperty('--right-msg-bg', '#004b1c');
            document.documentElement.style.setProperty('--wb-bg', '#000000');
            document.documentElement.style.setProperty('--wb-hbg', '#000000');
            document.documentElement.style.setProperty('--btn-bg', 'white');
            document.documentElement.style.setProperty('--btn-color', 'black');
            document.documentElement.style.setProperty('--btn-opc', '1');
            document.documentElement.style.setProperty('--btns-left', '20px');
            document.documentElement.style.setProperty('--my-settings-label-color', 'limegreen');
            document.documentElement.style.setProperty('--box-shadow', '3px 3px 6px #27944f, -3px -3px 6px #14843d');
            break;
        case 'sky':
            // sky theme
            swalBackground = 'rgba(0, 0, 0, 0.7)';
            document.documentElement.style.setProperty('--body-bg', 'black');
            document.documentElement.style.setProperty('--msger-bg', 'black');
            document.documentElement.style.setProperty('--msger-private-bg', 'black');
            document.documentElement.style.setProperty('--left-msg-bg', '#0c95b7');
            document.documentElement.style.setProperty('--private-msg-bg', '#f77070');
            document.documentElement.style.setProperty('--right-msg-bg', '#012a5f');
            document.documentElement.style.setProperty('--wb-bg', '#000000');
            document.documentElement.style.setProperty('--wb-hbg', '#000000');
            document.documentElement.style.setProperty('--btn-bg', 'white');
            document.documentElement.style.setProperty('--btn-color', 'black');
            document.documentElement.style.setProperty('--btn-opc', '1');
            document.documentElement.style.setProperty('--btns-left', '20px');
            document.documentElement.style.setProperty('--my-settings-label-color', '#03a5ce');
            document.documentElement.style.setProperty('--box-shadow', '3px 3px 6px #03a5ce, -3px -3px 6px #03a5ce');
            break;
        case 'ghost':
            // ghost theme
            swalBackground = 'rgba(0, 0, 0, 0.150)';
            document.documentElement.style.setProperty('--body-bg', 'black');
            document.documentElement.style.setProperty('--msger-bg', 'transparent');
            document.documentElement.style.setProperty('--msger-private-bg', 'black');
            document.documentElement.style.setProperty('--wb-bg', '#000000');
            document.documentElement.style.setProperty('--wb-hbg', '#000000');
            document.documentElement.style.setProperty('--btn-bg', 'transparent');
            document.documentElement.style.setProperty('--btn-color', 'white');
            document.documentElement.style.setProperty('--btn-opc', '0.7');
            document.documentElement.style.setProperty('--btns-left', '20px');
            document.documentElement.style.setProperty('--box-shadow', '0px');
            document.documentElement.style.setProperty('--my-settings-label-color', 'limegreen');
            document.documentElement.style.setProperty('--left-msg-bg', 'rgba(0, 0, 0, 0.7)');
            document.documentElement.style.setProperty('--private-msg-bg', 'rgba(252, 110, 110, 0.7)');
            document.documentElement.style.setProperty('--right-msg-bg', 'rgba(0, 0, 0, 0.7)');
            break;
        // ...
        default:
            console.log('No theme found');
    }
}

/**
 * Setup local media stuff. Ask user for permission to use the computers microphone and/or camera,
 * attach it to an <audio> or <video> tag if they give us access.
 * https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia
 *
 * @param {*} callback
 * @param {*} errorback
 */
function setupLocalMedia(callback, errorback) {
    // if we've already been initialized do nothing
    if (localMediaStream != null) {
        if (callback) callback();
        return;
    }

    getPeerGeoLocation();

    console.log('Requesting access to local audio / video inputs');

    // default | qvgaVideo | vgaVideo | hdVideo | fhdVideo | 4kVideo |
    let videoConstraints =
        myBrowserName === 'Firefox' ? getVideoConstraints('useVideo') : getVideoConstraints('default');

    const constraints = {
        audio: useAudio,
        video: videoConstraints,
    };

    navigator.mediaDevices
        .getUserMedia(constraints)
        .then((stream) => {
            loadLocalMedia(stream);
            if (callback) callback();
        })
        .catch((err) => {
            // https://blog.addpipe.com/common-getusermedia-errors/
            console.error('Access denied for audio/video', err);
            playSound('error');
            window.location.href = `/permission?roomId=${roomId}&getUserMediaError=${err.toString()}`;
            if (errorback) errorback();
        });
} // end [setup_local_stream]

/**
 * Load Local Media Stream obj
 * @param {*} stream
 */
function loadLocalMedia(stream) {
    console.log('Access granted to audio/video');
    // hide img bg and loading div
    //document.body.style.backgroundImage = 'none';
   
    getId('loadingDiv').style.display = 'none';
    getId('newloading').style.display = 'none';
    //document.body.style.backgroundImage = url('/Cognimeet_Assets/Loading/Group 2306.png');
    //document.body.style.backgroundImage = '../css/Cognimeet_Assets/Loading/Group 2306.png';
    localMediaStream = stream;

    const videoWrap = document.createElement('div');
    // handle my peer name video audio status
    const myStatusMenu = document.createElement('div');
    const myCountTimeImg = document.createElement('i');
    const myCountTime = document.createElement('p');
    const myVideoParagraphImg = document.createElement('i');
    const myVideoParagraph = document.createElement('h4');
    const myHandStatusIcon = document.createElement('button');
    const myVideoStatusIcon = document.createElement('button');
    const myAudioStatusIcon = document.createElement('button');
    const myVideoFullScreenBtn = document.createElement('button');

    // const myVideoAvatarImage = document.createElement('img');

    // menu Status
    myStatusMenu.setAttribute('id', 'myStatusMenu');
    myStatusMenu.className = 'statusMenu';

    // session time
    myCountTimeImg.setAttribute('id', 'countTimeImg');
    myCountTimeImg.className = 'fas fa-clock';
    myCountTime.setAttribute('id', 'countTime');
    tippy(myCountTime, {
        content: 'Session Time',
    });

    // my peer name
    myVideoParagraphImg.setAttribute('id', 'myVideoParagraphImg');
    myVideoParagraphImg.className = 'fas fa-user';
    myVideoParagraph.setAttribute('id', 'myVideoParagraph');
    myVideoParagraph.className = 'videoPeerName';
    tippy(myVideoParagraph, {
        content: 'My name',
    });

    // my hand status element
    myHandStatusIcon.setAttribute('id', 'myHandStatusIcon');
    myHandStatusIcon.className = 'fas fa-hand-paper pulsate';
    myHandStatusIcon.style.setProperty('color', 'rgb(0, 255, 0)');
    tippy(myHandStatusIcon, {
        content: 'My hand is RAISED',
    });

    // my video status element
    myVideoStatusIcon.setAttribute('id', 'myVideoStatusIcon');
    myVideoStatusIcon.className = 'fas fa-video';
    tippy(myVideoStatusIcon, {
        content: 'My video is ON',
    });
    
    // my audio status element
    myAudioStatusIcon.setAttribute('id', 'myAudioStatusIcon');
    myAudioStatusIcon.className = 'fas fa-microphone';
    tippy(myAudioStatusIcon, {
        content: 'My audio is ON',
    });

    // my video full screen mode
    myVideoFullScreenBtn.setAttribute('id', 'myVideoFullScreenBtn');
    myVideoFullScreenBtn.className = 'fas fa-expand';
    tippy(myVideoFullScreenBtn, {
        content: 'Full screen mode',
    });

    // my video avatar image
    // myVideoAvatarImage.setAttribute('id', 'myVideoAvatarImage');
    // myVideoAvatarImage.className = 'videoAvatarImage pulsate';

    // add elements to myStatusMenu div
    myStatusMenu.appendChild(myCountTimeImg);
    myStatusMenu.appendChild(myCountTime);
    myStatusMenu.appendChild(myVideoParagraphImg);
    myStatusMenu.appendChild(myVideoParagraph);
    myStatusMenu.appendChild(myHandStatusIcon);
    myStatusMenu.appendChild(myVideoStatusIcon);
    myStatusMenu.appendChild(myAudioStatusIcon);
    myStatusMenu.appendChild(myVideoFullScreenBtn);

    // add elements to video wrap div
    videoWrap.appendChild(myStatusMenu);
    //videoWrap.appendChild(myVideoAvatarImage);

    // hand display none on default menad is raised == false
    myHandStatusIcon.style.display = 'none';

    const localMedia = document.createElement('video');
    videoWrap.className = 'video';
    videoWrap.setAttribute('id', 'myVideoWrap');
    videoWrap.appendChild(localMedia);
    localMedia.setAttribute('id', 'myVideo');
    localMedia.setAttribute('playsinline', true);
    localMedia.className = 'mirror';
    localMedia.autoplay = true;
    localMedia.muted = true;
    localMedia.volume = 0;
    localMedia.controls = false;
    document.body.appendChild(videoWrap);

    logStreamSettingsInfo('localMediaStream', localMediaStream);
    attachMediaStream(localMedia, localMediaStream);
    resizeVideos();
    getHtmlElementsById();
    setButtonsTitle();
    manageLeftButtons();
    handleBodyOnMouseMove();
    setupMySettings();
    startCountTime();
    handleVideoPlayerFs('myVideo', 'myVideoFullScreenBtn');
}

let emotionschunk = []; 

/**
 * Load Remote Media Stream obj   //other videos/ secondary videos
 * @param {*} stream
 * @param {*} peers
 * @param {*} peer_id
 */
function loadRemoteMediaStream(stream, peers, peer_id) {
    remoteMediaStream = stream;
    const videoWrap = document.createElement('div');
    // handle peers name video audio status
    const remoteStatusMenu = document.createElement('div');
    const remoteVideoParagraphImg = document.createElement('i');
    const remoteVideoParagraph = document.createElement('h4');
    const remoteHandStatusIcon = document.createElement('button');
    const remoteVideoStatusIcon = document.createElement('button');
    const remoteAudioStatusIcon = document.createElement('button');
    const remotePeerKickOut = document.createElement('button');
    const remoteVideoFullScreenBtn = document.createElement('button');
    const remoteVideoAvatarImage = document.createElement('img');

    // menu Status
    remoteStatusMenu.setAttribute('id', peer_id + '_menuStatus');
    remoteStatusMenu.className = 'statusMenu';

    // remote peer name element
    remoteVideoParagraphImg.setAttribute('id', peer_id + '_nameImg');
    remoteVideoParagraphImg.className = 'fas fa-user';
    remoteVideoParagraph.setAttribute('id', peer_id + '_name');
    remoteVideoParagraph.className = 'videoPeerName';
    tippy(remoteVideoParagraph, {
        content: 'Participant name',
    });
    const peerVideoText = document.createTextNode(peers[peer_id]['peer_name']);
    remoteVideoParagraph.appendChild(peerVideoText);

    // remote hand status element
    remoteHandStatusIcon.setAttribute('id', peer_id + '_handStatus');
    remoteHandStatusIcon.style.setProperty('color', 'rgb(0, 255, 0)');
    remoteHandStatusIcon.className = 'fas fa-hand-paper pulsate';
    tippy(remoteHandStatusIcon, {
        content: 'Participant hand is RAISED',
    });

    // remote video status element
    remoteVideoStatusIcon.setAttribute('id', peer_id + '_videoStatus');
    remoteVideoStatusIcon.className = 'fas fa-video';
    tippy(remoteVideoStatusIcon, {
        content: 'Participant video is ON',
    });

    // remote audio status element
    remoteAudioStatusIcon.setAttribute('id', peer_id + '_audioStatus');
    remoteAudioStatusIcon.className = 'fas fa-microphone';
    tippy(remoteAudioStatusIcon, {
        content: 'Participant audio is ON',
    });

    // remote peer kick out
    remotePeerKickOut.setAttribute('id', peer_id + '_kickOut');
    remotePeerKickOut.className = 'fas fa-sign-out-alt';
    tippy(remotePeerKickOut, {
        content: 'Kick out',
    });

    // remote video full screen mode
    remoteVideoFullScreenBtn.setAttribute('id', peer_id + '_fullScreen');
    remoteVideoFullScreenBtn.className = 'fas fa-expand';
    tippy(remoteVideoFullScreenBtn, {
        content: 'Full screen mode',
    });

    // my video avatar image
    remoteVideoAvatarImage.setAttribute('id', peer_id + '_avatar');
    remoteVideoAvatarImage.className = 'videoAvatarImage pulsate';

    // add elements to remoteStatusMenu div
    remoteStatusMenu.appendChild(remoteVideoParagraphImg);
    remoteStatusMenu.appendChild(remoteVideoParagraph);
    remoteStatusMenu.appendChild(remoteHandStatusIcon);
    remoteStatusMenu.appendChild(remoteVideoStatusIcon);
    remoteStatusMenu.appendChild(remoteAudioStatusIcon);
    remoteStatusMenu.appendChild(remotePeerKickOut);
    remoteStatusMenu.appendChild(remoteVideoFullScreenBtn);

    // add elements to videoWrap div
    videoWrap.appendChild(remoteStatusMenu);
    videoWrap.appendChild(remoteVideoAvatarImage);

    const remoteMedia = document.createElement('video');
    videoWrap.className = 'video';
    videoWrap.appendChild(remoteMedia);
    remoteMedia.setAttribute('id', peer_id + '_video');
    remoteMedia.setAttribute('playsinline', true);
    remoteMedia.mediaGroup = 'remotevideo';
    remoteMedia.autoplay = true;
    isMobileDevice ? (remoteMediaControls = false) : (remoteMediaControls = remoteMediaControls);
    remoteMedia.controls = remoteMediaControls;
    peerMediaElements[peer_id] = remoteMedia;
    document.body.appendChild(videoWrap);

    // attachMediaStream is a part of the adapter.js library
    attachMediaStream(remoteMedia, remoteMediaStream);
    // resize video elements
    resizeVideos();
    // handle video full screen mode
    handleVideoPlayerFs(peer_id + '_video', peer_id + '_fullScreen');
    // handle kick out button event
    handlePeerKickOutBtn(peer_id);
    // refresh remote peers avatar name
    setPeerAvatarImgName(peer_id + '_avatar', peers[peer_id]['peer_name']);
    // refresh remote peers hand icon status and title
    setPeerHandStatus(peer_id, peers[peer_id]['peer_name'], peers[peer_id]['peer_hand']);
    // refresh remote peers video icon status and title
    setPeerVideoStatus(peer_id, peers[peer_id]['peer_video']);
    // refresh remote peers audio icon status and title
    setPeerAudioStatus(peer_id, peers[peer_id]['peer_audio']);
    // show status menu
    toggleClassElements('statusMenu', 'inline');

    //------ code to take images , convert to base64, sending to api, saving result in text file.
    //add take photo code 
    var canvas = document.getElementById('canvas');
    //hide photo element
    var photo = document.getElementById('photo');  
    document.getElementById("photo").style.display = "none";
    //hide startbutton element
    var startbutton = document.getElementById('startbutton');
    document.getElementById("startbutton").style.display = "none";
    document.getElementById("canvas").style.display = "none";
    var video = document.getElementById(peer_id + '_video');
    document.getElementById("camera_container").style.display = "none";
    //document.getHtmlElementById("submit").style.display ="none";
    startbutton.addEventListener('click', function(ev){
        takepicture();
        ev.preventDefault();
      }, false);
  
      //this function will click the button every 1000 ms
      setInterval(function () {document.getElementById("startbutton").click();}, 5000);
      
      clearphoto();

      function clearphoto() {
        var context = canvas.getContext('2d');
        context.fillStyle = "#AAA";
        context.fillRect(0, 0, canvas.width, canvas.height);
        var data = canvas.toDataURL('image/png');
        photo.setAttribute('src', data);
      }

      var width = 320;
      var height = 320;

      function takepicture() {
        var context = canvas.getContext('2d');
        if (width && height) {
        canvas.width = width;
        canvas.height = height;
        context.drawImage(video, 0, 0, width, height);
        var data = canvas.toDataURL('image/png');
        //console.log(data)
        photo.setAttribute('src', data);
        } else {
        clearphoto();
        }
        var image_data_in_json = JSON.stringify({"img": [data]});
        //console.log(image_data_in_json)
        //sendJSON(imgdata)
        
        //do something with response json
        //success holds the json data
        function doSomething(success){
            //console.log('dosomething_function');
            var dominant_emotion = success["instance_1"]["dominant_emotion"];
            //console.log('dominant_emotion',dominant_emotion) //normal output of emotion
            var dominant_emotion_json = JSON.stringify(dominant_emotion);
            //console.log('dominant_emotion_json',dominant_emotion_json); //string output of emotion

            emotionschunk.push(dominant_emotion_json);
            emotionschunk.push(',');
            emotionschunk.push('\n');
          }
        
        //console.log('emotionschunk:',emotionschunk)
        //trying fetch api
        var url = 'https://cogniemoai.azurewebsites.net/analyze';
        fetch(url, {
        method: 'POST', // or 'PUT'
        body: image_data_in_json, // data can be `string` or {object}!
        headers:{
            'Content-Type': 'application/json'
        }
        }).then(res => res.json())
        //.then(response => console.log('Success:', JSON.stringify(response)))  //here we will see the result from the api
        .then(success => doSomething(success))
        .catch(error => console.error('Error:', error));

    } //end of take picture function
} //end of loadremotestream function

//writing a fucntion to downlaod the emotions data 
start.addEventListener('click', async function(){
    savejsonFile(emotionschunk);
    console.log('emotionschunk saving initiated...')
})

function savejsonFile(emotionschunk){
    //blob contains all the json data now
    const blob = new Blob(emotionschunk, {
       type: 'text/plain'
     });
    //console.log(blob);
    let filename = 'emotionsjson',
    downloadLink = document.createElement('a');
    downloadLink.href = URL.createObjectURL(blob);
    downloadLink.download = `${filename}.txt`; //`url('${filename}.txt')`;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    //console.log(downloadLink)
    //console.log(downloadLink.download)
    URL.revokeObjectURL(blob); // clear from memory
    document.body.removeChild(downloadLink);
}

/**
 * Log stream settings info
 * @param {*} name
 * @param {*} stream
 */
function logStreamSettingsInfo(name, stream) {
    console.log(name, {
        video: {
            label: stream.getVideoTracks()[0].label,
            settings: stream.getVideoTracks()[0].getSettings(),
        },
        audio: {
            label: stream.getAudioTracks()[0].label,
            settings: stream.getAudioTracks()[0].getSettings(),
        },
    });
}

/**
 * Resize video elements
 */
function resizeVideos() {
    const numToString = ['', 'one', 'two', 'three', 'four', 'five', 'six'];
    const videos = document.querySelectorAll('.video');
    document.querySelectorAll('.video').forEach((v) => {
        v.className = 'video ' + numToString[videos.length];
    });
}

/**
 * Refresh video - chat image avatar on name changes
 * https://eu.ui-avatars.com/
 *
 * @param {*} videoAvatarImageId element
 * @param {*} peerName
 */
function setPeerAvatarImgName(videoAvatarImageId, peerName) {
    let videoAvatarImageElement = getId(videoAvatarImageId);
    // default img size 64 max 512
    let avatarImgSize = isMobileDevice ? 128 : 256;
    videoAvatarImageElement.setAttribute(
        'src',
        avatarApiUrl + '?name=' + peerName + '&size=' + avatarImgSize + '&background=random&rounded=true',
    );
}

/**
 * Set Chat avatar image by peer name
 * @param {*} avatar left/right
 * @param {*} peerName my/friends
 */
function setPeerChatAvatarImgName(avatar, peerName) {
    let avatarImg = avatarApiUrl + '?name=' + peerName + '&size=32' + '&background=random&rounded=true';

    switch (avatar) {
        case 'left':
            // console.log("Set Friend chat avatar image");
            leftChatAvatar = avatarImg;
            break;
        case 'right':
            // console.log("Set My chat avatar image");
            rightChatAvatar = avatarImg;
            break;
    }
}

/**
 * On video player click, go on full screen mode ||
 * On button click, go on full screen mode.
 * Press Esc to exit from full screen mode, or click again.
 *
 * @param {*} videoId
 * @param {*} videoFullScreenBtnId
 */
function handleVideoPlayerFs(videoId, videoFullScreenBtnId) {
    let videoPlayer = getId(videoId);
    let videoFullScreenBtn = getId(videoFullScreenBtnId);

    // handle Chrome Firefox Opera Microsoft Edge videoPlayer ESC
    videoPlayer.addEventListener('fullscreenchange', (e) => {
        // if Controls enabled, or document on FS do nothing
        if (videoPlayer.controls || isDocumentOnFullScreen) return;
        let fullscreenElement = document.fullscreenElement;
        if (!fullscreenElement) {
            videoPlayer.style.pointerEvents = 'auto';
            isVideoOnFullScreen = false;
            // console.log("Esc FS isVideoOnFullScreen", isVideoOnFullScreen);
        }
    });

    // handle Safari videoPlayer ESC
    videoPlayer.addEventListener('webkitfullscreenchange', (e) => {
        // if Controls enabled, or document on FS do nothing
        if (videoPlayer.controls || isDocumentOnFullScreen) return;
        let webkitIsFullScreen = document.webkitIsFullScreen;
        if (!webkitIsFullScreen) {
            videoPlayer.style.pointerEvents = 'auto';
            isVideoOnFullScreen = false;
            // console.log("Esc FS isVideoOnFullScreen", isVideoOnFullScreen);
        }
    });

    // on button click go on FS
    videoFullScreenBtn.addEventListener('click', (e) => {
        handleFSVideo();
    });

    // on video click go on FS
    videoPlayer.addEventListener('click', (e) => {
        // not mobile on click go on FS or exit from FS
        if (!isMobileDevice) {
            handleFSVideo();
        } else {
            // mobile on click exit from FS, for enter use videoFullScreenBtn
            if (isVideoOnFullScreen) handleFSVideo();
        }
    });

    function handleFSVideo() {
        // if Controls enabled, or document on FS do nothing
        if (videoPlayer.controls || isDocumentOnFullScreen) return;

        if (!isVideoOnFullScreen) {
            if (videoPlayer.requestFullscreen) {
                // Chrome Firefox Opera Microsoft Edge
                videoPlayer.requestFullscreen();
            } else if (videoPlayer.webkitRequestFullscreen) {
                // Safari request full screen mode
                videoPlayer.webkitRequestFullscreen();
            } else if (videoPlayer.msRequestFullscreen) {
                // IE11 request full screen mode
                videoPlayer.msRequestFullscreen();
            }
            isVideoOnFullScreen = true;
            videoPlayer.style.pointerEvents = 'none';
            // console.log("Go on FS isVideoOnFullScreen", isVideoOnFullScreen);
        } else {
            if (document.exitFullscreen) {
                // Chrome Firefox Opera Microsoft Edge
                document.exitFullscreen();
            } else if (document.webkitCancelFullScreen) {
                // Safari exit full screen mode ( Not work... )
                document.webkitCancelFullScreen();
            } else if (document.msExitFullscreen) {
                // IE11 exit full screen mode
                document.msExitFullscreen();
            }
            isVideoOnFullScreen = false;
            videoPlayer.style.pointerEvents = 'auto';
            // console.log("Esc FS isVideoOnFullScreen", isVideoOnFullScreen);
        }
    }
}

/**
 * Start talk time
 */
function startCountTime() {
    countTime.style.display = 'inline';
    callStartTime = Date.now();
    setInterval(function printTime() {
        callElapsedTime = Date.now() - callStartTime;
        countTime.innerHTML = getTimeToString(callElapsedTime);
    }, 1000);
}

/**
 * Return time to string
 * @param {*} time
 */
function getTimeToString(time) {
    let diffInHrs = time / 3600000;
    let hh = Math.floor(diffInHrs);
    let diffInMin = (diffInHrs - hh) * 60;
    let mm = Math.floor(diffInMin);
    let diffInSec = (diffInMin - mm) * 60;
    let ss = Math.floor(diffInSec);
    let formattedHH = hh.toString().padStart(2, '0');
    let formattedMM = mm.toString().padStart(2, '0');
    let formattedSS = ss.toString().padStart(2, '0');
    return `${formattedHH}:${formattedMM}:${formattedSS}`;
}

/**
 * Handle WebRTC left buttons
 */
function manageLeftButtons() {
    setShareRoomBtn();
    setAudioBtn();
    setVideoBtn();
    setSwapCameraBtn();
    setScreenShareBtn();
    setRecordStreamBtn();
    //setFullScreenBtn();
    setChatRoomBtn();
    setChatEmojiBtn();
    setMyHandBtn();
    //setMyWhiteboardBtn();
    //setMyBgImgBtn();
    setMyFileShareBtn();
    setMySettingsBtn();
    // setAboutBtn();
    setLeaveRoomBtn();
    showLeftButtonsAndMenu();
}

/**
 * Copy - share room url button click event
 */
function setShareRoomBtn() {
    shareRoomBtn.addEventListener('click', async (e) => {
        shareRoomUrl();
    });
}

/**
 * Audio mute - unmute button click event
 */
function setAudioBtn() {
    audioBtn.addEventListener('click', (e) => {
        handleAudio(e, false);
    });
}

/**
 * Video hide - show button click event
 */
function setVideoBtn() {
    videoBtn.addEventListener('click', (e) => {
        handleVideo(e, false);
    });
}

/**
 * Check if can swap or not the cam, if yes show the button else hide it
 */
function setSwapCameraBtn() {
    navigator.mediaDevices.enumerateDevices().then((devices) => {
        const videoInput = devices.filter((device) => device.kind === 'videoinput');
        if (videoInput.length > 1 && isMobileDevice) {
            swapCameraBtn.addEventListener('click', (e) => {
                swapCamera();
            });
        } else {
            swapCameraBtn.style.display = 'none';
        }
    });
}

/**
 * Check if i can share the screen, if yes show button else hide it
 */
function setScreenShareBtn() {
    if (!isMobileDevice && (navigator.getDisplayMedia || navigator.mediaDevices.getDisplayMedia)) {
        screenShareBtn.addEventListener('click', (e) => {
            toggleScreenSharing();
            if (myVideoStatus === false) {
                console.log(myVideoStatus);
                setMyVideoStatus(myVideoStatus);
            }
        });
    } else {
        screenShareBtn.style.display = 'none';
    }
}

/**
 * Start - Stop Stream recording
 */
function setRecordStreamBtn() {
    recordStreamBtn.addEventListener('click', (e) => {
        if (isStreamRecording) {
            playSound('recStop');
            stopStreamRecording();
        } else {
            playSound('recStart');
            startStreamRecording();
        }
    });
}

/**
 * Full screen button click event
 */

//deleted the function , as fullscreen button is not needed anymore

/**
 * Chat room buttons click event
 */
function setChatRoomBtn() {
    // adapt chat room size for mobile
    setChatRoomForMobile();

    // open hide chat room
    chatRoomBtn.addEventListener('click', (e) => {
        if (!isChatRoomVisible) {
            showChatRoomDraggable();
        } else {
            hideChatRoomAndEmojiPicker();
            /*e.target.className = 'fas fa-comment';*/
        }
    });

    // ghost theme + undo
    msgerTheme.addEventListener('click', (e) => {
        if (mirotalkTheme == 'ghost') return;

        if (e.target.className == 'fas fa-ghost') {
            e.target.className = 'fas fa-undo';
            document.documentElement.style.setProperty('--msger-bg', 'rgba(0, 0, 0, 0.100)');
            document.documentElement.style.setProperty('--msger-private-bg', 'black');
        } else {
            e.target.className = 'fas fa-ghost';
            mirotalkTheme == 'dark'
                ? document.documentElement.style.setProperty('--msger-bg', '#16171b')
                : document.documentElement.style.setProperty('--msger-bg', 'black');
        }
    });

    // show msger participants section
    msgerCPBtn.addEventListener('click', (e) => {
        if (!thereIsPeerConnections()) {
            userLog('info', 'No participants detected');
            return;
        }
        msgerCP.style.display = 'flex';
    });

    // hide msger participants section
    msgerCPCloseBtn.addEventListener('click', (e) => {
        msgerCP.style.display = 'none';
    });

    // clean chat messages
    msgerClean.addEventListener('click', (e) => {
        cleanMessages();
    });

    // save chat messages to file
    msgerSaveBtn.addEventListener('click', (e) => {
        if (chatMessages.length != 0) {
            downloadChatMsgs();
            return;
        }
        userLog('info', 'No chat messages to save');
    });

    // close chat room - show left button and status menu if hide
    msgerClose.addEventListener('click', (e) => {
        hideChatRoomAndEmojiPicker();
        showLeftButtonsAndMenu();
    });

    // Execute a function when the user releases a key on the keyboard
    msgerInput.addEventListener('keyup', (e) => {
        // Number 13 is the "Enter" key on the keyboard
        if (e.keyCode === 13) {
            e.preventDefault();
            msgerSendBtn.click();
        }
    });

    // on input check 4emoji from map
    msgerInput.oninput = function () {
        for (let i in chatInputEmoji) {
            let regex = new RegExp(escapeSpecialChars(i), 'gim');
            this.value = this.value.replace(regex, chatInputEmoji[i]);
        }
    };

    // chat send msg
    msgerSendBtn.addEventListener('click', (e) => {
        // prevent refresh page
        e.preventDefault();
        sendChatMessage();
    });
}

/**
 * Emoji picker chat room button click event
 */
function setChatEmojiBtn() {
    if (isMobileDevice) {
        // mobile already have it
        msgerEmojiBtn.style.display = 'none';
    } else {
        // make emoji picker draggable for desktop
        dragElement(msgerEmojiPicker, msgerEmojiHeader);

        msgerEmojiBtn.addEventListener('click', (e) => {
            // prevent refresh page
            e.preventDefault();
            hideShowEmojiPicker();
        });

        msgerCloseEmojiBtn.addEventListener('click', (e) => {
            // prevent refresh page
            e.preventDefault();
            hideShowEmojiPicker();
        });

        emojiPicker.addEventListener('emoji-click', (e) => {
            //console.log(e.detail);
            //console.log(e.detail.emoji.unicode);
            msgerInput.value += e.detail.emoji.unicode;
        });
    }
}

/**
 * Set my hand button click event
 */
function setMyHandBtn() {
    myHandBtn.addEventListener('click', async (e) => {
        setMyHandStatus();
    });
}

/**
 * Whiteboard : https://r8.whiteboardfox.com (good alternative)
 */
function setMyWhiteboardBtn() {
    // not supported for mobile
    if (isMobileDevice) {
        whiteboardBtn.style.display = 'none';
        return;
    }

    setupCanvas();

    // open - close whiteboard
    whiteboardBtn.addEventListener('click', (e) => {
        if (isWhiteboardVisible) {
            whiteboardClose();
            remoteWbAction('close');
        } else {
            whiteboardOpen();
            remoteWbAction('open');
        }
    });
    // close whiteboard
    whiteboardCloseBtn.addEventListener('click', (e) => {
        whiteboardClose();
        remoteWbAction('close');
    });
    // view full screen
    whiteboardFsBtn.addEventListener('click', (e) => {
        whiteboardResize();
        remoteWbAction('resize');
    });
    // erase whiteboard
    whiteboardEraserBtn.addEventListener('click', (e) => {
        setEraser();
    });
    // save whitebaord content as img
    whiteboardSaveBtn.addEventListener('click', (e) => {
        saveWbCanvas();
    });
    // clean whiteboard
    whiteboardCleanBtn.addEventListener('click', (e) => {
        confirmCleanBoard();
    });
}

/**
 * Set my background image button click event
 */
/*
function setMyBgImgBtn() {
    setBgImgBtn.addEventListener('click', (e) => {
        if (!isImgDivOpen) {
            optionsContainer.style.display = 'flex';
        } else {
            optionsContainer.style.display = 'none';
        }
        for (let i = 0; i < imgOptions.length; i++) {
            imgOptions[i].addEventListener('click', (e) => {
                let selectedImg = e.target.classList[0];
                console.log('gekfk');
                document.body.style.backgroundImage = `url('../images/2d Backgrounds/bg${selectedImg}.jpg')`;
                document.body.style.backgroundSize = "cover"
                optionsContainer.style.display = 'none';
                isImgDivOpen = false;
            });
        }
        isImgDivOpen = !isImgDivOpen;
    });
    
}
*/

/**
 * File Transfer button event click
 */
function setMyFileShareBtn() {
    // make send file div draggable
    if (!isMobileDevice) dragElement(getId('sendFileDiv'), getId('imgShare'));

    fileShareBtn.addEventListener('click', (e) => {
        //window.open("https://fromsmash.com"); // for Big Data
        selectFileToShare();
    });
    sendAbortBtn.addEventListener('click', (e) => {
        abortFileTransfer();
    });
}

/**
 * My settings button click event
 */
function setMySettingsBtn() {
    mySettingsBtn.addEventListener('click', (e) => {
        if (isMobileDevice) {
            leftButtons.style.display = 'none';
            isButtonsVisible = false;
        }
        hideShowMySettings();
    });
    mySettingsCloseBtn.addEventListener('click', (e) => {
        hideShowMySettings();
    });
    myPeerNameSetBtn.addEventListener('click', (e) => {
        updateMyPeerName();
    });
    // make chat room draggable for desktop
    if (!isMobileDevice) dragElement(mySettings, mySettingsHeader);
}

/**
 * About button click event
 */
// function setAboutBtn() {
//     aboutBtn.addEventListener('click', (e) => {
//         // getAbout();
//     });
// }

/**
 * Leave room button click event
 */
function setLeaveRoomBtn() {
    leaveRoomBtn.addEventListener('click', (e) => {
        leaveRoom();
    });
}

/**
 * Handle left buttons - status menù show - hide on body mouse move
 */
function handleBodyOnMouseMove() {
    document.body.addEventListener('mousemove', (e) => {
        showLeftButtonsAndMenu();
    });
}

/**
 * Setup local audio - video devices - theme ...
 */
function setupMySettings() {
    // tab buttons
    tabDevicesBtn.addEventListener('click', (e) => {
        openTab(e, 'tabDevices');
    });
    tabBandwidthBtn.addEventListener('click', (e) => {
        openTab(e, 'tabBandwidth');
    });
    tabRoomBtn.addEventListener('click', (e) => {
        openTab(e, 'tabRoom');
    });
    tabThemeBtn.addEventListener('click', (e) => {
        openTab(e, 'tabTheme');
    });
    // audio - video select box
    selectors = [audioInputSelect, audioOutputSelect, videoSelect];
    audioOutputSelect.disabled = !('sinkId' in HTMLMediaElement.prototype);
    navigator.mediaDevices.enumerateDevices().then(gotDevices).catch(handleError);
    // select audio input
    audioInputSelect.addEventListener('change', (e) => {
        myVideoChange = false;
        refreshLocalMedia();
    });
    // select audio output
    audioOutputSelect.addEventListener('change', (e) => {
        changeAudioDestination();
    });
    // select video input
    videoSelect.addEventListener('change', (e) => {
        myVideoChange = true;
        refreshLocalMedia();
    });
    // select video quality
    videoQualitySelect.addEventListener('change', (e) => {
        setLocalVideoQuality();
    });
    // select video fps
    videoFpsSelect.addEventListener('change', (e) => {
        videoMaxFrameRate = parseInt(videoFpsSelect.value);
        setLocalMaxFps(videoMaxFrameRate);
    });
    // Firefox not support video cam Fps O.o
    if (myBrowserName === 'Firefox') {
        videoFpsSelect.value = null;
        videoFpsSelect.disabled = true;
    }
    // select screen fps
    screenFpsSelect.addEventListener('change', (e) => {
        screenMaxFrameRate = parseInt(screenFpsSelect.value);
        if (isScreenStreaming) setLocalMaxFps(screenMaxFrameRate);
    });
    // Mobile not support screen sharing
    if (isMobileDevice) {
        screenFpsSelect.value = null;
        screenFpsSelect.disabled = true;
    }
    // select themes
    themeSelect.addEventListener('change', (e) => {
        setTheme(themeSelect.value);
        setRecordButtonUi();
    });
    // room actions
    muteEveryoneBtn.addEventListener('click', (e) => {
        disableAllPeers('audio');
    });
    hideEveryoneBtn.addEventListener('click', (e) => {
        disableAllPeers('video');
    });
    lockUnlockRoomBtn.addEventListener('click', (e) => {
        lockUnlockRoom();
    });
}

/**
 * Refresh Local media audio video in - out
 */
function refreshLocalMedia() {
    // some devices can't swap the video track, if already in execution.
    stopLocalVideoTrack();
    stopLocalAudioTrack();

    navigator.mediaDevices.getUserMedia(getAudioVideoConstraints()).then(gotStream).then(gotDevices).catch(handleError);
}

/**
 * Get audio - video constraints
 * @returns constraints
 */
function getAudioVideoConstraints() {
    const audioSource = audioInputSelect.value;
    const videoSource = videoSelect.value;
    let videoConstraints = getVideoConstraints(videoQualitySelect.value ? videoQualitySelect.value : 'default');
    videoConstraints['deviceId'] = videoSource ? { exact: videoSource } : undefined;
    const constraints = {
        audio: { deviceId: audioSource ? { exact: audioSource } : undefined },
        video: videoConstraints,
    };
    return constraints;
}

/**
 * https://webrtc.github.io/samples/src/content/getusermedia/resolution/
 *
 * @returns video constraints
 */
function getVideoConstraints(videoQuality) {
    let frameRate = { max: videoMaxFrameRate };

    switch (videoQuality) {
        case 'useVideo':
            return useVideo;
        // Firefox not support set frameRate (OverconstrainedError) O.o
        case 'default':
            return { frameRate: frameRate };
        // video cam constraints default
        case 'qvgaVideo':
            return {
                width: { exact: 320 },
                height: { exact: 240 },
                frameRate: frameRate,
            }; // video cam constraints low bandwidth
        case 'vgaVideo':
            return {
                width: { exact: 640 },
                height: { exact: 480 },
                frameRate: frameRate,
            }; // video cam constraints medium bandwidth
        case 'hdVideo':
            return {
                width: { exact: 1280 },
                height: { exact: 720 },
                frameRate: frameRate,
            }; // video cam constraints high bandwidth
        case 'fhdVideo':
            return {
                width: { exact: 1920 },
                height: { exact: 1080 },
                frameRate: frameRate,
            }; // video cam constraints very high bandwidth
        case '4kVideo':
            return {
                width: { exact: 3840 },
                height: { exact: 2160 },
                frameRate: frameRate,
            }; // video cam constraints ultra high bandwidth
    }
}

/**
 * https://developer.mozilla.org/en-US/docs/Web/API/MediaStreamTrack/applyConstraints
 *
 * @param {*} maxFrameRate
 */
function setLocalMaxFps(maxFrameRate) {
    localMediaStream
        .getVideoTracks()[0]
        .applyConstraints({ frameRate: { max: maxFrameRate } })
        .then(() => {
            logStreamSettingsInfo('setLocalMaxFps', localMediaStream);
        })
        .catch((err) => {
            console.error('setLocalMaxFps', err);
            userLog('error', "Your device doesn't support the selected fps, please select the another one.");
        });
}

/**
 * https://developer.mozilla.org/en-US/docs/Web/API/MediaStreamTrack/applyConstraints
 */
function setLocalVideoQuality() {
    let videoConstraints = getVideoConstraints(videoQualitySelect.value ? videoQualitySelect.value : 'default');
    localMediaStream
        .getVideoTracks()[0]
        .applyConstraints(videoConstraints)
        .then(() => {
            logStreamSettingsInfo('setLocalVideoQuality', localMediaStream);
        })
        .catch((err) => {
            console.error('setLocalVideoQuality', err);
            userLog('error', "Your device doesn't support the selected video quality, please select the another one.");
        });
}

/**
 * Change Speaker
 */
function changeAudioDestination() {
    const audioDestination = audioOutputSelect.value;
    attachSinkId(myVideo, audioDestination);
}

/**
 * Attach audio output device to video element using device/sink ID.
 * @param {*} element
 * @param {*} sinkId
 */
function attachSinkId(element, sinkId) {
    if (typeof element.sinkId !== 'undefined') {
        element
            .setSinkId(sinkId)
            .then(() => {
                console.log(`Success, audio output device attached: ${sinkId}`);
            })
            .catch((err) => {
                let errorMessage = err;
                if (err.name === 'SecurityError')
                    errorMessage = `You need to use HTTPS for selecting audio output device: ${err}`;
                console.error(errorMessage);
                // Jump back to first output device in the list as it's the default.
                audioOutputSelect.selectedIndex = 0;
            });
    } else {
        console.warn('Browser does not support output device selection.');
    }
}

/**
 * Got Stream and append to local media
 * @param {*} stream
 */
function gotStream(stream) {
    refreshMyStreamToPeers(stream, true);
    refreshMyLocalStream(stream, true);
    if (myVideoChange) {
        setMyVideoStatusTrue();
        if (isMobileDevice) myVideo.classList.toggle('mirror');
    }
    // Refresh button list in case labels have become available
    return navigator.mediaDevices.enumerateDevices();
}

/**
 * Get audio-video Devices and show it to select box
 * https://webrtc.github.io/samples/src/content/devices/input-output/
 * https://github.com/webrtc/samples/tree/gh-pages/src/content/devices/input-output
 * @param {*} deviceInfos
 */
function gotDevices(deviceInfos) {
    // Handles being called several times to update labels. Preserve values.
    const values = selectors.map((select) => select.value);
    selectors.forEach((select) => {
        while (select.firstChild) {
            select.removeChild(select.firstChild);
        }
    });
    // check devices
    for (let i = 0; i !== deviceInfos.length; ++i) {
        const deviceInfo = deviceInfos[i];
        // console.log("device-info ------> ", deviceInfo);
        const option = document.createElement('option');
        option.value = deviceInfo.deviceId;

        switch (deviceInfo.kind) {
            case 'videoinput':
                option.text = `📹 ` + deviceInfo.label || `📹 camera ${videoSelect.length + 1}`;
                videoSelect.appendChild(option);
                break;

            case 'audioinput':
                option.text = `🎤 ` + deviceInfo.label || `🎤 microphone ${audioInputSelect.length + 1}`;
                audioInputSelect.appendChild(option);
                break;

            case 'audiooutput':
                option.text = `🔈 ` + deviceInfo.label || `🔈 speaker ${audioOutputSelect.length + 1}`;
                audioOutputSelect.appendChild(option);
                break;

            default:
                console.log('Some other kind of source/device: ', deviceInfo);
        }
    } // end for devices

    selectors.forEach((select, selectorIndex) => {
        if (Array.prototype.slice.call(select.childNodes).some((n) => n.value === values[selectorIndex])) {
            select.value = values[selectorIndex];
        }
    });
}

/**
 * Handle getUserMedia error
 * @param {*} err
 */
function handleError(err) {
    console.log('navigator.MediaDevices.getUserMedia error: ', err);
    switch (err.name) {
        case 'OverconstrainedError':
            userLog(
                'error',
                "GetUserMedia: Your device doesn't support the selected video quality or fps, please select the another one.",
            );
            break;
        default:
            userLog('error', 'GetUserMedia error ' + err);
    }
    // https://blog.addpipe.com/common-getusermedia-errors/
}

/**
 * AttachMediaStream stream to element
 * @param {*} element
 * @param {*} stream
 */
function attachMediaStream(element, stream) {
    //console.log("DEPRECATED, attachMediaStream will soon be removed.");
    console.log('Success, media stream attached');
    element.srcObject = stream;
}

/**
 * Show left buttons & status menù for 10 seconds on body mousemove
 * if mobile and chatroom open do nothing return
 * if mobile and mySettings open do nothing return
 */
function showLeftButtonsAndMenu() {
    if (isButtonsVisible || (isMobileDevice && isChatRoomVisible) || (isMobileDevice && isMySettingsVisible)) return;
    toggleClassElements('statusMenu', 'inline');
    leftButtons.style.display = 'flex';
    isButtonsVisible = true;
    setTimeout(() => {
        toggleClassElements('statusMenu', 'none');
        leftButtons.style.display = 'none';
        isButtonsVisible = false;
    }, 1000000);
}

/**
 * Copy room url to clipboard and share it with navigator share if supported
 * https://developer.mozilla.org/en-US/docs/Web/API/Navigator/share
 */
async function shareRoomUrl() {
    const myRoomUrl = window.location.href;

    // navigator share
    let isSupportedNavigatorShare = false;
    let errorNavigatorShare = false;
    // if supported
    if (navigator.share) {
        isSupportedNavigatorShare = true;
        try {
            // not add title and description to load metadata from url
            await navigator.share({ url: myRoomUrl });
            userLog('toast', 'Room Shared successfully!');
        } catch (err) {
            errorNavigatorShare = true;
            /*
                This feature is available only in secure contexts (HTTPS),
                in some or all supporting browsers and mobile devices
                console.error("navigator.share", err); 
            */
        }
    }

    // something wrong or not supported navigator.share
    if (!isSupportedNavigatorShare || (isSupportedNavigatorShare && errorNavigatorShare)) {
        // playSound('newMessage');
        Swal.fire({
            background: swalBackground,
            position: 'center',
            title: 'Share the Room',
            imageAlt: 'mirotalk-share',
            imageUrl: shareUrlImg,
            html:
                `
            <br/>
            <div id="qrRoomContainer">
                <canvas id="qrRoom"></canvas>
            </div>
            <br/><br/>
            <p style="color:white;"> Share this meeting invite others to join.</p>
            <p style="color:rgb(8, 189, 89);">` +
                myRoomUrl +
                `</p>`,
            showDenyButton: true,
            showCancelButton: true,
            confirmButtonText: `Copy meeting URL`,
            denyButtonText: `Email invite`,
            cancelButtonText: `Close`,
            showClass: {
                popup: 'animate__animated animate__fadeInDown',
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOutUp',
            },
        }).then((result) => {
            if (result.isConfirmed) {
                copyRoomURL();
            } else if (result.isDenied) {
                let message = {
                    email: '',
                    subject: 'Please join our CogniMeet Video Chat Meeting',
                    body: 'Click to join: ' + myRoomUrl,
                };
                shareRoomByEmail(message);
            }
        });
        makeRoomQR();
    }
}

/**
 * Make Room QR
 * https://github.com/neocotic/qrious
 */
function makeRoomQR() {
    let qr = new QRious({
        element: getId('qrRoom'),
        value: window.location.href,
    });
    qr.set({
        size: 128,
    });
}

/**
 * Copy Room URL to clipboard
 */
function copyRoomURL() {
    let roomURL = window.location.href;
    let tmpInput = document.createElement('input');
    document.body.appendChild(tmpInput);
    tmpInput.value = roomURL;
    tmpInput.select();
    tmpInput.setSelectionRange(0, 99999);
    document.execCommand('copy');
    console.log('Copied to clipboard Join Link ', roomURL);
    document.body.removeChild(tmpInput);
    userLog('toast', 'Meeting URL is copied to clipboard 👍');
}

/**
 * Share room id by email
 * @param {*} message email | subject | body
 */
function shareRoomByEmail(message) {
    let email = message.email;
    let subject = message.subject;
    let emailBody = message.body;
    document.location = 'mailto:' + email + '?subject=' + subject + '&body=' + emailBody;
}

/**
 * Handle Audio ON - OFF
 * @param {*} e event
 * @param {*} init bool true/false
 */
function handleAudio(e, init) {
    // https://developer.mozilla.org/en-US/docs/Web/API/MediaStream/getAudioTracks
    localMediaStream.getAudioTracks()[0].enabled = !localMediaStream.getAudioTracks()[0].enabled;
    myAudioStatus = localMediaStream.getAudioTracks()[0].enabled;
    e.target.className = 'fas fa-microphone' + (myAudioStatus ? '' : '-slash');
    if (init) {
        audioBtn.className = 'fas fa-microphone' + (myAudioStatus ? '' : '-slash');
        if (!isMobileDevice) {
            tippy(initAudioBtn, {
                content: myAudioStatus ? 'Click to audio OFF' : 'Click to audio ON',
                placement: 'top',
            });
        }
    }
    setMyAudioStatus(myAudioStatus);
}

/**
 * Handle Video ON - OFF
 * @param {*} e event
 * @param {*} init bool true/false
 */
function handleVideo(e, init) {
    // https://developer.mozilla.org/en-US/docs/Web/API/MediaStream/getVideoTracks
    localMediaStream.getVideoTracks()[0].enabled = !localMediaStream.getVideoTracks()[0].enabled;
    myVideoStatus = localMediaStream.getVideoTracks()[0].enabled;
    console.log(localMediaStream.getVideoTracks()[0].enabled);
    e.target.className = 'fas fa-video' + (myVideoStatus ? '' : '-slash');
    if (init) {
        videoBtn.className = 'fas fa-video' + (myVideoStatus ? '' : '-slash');
        if (!isMobileDevice) {
            tippy(initVideoBtn, {
                content: myVideoStatus ? 'Click to video OFF' : 'Click to video ON',
                placement: 'top',
            });
        }
    }
    setMyVideoStatus(myVideoStatus);
}

/**
 * SwapCamera front (user) - rear (environment)
 */
function swapCamera() {
    // setup camera
    camera = camera == 'user' ? 'environment' : 'user';
    if (camera == 'user') useVideo = true;
    else useVideo = { facingMode: { exact: camera } };

    // some devices can't swap the cam, if have Video Track already in execution.
    if (useVideo) stopLocalVideoTrack();

    // https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia
    navigator.mediaDevices
        .getUserMedia({ video: useVideo })
        .then((camStream) => {
            refreshMyStreamToPeers(camStream);
            refreshMyLocalStream(camStream);
            if (useVideo) setMyVideoStatusTrue();
            myVideo.classList.toggle('mirror');
        })
        .catch((err) => {
            console.log('[Error] to swaping camera', err);
            userLog('error', 'Error to swaping the camera ' + err);
            // https://blog.addpipe.com/common-getusermedia-errors/
        });
}

/**
 * Stop Local Video Track
 */
function stopLocalVideoTrack() {
    localMediaStream.getVideoTracks()[0].stop();
}

/**
 * Stop Local Audio Track
 */
function stopLocalAudioTrack() {
    localMediaStream.getAudioTracks()[0].stop();
}

/**
 * Enable - disable screen sharing
 */
function toggleScreenSharing() {
    screenMaxFrameRate = parseInt(screenFpsSelect.value);
    const constraints = {
        video: { frameRate: { max: screenMaxFrameRate } },
    }; // true | { frameRate: { max: screenMaxFrameRate } }

    let screenMediaPromise;
    let isVideoOff = false;
    if ((localMediaStream.getVideoTracks()[0].enabled = false)) {
        isVideoOff = true;
    }

    if (!isScreenStreaming) {
        // on screen sharing start
        // https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getDisplayMedia
        screenMediaPromise = navigator.mediaDevices.getDisplayMedia(constraints);
    } else {
        // on screen sharing stop
        screenMediaPromise = navigator.mediaDevices.getUserMedia(getAudioVideoConstraints());
        if (isStreamRecording) stopStreamRecording();
        localMediaStream.getVideoTracks()[0].enabled = false;
    }
    screenMediaPromise
        .then((screenStream) => {
            // stop cam video track on screen share
            localMediaStream.getVideoTracks()[0].enabled = true;
            stopLocalVideoTrack();
            isScreenStreaming = !isScreenStreaming;
            refreshMyStreamToPeers(screenStream);
            refreshMyLocalStream(screenStream);
            myVideo.classList.toggle('mirror');
            setScreenSharingStatus(isScreenStreaming);
        })
        .catch((err) => {
            if (isVideoOff) {
                localMediaStream.getVideoTracks()[0].enabled = false;
            }
            console.error('[Error] Unable to share the screen', err);
            userLog('error', 'Unable to share the screen ' + err);
        });
}

/**
 * Set Screen Sharing Status
 * @param {*} status
 */
function setScreenSharingStatus(status) {
    screenShareBtn.className = status ? 'fas fa-stop-circle' : 'fas fa-desktop';
    // only for desktop
    if (!isMobileDevice) {
        tippy(screenShareBtn, {
            content: status ? 'STOP screen sharing' : 'START screen sharing',
            placement: 'right-start',
        });
    }
}

/**
 * set myVideoStatus true
 */
function setMyVideoStatusTrue() {
    if (myVideoStatus) return;
    // Put video status alredy ON
    localMediaStream.getVideoTracks()[0].enabled = true;
    myVideoStatus = true;
    videoBtn.className = 'fas fa-video';
    myVideoStatusIcon.className = 'fas fa-video';
    // myVideoAvatarImage.style.display = 'none';
    emitPeerStatus('video', myVideoStatus);
    // only for desktop
    if (!isMobileDevice) {
        tippy(videoBtn, {
            content: 'Click to video OFF',
            placement: 'right-start',
        });
    }
}

/**
 * Enter - esc on full screen mode
 * https://developer.mozilla.org/en-US/docs/Web/API/Fullscreen_API
 */

/*
function toggleFullScreen() {
    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen();
        isDocumentOnFullScreen = true;
    } else {
        if (document.exitFullscreen) {
            document.exitFullscreen();
            isDocumentOnFullScreen = false;
        }
    }
    // only for desktop
    if (!isMobileDevice) {
        tippy(fullScreenBtn, {
            content: isDocumentOnFullScreen ? 'EXIT full screen' : 'VIEW full screen',
            placement: 'right-start',
        });
    }
}
*/

/**
 * Refresh my stream changes to connected peers in the room
 * @param {*} stream
 * @param {*} localAudioTrackChange true or false(default)
 */
function refreshMyStreamToPeers(stream, localAudioTrackChange = false) {
    if (!thereIsPeerConnections()) return;

    // refresh my stream to peers
    for (let peer_id in peerConnections) {
        // https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/getSenders
        let videoSender = peerConnections[peer_id]
            .getSenders()
            .find((s) => (s.track ? s.track.kind === 'video' : false));
        // https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender/replaceTrack
        videoSender.replaceTrack(stream.getVideoTracks()[0]);

        if (localAudioTrackChange) {
            let audioSender = peerConnections[peer_id]
                .getSenders()
                .find((s) => (s.track ? s.track.kind === 'audio' : false));
            // https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender/replaceTrack
            audioSender.replaceTrack(stream.getAudioTracks()[0]);
        }
    }
}

/**
 * Refresh my local stream
 * @param {*} stream
 * @param {*} localAudioTrackChange true or false(default)
 */
function refreshMyLocalStream(stream, localAudioTrackChange = false) {
    stream.getVideoTracks()[0].enabled = true;

    // enable audio
    if (localAudioTrackChange && myAudioStatus === false) {
        audioBtn.className = 'fas fa-microphone';
        setMyAudioStatus(true);
        myAudioStatus = true;
    }

    // https://developer.mozilla.org/en-US/docs/Web/API/MediaStream
    const newStream = new MediaStream([
        stream.getVideoTracks()[0],
        localAudioTrackChange ? stream.getAudioTracks()[0] : localMediaStream.getAudioTracks()[0],
    ]);
    localMediaStream = newStream;

    // log newStream devices
    logStreamSettingsInfo('refreshMyLocalStream', localMediaStream);

    // attachMediaStream is a part of the adapter.js library
    attachMediaStream(myVideo, localMediaStream); // newstream

    // on toggleScreenSharing video stop
    stream.getVideoTracks()[0].onended = () => {
        if (isScreenStreaming) toggleScreenSharing();
    };

    /**
     * When you stop the screen sharing, on default i turn back to the webcam with video stream ON.
     * If you want the webcam with video stream OFF, just disable it with the button (click to video OFF),
     * before to stop the screen sharing.
     */
    if (myVideoStatus === false) localMediaStream.getVideoTracks()[0].enabled = false;
}

/**
 * Start recording time
 */
function startRecordingTime() {
    recStartTime = Date.now();
    let rc = setInterval(function printTime() {
        if (isStreamRecording) {
            recElapsedTime = Date.now() - recStartTime;
            myVideoParagraph.innerHTML = myPeerName + '&nbsp;&nbsp; 🔴 REC ' + getTimeToString(recElapsedTime);
            return;
        }
        clearInterval(rc);
    }, 1000);
}

/**
 * Get MediaRecorder MimeTypes
 * @returns mimeType
 */
function getSupportedMimeTypes() {
    const possibleTypes = [
        'video/webm;codecs=vp9,opus',
        'video/webm;codecs=vp8,opus',
        'video/webm;codecs=h264,opus',
        'video/mp4;codecs=h264,aac',
        'video/mp4',
    ];
    return possibleTypes.filter((mimeType) => {
        return MediaRecorder.isTypeSupported(mimeType);
    });
}

/**
 * Start Recording
 * https://github.com/webrtc/samples/tree/gh-pages/src/content/getusermedia/record
 */
function startStreamRecording() {
    recordedBlobs = [];
    let options = getSupportedMimeTypes();
    console.log('MediaRecorder options supported', options);
    options = { mimeType: options[0] }; // select the first available as mimeType video types etc

    try {
        // record only my local Media Stream
        mediaRecorder = new MediaRecorder(localMediaStream, options);
        //console.log('Created MediaRecorder', mediaRecorder, 'with options', options);
        mediaRecorder.start();
    } catch (err) {
        console.error('Exception while creating MediaRecorder: ', err);
        userLog('error', "Can't start stream recording: " + err);
        return;
    }

    mediaRecorder.onstart = (event) => {
        //console.log('MediaRecorder started: ', event);
        isStreamRecording = true;
        recordStreamBtn.style.setProperty('background-color', 'red');
        startRecordingTime();
        disableElements(true);
        // only for desktop
        if (!isMobileDevice) {
            tippy(recordStreamBtn, {
                content: 'STOP recording',
                placement: 'right-start',
            });
        }
    };

    mediaRecorder.ondataavailable = (event) => {
        //console.log('MediaRecorder data: ', event);
        if (event.data && event.data.size > 0) recordedBlobs.push(event.data);
        console.log(recordedBlobs);
    };

    mediaRecorder.onstop = (event) => {
        console.log('MediaRecorder stopped: ', event);
        console.log('MediaRecorder Blobs: ', recordedBlobs);
        myVideoParagraph.innerHTML = myPeerName + ' (me)';
        isStreamRecording = false;
        setRecordButtonUi();
        disableElements(false);
        downloadRecordedStream();
        // only for desktop
        if (!isMobileDevice) {
            tippy(recordStreamBtn, {
                content: 'START recording',
                placement: 'right-start',
            });
        }
    };
}

/**
 * Stop recording
 */
function stopStreamRecording() {
    mediaRecorder.stop();
}

/**
 * Set Record Button UI on change theme
 */
function setRecordButtonUi() {
    recordStreamBtn.style.setProperty('background-color', 'black');
    //if (mirotalkTheme == 'ghost') recordStreamBtn.style.setProperty('background-color', 'transparent');
}

/**
 * Download recorded stream
 */
function downloadRecordedStream() {
    try {
        const type = recordedBlobs[0].type.includes('mp4') ? 'mp4' : 'webm';
        const blob = new Blob(recordedBlobs, { type: 'video/' + type });
        const recFileName = getDataTimeString() + '-REC.' + type;
        const currentDevice = isMobileDevice ? 'MOBILE' : 'PC';
        const blobFileSize = bytesToSize(blob.size);

        userLog(
            'success-html',
            `<div style="text-align: left;">
                🔴 Recording Info <br/>
                FILE: ${recFileName} <br/>
                SIZE: ${blobFileSize} <br/>
                Please wait to be processed, then will be downloaded to your ${currentDevice} device.
            </div>`,
        );
        //blob contains all the video data.
        saveFileFromBlob(blob, recFileName);
    } catch (err) {
        userLog('error', 'Recording save failed: ' + err);
    }
}

/**
 * Disable - enable some elements on Recording. I can Record One Media Stream at time
 * @param {*} b boolean true/false
 */
function disableElements(b) {
    swapCameraBtn.disabled = b;
    screenShareBtn.disabled = b;
    audioSource.disabled = b;
    videoSource.disabled = b;
    videoQualitySelect.disabled = b;
    // FireFox not support set video Fps make it always disabled
    videoFpsSelect.disabled = myBrowserName === 'Firefox' ? true : b;
    // Mobile devices not support screen sharing so disable it always
    screenFpsSelect.disabled = isMobileDevice ? true : b;
}

/**
 * Create Chat Room Data Channel
 * @param {*} peer_id
 */
function createChatDataChannel(peer_id) {
    chatDataChannels[peer_id] = peerConnections[peer_id].createDataChannel('mirotalk_chat_channel');
    console.log('chatDataChannels created', chatDataChannels);
}

/**
 * Set the chat room on full screen mode for mobile
 */
function setChatRoomForMobile() {
    if (isMobileDevice) {
        document.documentElement.style.setProperty('--msger-height', '99%');
        document.documentElement.style.setProperty('--msger-width', '99%');
    } else {
        // make chat room draggable for desktop
        dragElement(msgerDraggable, msgerHeader);
    }
}

/**
 * Show msger draggable on center screen position
 */
function showChatRoomDraggable() {
    // playSound('newMessage');
    if (isMobileDevice) {
        leftButtons.style.display = 'none';
        isButtonsVisible = false;
    }
    /*chatRoomBtn.className = 'fas fa-comment-slash';*/
    function myFunction(x) {
        if (x.matches) {
            msgerDraggable.style.top = '50%';
            msgerDraggable.style.left = '50%';
            msgerDraggable.style.display = 'flex';
        } else {
            msgerDraggable.style.top = '50%';
            msgerDraggable.style.right = '-150px';
            msgerDraggable.style.display = 'flex';
        }
    }

    var x = window.matchMedia('(max-width: 700px)');
    myFunction(x);
    x.addListener(myFunction);
    isChatRoomVisible = true;
    // only for desktop
    if (!isMobileDevice) {
        tippy(chatRoomBtn, {
            content: 'CLOSE the chat',
            placement: 'right-start',
        });
    }
}

/**
 * Clean chat messages
 */
function cleanMessages() {
    Swal.fire({
        background: swalBackground,
        position: 'center',
        title: 'Clean up chat Messages?',
        imageUrl: deleteImg,
        showDenyButton: true,
        confirmButtonText: `Yes`,
        denyButtonText: `No`,
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
    }).then((result) => {
        // clean chat messages
        if (result.isConfirmed) {
            let msgs = msgerChat.firstChild;
            while (msgs) {
                msgerChat.removeChild(msgs);
                msgs = msgerChat.firstChild;
            }
            // clean object
            chatMenpssages = [];
        }
    });
}

/**
 * Hide chat room and emoji picker
 */
function hideChatRoomAndEmojiPicker() {
    msgerDraggable.style.display = 'none';
    msgerEmojiPicker.style.display = 'none';
    /*chatRoomBtn.className = 'fas fa-comment';*/
    isChatRoomVisible = false;
    isChatEmojiVisible = false;
    // only for desktop
    if (!isMobileDevice) {
        tippy(chatRoomBtn, {
            content: 'OPEN the chat',
            placement: 'right-start',
        });
    }
}

/**
 * Send Chat messages to peers in the room
 */
function sendChatMessage() {
    if (!thereIsPeerConnections()) {
        userLog('info', "Can't send message, no participants in the room");
        msgerInput.value = '';
        return;
    }

    const msg = msgerInput.value;
    // empity msg or
    if (!msg) return;

    emitMsg(myPeerName, 'toAll', msg, false);
    appendMessage(myPeerName, rightChatAvatar, 'right', msg, false);
    msgerInput.value = '';
}

/**
 * handle Incoming Data Channel Chat Messages
 * @param {*} dataMessage
 */
function handleDataChannelChat(dataMessage) {
    if (!dataMessage) return;

    let msgFrom = dataMessage.from;
    let msgTo = dataMessage.to;
    let msg = dataMessage.msg;
    let msgPrivate = dataMessage.privateMsg;

    // private message but not for me return
    if (msgPrivate && msgTo != myPeerName) return;

    console.log('handleDataChannelChat', dataMessage);
    // chat message for me also
    if (!isChatRoomVisible) {
        showChatRoomDraggable();
        /*chatRoomBtn.className = 'fas fa-comment-slash';*/
    }
    playSound('chatMessage');
    setPeerChatAvatarImgName('left', msgFrom);
    appendMessage(msgFrom, leftChatAvatar, 'left', msg, msgPrivate);
}

/**
 * Escape Special Chars
 * @param {*} regex
 */
function escapeSpecialChars(regex) {
    return regex.replace(/([()[{*+.$^\\|?])/g, '\\$1');
}

/**
 * Append Message to msger chat room
 * @param {*} from
 * @param {*} img
 * @param {*} side
 * @param {*} msg
 * @param {*} privateMsg
 */
function appendMessage(from, img, side, msg, privateMsg) {
    let time = getFormatDate(new Date());
    // collect chat msges to save it later
    chatMessages.push({
        time: time,
        from: from,
        msg: msg,
        privateMsg: privateMsg,
    });

    // check if i receive a private message
    let msgBubble = privateMsg ? 'private-msg-bubble' : 'msg-bubble';

    // console.log("chatMessages", chatMessages);
    let cMsg = detectUrl(msg);
    const msgHTML = `
	<div class="msg ${side}-msg">
		<div class="msg-img" style="background-image: url('${img}')"></div>
		<div class=${msgBubble}>
            <div class="msg-info">
                <div class="msg-info-name">${from}</div>
                <div class="msg-info-time">${time}</div>
            </div>
            <div class="msg-text">${cMsg}</div>
        </div>
	</div>
    `;
    msgerChat.insertAdjacentHTML('beforeend', msgHTML);
    msgerChat.scrollTop += 500;
}

/**
 * Add participants in the chat room lists
 * @param {*} peers
 */
function msgerAddPeers(peers) {
    // console.log("peers", peers);
    // add all current Participants
    for (let peer_id in peers) {
        let peer_name = peers[peer_id]['peer_name'];
        // bypass insert to myself in the list :)
        if (peer_name != myPeerName) {
            let exsistMsgerPrivateDiv = getId(peer_id + '_pMsgDiv');
            // if there isn't add it....
            if (!exsistMsgerPrivateDiv) {
                let msgerPrivateDiv = `
                <div id="${peer_id}_pMsgDiv" class="msger-peer-inputarea">
                    <input
                        id="${peer_id}_pMsgInput"
                        class="msger-input"
                        type="text"
                        placeholder="Enter your message..."
                    />
                    <button id="${peer_id}_pMsgBtn" class="fas fa-paper-plane" value="${peer_name}">&nbsp;${peer_name}</button>
                </div>
                `;
                msgerCPList.insertAdjacentHTML('beforeend', msgerPrivateDiv);
                msgerCPList.scrollTop += 500;

                let msgerPrivateMsgInput = getId(peer_id + '_pMsgInput');
                let msgerPrivateBtn = getId(peer_id + '_pMsgBtn');
                addMsgerPrivateBtn(msgerPrivateBtn, msgerPrivateMsgInput);
            }
        }
    }
}

/**
 * Search peer by name in chat room lists to send the private messages
 */
function searchPeer() {
    let searchPeerBarName = getId('searchPeerBarName').value;
    let msgerPeerInputarea = getEcN('msger-peer-inputarea');
    searchPeerBarName = searchPeerBarName.toLowerCase();
    for (let i = 0; i < msgerPeerInputarea.length; i++) {
        if (!msgerPeerInputarea[i].innerHTML.toLowerCase().includes(searchPeerBarName)) {
            msgerPeerInputarea[i].style.display = 'none';
        } else {
            msgerPeerInputarea[i].style.display = 'flex';
        }
    }
}

/**
 * Remove participant from chat room lists
 * @param {*} peer_id
 */
function msgerRemovePeer(peer_id) {
    let msgerPrivateDiv = getId(peer_id + '_pMsgDiv');
    if (msgerPrivateDiv) {
        let peerToRemove = msgerPrivateDiv.firstChild;
        while (peerToRemove) {
            msgerPrivateDiv.removeChild(peerToRemove);
            peerToRemove = msgerPrivateDiv.firstChild;
        }
        msgerPrivateDiv.remove();
    }
}

/**
 * Setup msger buttons to send private messages
 * @param {*} msgerPrivateBtn
 * @param {*} msgerPrivateMsgInput
 */
function addMsgerPrivateBtn(msgerPrivateBtn, msgerPrivateMsgInput) {
    // add button to send private messages
    msgerPrivateBtn.addEventListener('click', (e) => {
        e.preventDefault();
        let pMsg = msgerPrivateMsgInput.value;
        if (!pMsg) return;
        let toPeerName = msgerPrivateBtn.value;
        emitMsg(myPeerName, toPeerName, pMsg, true);
        appendMessage(myPeerName, rightChatAvatar, 'right', pMsg + '<br/><hr>Private message to ' + toPeerName, true);
        msgerPrivateMsgInput.value = '';
        msgerCP.style.display = 'none';
    });
}

/**
 * Detect url from text and make it clickable
 * Detect also if url is a img to create preview of it
 * @param {*} text
 * @returns html
 */
function detectUrl(text) {
    let urlRegex = /(https?:\/\/[^\s]+)/g;
    return text.replace(urlRegex, (url) => {
        if (isImageURL(text)) return '<p><img src="' + url + '" alt="img" width="200" height="auto"/></p>';
        return '<a id="chat-msg-a" href="' + url + '" target="_blank">' + url + '</a>';
    });
}

/**
 * Check if url passed is a image
 * @param {*} url
 * @returns true/false
 */
function isImageURL(url) {
    return url.match(/\.(jpeg|jpg|gif|png|tiff|bmp)$/) != null;
}

/**
 * Format data h:m:s
 * @param {*} date
 */
function getFormatDate(date) {
    const time = date.toTimeString().split(' ')[0];
    return `${time}`;
}

/**
 * Send message over Secure dataChannels
 * @param {*} from
 * @param {*} to
 * @param {*} msg
 * @param {*} privateMsg true/false
 */
function emitMsg(from, to, msg, privateMsg) {
    if (!msg) return;

    let chatMessage = {
        from: from,
        to: to,
        msg: msg,
        privateMsg: privateMsg,
    };
    console.log('Send msg', chatMessage);

    // Send chat msg through RTC Data Channels
    for (let peer_id in chatDataChannels) {
        if (chatDataChannels[peer_id].readyState === 'open')
            chatDataChannels[peer_id].send(JSON.stringify(chatMessage));
    }
}

/**
 * Hide - Show emoji picker div
 */
function hideShowEmojiPicker() {
    if (!isChatEmojiVisible) {
        // playSound('newMessage');
        msgerEmojiPicker.style.display = 'block';
        isChatEmojiVisible = true;
        return;
    }
    msgerEmojiPicker.style.display = 'none';
    isChatEmojiVisible = false;
}

/**
 * Download Chat messages in json format
 * https://developer.mozilla.org/it/docs/Web/JavaScript/Reference/Global_Objects/JSON/stringify
 */
function downloadChatMsgs() {
    let a = document.createElement('a');
    a.href = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(chatMessages, null, 1));
    a.download = getDataTimeString() + '-CHAT.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

/**
 * Hide - show my settings
 */
function hideShowMySettings() {
    if (!isMySettingsVisible) {
        // playSound('newMessage');
        // adapt it for mobile
        if (isMobileDevice) {
            mySettings.style.setProperty('width', '90%');
            document.documentElement.style.setProperty('--mySettings-select-w', '99%');
        }
        // my current peer name
        myPeerNameSet.placeholder = myPeerName;
        // center screen on show
        mySettings.style.top = '50%';
        mySettings.style.left = '50%';
        mySettings.style.display = 'block';
        isMySettingsVisible = true;
        return;
    }
    mySettings.style.display = 'none';
    isMySettingsVisible = false;
}

/**
 * Handle html tab settings
 * https://www.w3schools.com/howto/howto_js_tabs.asp
 *
 * @param {*} evt
 * @param {*} tabName
 */
function openTab(evt, tabName) {
    let i, tabcontent, tablinks;
    tabcontent = getEcN('tabcontent');
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = 'none';
    }
    tablinks = getEcN('tablinks');
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(' active', '');
    }
    getId(tabName).style.display = 'block';
    evt.currentTarget.className += ' active';
}

/**
 * Update myPeerName to other peers in the room
 */
function updateMyPeerName() {
    let myNewPeerName = myPeerNameSet.value;
    let myOldPeerName = myPeerName;

    // myNewPeerName empty
    if (!myNewPeerName) return;

    myPeerName = myNewPeerName;
    myVideoParagraph.innerHTML = myPeerName + ' (me)';

    signalingSocket.emit('peerName', {
        peerConnections: peerConnections,
        room_id: roomId,
        peer_name_old: myOldPeerName,
        peer_name_new: myPeerName,
    });

    myPeerNameSet.value = '';
    myPeerNameSet.placeholder = myPeerName;

    // setPeerAvatarImgName('myVideoAvatarImage', myPeerName);
    setPeerChatAvatarImgName('right', myPeerName);
    userLog('toast', 'My name changed to ' + myPeerName);
}

/**
 * Append updated peer name to video player
 * @param {*} config
 */
function handlePeerName(config) {
    let peer_id = config.peer_id;
    let peer_name = config.peer_name;
    let videoName = getId(peer_id + '_name');
    if (videoName) videoName.innerHTML = peer_name;
    // change also btn value - name on chat lists....
    let msgerPeerName = getId(peer_id + '_pMsgBtn');
    if (msgerPeerName) {
        msgerPeerName.innerHTML = `&nbsp;${peer_name}`;
        msgerPeerName.value = peer_name;
    }
    // refresh also peer video avatar name
    setPeerAvatarImgName(peer_id + '_avatar', peer_name);
}

/**
 * Send my Video-Audio-Hand... status
 * @param {*} element
 * @param {*} status
 */
function emitPeerStatus(element, status) {
    signalingSocket.emit('peerStatus', {
        peerConnections: peerConnections,
        room_id: roomId,
        peer_name: myPeerName,
        element: element,
        status: status,
    });
}

/**
 * Set my Hand Status and Icon
 */
function setMyHandStatus() {
    if (myHandStatus) {
        // Raise hand
        myHandStatus = false;
        if (!isMobileDevice) {
            tippy(myHandBtn, {
                content: 'RAISE your hand',
                placement: 'right-start',
            });
        }
    } else {
        // Lower hand
        myHandStatus = true;
        if (!isMobileDevice) {
            tippy(myHandBtn, {
                content: 'LOWER your hand',
                placement: 'right-start',
            });
        }
        playSound('raiseHand');
    }
    myHandStatusIcon.style.display = myHandStatus ? 'inline' : 'none';
    emitPeerStatus('hand', myHandStatus);
}

/**
 * Set My Audio Status Icon and Title
 * @param {*} status
 */
function setMyAudioStatus(status) {
    myAudioStatusIcon.className = 'fas fa-microphone' + (status ? '' : '-slash');
    // send my audio status to all peers in the room
    emitPeerStatus('audio', status);
    tippy(myAudioStatusIcon, {
        content: status ? 'My audio is ON' : 'My audio is OFF',
    });
    // only for desktop
    if (!isMobileDevice) {
        tippy(audioBtn, {
            content: status ? 'Click to audio OFF' : 'Click to audio ON',
            placement: 'right-start',
        });
    }
}

/**
 * Set My Video Status Icon and Title
 * @param {*} status
 */
function setMyVideoStatus(status) {
    // on vdeo OFF display my video avatar name
    // myVideoAvatarImage.style.display = status ? 'none' : 'block';
    myVideoStatusIcon.className = 'fas fa-video' + (status ? '' : '-slash');
    // send my video status to all peers in the room
    emitPeerStatus('video', status);
    tippy(myVideoStatusIcon, {
        content: status ? 'My video is ON' : 'My video is OFF',
    });
    // only for desktop
    if (!isMobileDevice) {
        tippy(videoBtn, {
            content: status ? 'Click to video OFF' : 'Click to video ON',
            placement: 'right-start',
        });
    }
}

/**
 * Handle peer audio - video - hand status
 * @param {*} config
 */
function handlePeerStatus(config) {
    //
    let peer_id = config.peer_id;
    let peer_name = config.peer_name;
    let element = config.element;
    let status = config.status;

    switch (element) {
        case 'video':
            setPeerVideoStatus(peer_id, status);
            break;
        case 'audio':
            setPeerAudioStatus(peer_id, status);
            break;
        case 'hand':
            setPeerHandStatus(peer_id, peer_name, status);
            break;
    }
}

/**
 * Set Participant Hand Status Icon and Title
 * @param {*} peer_id
 * @param {*} peer_name
 * @param {*} status
 */
function setPeerHandStatus(peer_id, peer_name, status) {
    let peerHandStatus = getId(peer_id + '_handStatus');
    peerHandStatus.style.display = status ? 'block' : 'none';
    if (status) {
        userLog('toast', peer_name + ' has raised the hand');
        playSound('raiseHand');
    }
}

/**
 * Set Participant Audio Status Icon and Title
 * @param {*} peer_id
 * @param {*} status
 */
function setPeerAudioStatus(peer_id, status) {
    let peerAudioStatus = getId(peer_id + '_audioStatus');
    peerAudioStatus.className = 'fas fa-microphone' + (status ? '' : '-slash');
    tippy(peerAudioStatus, {
        content: status ? 'Participant audio is ON' : 'Participant audio is OFF',
    });
}

/**
 * Set Participant Video Status Icon and Title
 * @param {*} peer_id
 * @param {*} status
 */
function setPeerVideoStatus(peer_id, status) {
    let peerVideoAvatarImage = getId(peer_id + '_avatar');
    let peerVideoStatus = getId(peer_id + '_videoStatus');
    peerVideoStatus.className = 'fas fa-video' + (status ? '' : '-slash');
    peerVideoAvatarImage.style.display = status ? 'none' : 'block';
    tippy(peerVideoStatus, {
        content: status ? 'Participant video is ON' : 'Participant video is OFF',
    });
}

/**
 * Emit actions to all peers in the same room except yourself
 * @param {*} peerAction muteEveryone hideEveryone ...
 */
function emitPeerAction(peerAction) {
    signalingSocket.emit('peerAction', {
        peerConnections: peerConnections,
        room_id: roomId,
        peer_name: myPeerName,
        peer_action: peerAction,
    });
}

/**
 * Handle received peer actions
 * @param {*} config
 */
function handlePeerAction(config) {
    let peer_name = config.peer_name;
    let peer_action = config.peer_action;

    switch (peer_action) {
        case 'muteEveryone':
            setMyAudioOff(peer_name);
            break;
        case 'hideEveryone':
            setMyVideoOff(peer_name);
            break;
    }
}

/**
 * Set my Audio off and Popup the peer name that performed this action
 */
function setMyAudioOff() {
    if (myAudioStatus === false) return;
    localMediaStream.getAudioTracks()[0].enabled = false;
    myAudioStatus = localMediaStream.getAudioTracks()[0].enabled;
    audioBtn.className = 'fas fa-microphone-slash';
    setMyAudioStatus(myAudioStatus);
    userLog('toast', peer_name + ' has disabled your audio');
}

/**
 * Set my Video off and Popup the peer name that performed this action
 */
function setMyVideoOff(peer_name) {
    if (myVideoStatus === false) return;
    localMediaStream.getVideoTracks()[0].enabled = false;
    myVideoStatus = localMediaStream.getVideoTracks()[0].enabled;
    videoBtn.className = 'fas fa-video-slash';
    setMyVideoStatus(myVideoStatus);
    userLog('toast', peer_name + ' has disabled your video');
}

/**
 * Mute or Hide everyone except yourself
 * @param {*} element audio/video
 */
function disableAllPeers(element) {
    if (!thereIsPeerConnections()) {
        userLog('info', 'No participants detected');
        return;
    }
    Swal.fire({
        background: swalBackground,
        position: 'center',
        imageUrl: element == 'audio' ? audioOffImg : camOffImg,
        title: element == 'audio' ? 'Mute everyone except yourself?' : 'Hide everyone except yourself?',
        text:
            element == 'audio'
                ? "Once muted, you won't be able to unmute them, but they can unmute themselves at any time."
                : "Once hided, you won't be able to unhide them, but they can unhide themselves at any time.",
        showDenyButton: true,
        confirmButtonText: element == 'audio' ? `Mute` : `Hide`,
        denyButtonText: `Cancel`,
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
    }).then((result) => {
        if (result.isConfirmed) {
            switch (element) {
                case 'audio':
                    userLog('toast', 'Mute everyone 👍');
                    emitPeerAction('muteEveryone');
                    break;
                case 'video':
                    userLog('toast', 'Hide everyone 👍');
                    emitPeerAction('hideEveryone');
                    break;
            }
        }
    });
}

/**
 * Lock Unlock the room from unauthorized access
 */
function lockUnlockRoom() {
    lockUnlockRoomBtn.className = roomLocked ? 'fas fa-lock-open' : 'fas fa-lock';

    if (roomLocked) {
        roomLocked = false;
        emitRoomStatus();
    } else {
        roomLocked = true;
        emitRoomStatus();
        playSound('locked');
    }
}

/**
 * Refresh Room Status (Locked/Unlocked)
 */
function emitRoomStatus() {
    let rStatus = roomLocked ? '🔒 LOCKED the room, no one can access!' : '🔓 UNLOCKED the room';
    userLog('toast', rStatus);

    signalingSocket.emit('roomStatus', {
        peerConnections: peerConnections,
        room_id: roomId,
        room_locked: roomLocked,
        peer_name: myPeerName,
    });
}

/**
 * Handle Room Status (Lock - Unlock)
 * @param {*} config
 */
function handleRoomStatus(config) {
    let peer_name = config.peer_name;
    let room_locked = config.room_locked;
    roomLocked = room_locked;
    lockUnlockRoomBtn.className = roomLocked ? 'fas fa-lock' : 'fas fa-lock-open';
    userLog('toast', peer_name + ' set room is locked to ' + roomLocked);
}

/**
 * Room is Locked can't access...
 */
function handleRoomLocked() {
    playSound('kickedOut');

    Swal.fire({
        allowOutsideClick: false,
        background: swalBackground,
        position: 'center',
        imageUrl: roomLockedImg,
        title: 'Oops, Room Locked',
        text: 'The room is locked, try with another one.',
        showDenyButton: false,
        confirmButtonText: `Ok`,
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
    }).then((result) => {
        if (result.isConfirmed) window.location.href = '/newcall';
    });
}

/**
 * Handle whiteboard events
 * @param {*} config
 */
function handleWhiteboard(config) {
    //
    let peer_name = config.peer_name;
    let act = config.act;

    if (isMobileDevice) return;
    switch (act) {
        case 'draw':
            drawRemote(config);
            break;
        case 'clean':
            userLog('toast', peer_name + ' has cleaned the board');
            whiteboardClean();
            break;
        case 'open':
            userLog('toast', peer_name + ' has opened the board');
            whiteboardOpen();
            break;
        case 'close':
            userLog('toast', peer_name + ' has closed the board');
            whiteboardClose();
            break;
        case 'resize':
            userLog('toast', peer_name + ' has resized the board');
            whiteboardResize();
            break;
    }
}

/**
 * Whiteboard draggable
 */
function setWhiteboardDraggable() {
    dragElement(whiteboardCont, whiteboardHeader);
}

/**
 * Whiteboard Open
 */
function whiteboardOpen() {
    if (!isWhiteboardVisible) {
        setWhiteboardDraggable();
        setColor('#ffffff'); // color picker
        whiteboardCont.style.top = '50%';
        whiteboardCont.style.left = '50%';
        whiteboardCont.style.display = 'block';
        isWhiteboardVisible = true;
        drawsize = 3;
        fitToContainer(canvas);
        tippy(whiteboardBtn, {
            content: 'CLOSE the whiteboard',
            placement: 'right-start',
        });
        // playSound('newMessage');
    }
}

/**
 * Whiteboard close
 */
function whiteboardClose() {
    if (isWhiteboardVisible) {
        whiteboardCont.style.display = 'none';
        isWhiteboardVisible = false;
        tippy(whiteboardBtn, {
            content: 'OPEN the whiteboard',
            placement: 'right-start',
        });
    }
}

/**
 * Whiteboard resize
 */
function whiteboardResize() {
    let content;
    whiteboardCont.style.top = '50%';
    whiteboardCont.style.left = '50%';
    if (isWhiteboardFs) {
        document.documentElement.style.setProperty('--wb-width', '800px');
        document.documentElement.style.setProperty('--wb-height', '600px');
        fitToContainer(canvas);
        whiteboardFsBtn.className = 'fas fa-expand-alt';
        content = 'VIEW full screen';
        isWhiteboardFs = false;
    } else {
        document.documentElement.style.setProperty('--wb-width', '99%');
        document.documentElement.style.setProperty('--wb-height', '99%');
        fitToContainer(canvas);
        whiteboardFsBtn.className = 'fas fa-compress-alt';
        content = 'EXIT full screen';
        isWhiteboardFs = true;
    }
    tippy(whiteboardFsBtn, {
        content: content,
        placement: 'bottom',
    });
}

/**
 * Whiteboard clean
 */
function whiteboardClean() {
    if (isWhiteboardVisible) ctx.clearRect(0, 0, canvas.width, canvas.height);
}

/**
 * Set whiteboard color
 * @param {*} newcolor
 */
function setColor(newcolor) {
    color = newcolor;
    drawsize = 3;
    whiteboardColorPicker.value = color;
}

/**
 * Whiteboard eraser
 */
function setEraser() {
    color = '#000000';
    drawsize = 25;
    whiteboardColorPicker.value = color;
}

/**
 * Clean whiteboard content
 */
function confirmCleanBoard() {
    // playSound('newMessage');

    Swal.fire({
        background: swalBackground,
        position: 'center',
        title: 'Clean the board',
        text: 'Are you sure you want to clean the board?',
        showDenyButton: true,
        confirmButtonText: `Yes`,
        denyButtonText: `No`,
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
    }).then((result) => {
        if (result.isConfirmed) {
            whiteboardClean();
            remoteWbAction('clean');
        }
    });
}

/**
 * Draw on whiteboard
 * @param {*} newx
 * @param {*} newy
 * @param {*} oldx
 * @param {*} oldy
 */
function draw(newx, newy, oldx, oldy) {
    ctx.strokeStyle = color;
    ctx.lineWidth = drawsize;
    ctx.beginPath();
    ctx.moveTo(oldx, oldy);
    ctx.lineTo(newx, newy);
    ctx.stroke();
    ctx.closePath();
}

/**
 * Draw Remote whiteboard
 * @param {*} config draw coordinates, color and size
 */
function drawRemote(config) {
    if (!isWhiteboardVisible) return;

    ctx.strokeStyle = config.color;
    ctx.lineWidth = config.size;
    ctx.beginPath();
    ctx.moveTo(config.prevx, config.prevy);
    ctx.lineTo(config.newx, config.newy);
    ctx.stroke();
    ctx.closePath();
}

/**
 * Resize canvas
 * @param {*} canvas
 */
function fitToContainer(canvas) {
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
}

/**
 * Handle whiteboard on windows resize, here i lose drawing, Todo fix it
 */
function reportWindowSize() {
    fitToContainer(canvas);
}
/**
 * Whiteboard setup
 */
function setupCanvas() {
    fitToContainer(canvas);

    canvas.addEventListener('mousedown', (e) => {
        x = e.offsetX;
        y = e.offsetY;
        isDrawing = true;
    });
    canvas.addEventListener('mousemove', (e) => {
        if (!isDrawing) return;

        draw(e.offsetX, e.offsetY, x, y);
        // send draw to other peers in the room
        if (thereIsPeerConnections()) {
            signalingSocket.emit('wb', {
                peerConnections: peerConnections,
                peer_name: myPeerName,
                act: 'draw',
                newx: e.offsetX,
                newy: e.offsetY,
                prevx: x,
                prevy: y,
                color: color,
                size: drawsize,
            });
        }
        x = e.offsetX;
        y = e.offsetY;
    });
    canvas.addEventListener('mouseup', (e) => {
        if (isDrawing) isDrawing = false;
    });

    window.onresize = reportWindowSize;
}

/**
 * Save whiteboard canvas to file as png
 */
function saveWbCanvas() {
    // Improve it if erase something...
    let link = document.createElement('a');
    link.download = getDataTimeString() + 'WHITEBOARD.png';
    link.href = canvas.toDataURL();
    link.click();
    link.delete;
}

/**
 * Remote whiteboard actions
 * @param {*} action
 */
function remoteWbAction(action) {
    if (thereIsPeerConnections()) {
        signalingSocket.emit('wb', {
            peerConnections: peerConnections,
            peer_name: myPeerName,
            act: action,
        });
    }
}

/**
 * Create File Sharing Data Channel
 * @param {*} peer_id
 */
function createFileSharingDataChannel(peer_id) {
    fileDataChannels[peer_id] = peerConnections[peer_id].createDataChannel('mirotalk_file_sharing_channel');
    fileDataChannels[peer_id].binaryType = 'arraybuffer';
    console.log('fileDataChannels created', fileDataChannels);
}

/**
 * Handle File Sharing
 * @param {*} data
 */
function handleDataChannelFileSharing(data) {
    receiveBuffer.push(data);
    receivedSize += data.byteLength;

    // let getPercentage = ((receivedSize / incomingFileInfo.fileSize) * 100).toFixed(2);
    // console.log("Received progress: " + getPercentage + "%");

    if (receivedSize === incomingFileInfo.fileSize) {
        incomingFileData = receiveBuffer;
        receiveBuffer = [];
        endDownload();
    }
}

/**
 * Send File Data trought datachannel
 * https://webrtc.github.io/samples/src/content/datachannel/filetransfer/
 * https://github.com/webrtc/samples/blob/gh-pages/src/content/datachannel/filetransfer/js/main.js
 */
function sendFileData() {
    console.log('Send file ' + fileToSend.name + ' size ' + bytesToSize(fileToSend.size) + ' type ' + fileToSend.type);

    sendInProgress = true;

    sendFileInfo.innerHTML =
        'File name: ' +
        fileToSend.name +
        '<br>' +
        'File type: ' +
        fileToSend.type +
        '<br>' +
        'File size: ' +
        bytesToSize(fileToSend.size) +
        '<br>';

    sendFileDiv.style.display = 'inline';
    sendProgress.max = fileToSend.size;
    fileReader = new FileReader();
    let offset = 0;

    fileReader.addEventListener('error', (err) => console.error('fileReader error', err));
    fileReader.addEventListener('abort', (e) => console.log('fileReader aborted', e));
    fileReader.addEventListener('load', (e) => {
        if (!sendInProgress) return;

        // peer to peer over DataChannels
        sendFSData(e.target.result);
        offset += e.target.result.byteLength;

        sendProgress.value = offset;
        sendFilePercentage.innerHTML = 'Send progress: ' + ((offset / fileToSend.size) * 100).toFixed(2) + '%';

        // send file completed
        if (offset === fileToSend.size) {
            sendInProgress = false;
            sendFileDiv.style.display = 'none';
            userLog('success', 'The file ' + fileToSend.name + ' was sent successfully.');
        }

        if (offset < fileToSend.size) readSlice(offset);
    });
    const readSlice = (o) => {
        const slice = fileToSend.slice(offset, o + chunkSize);
        fileReader.readAsArrayBuffer(slice);
    };
    readSlice(0);
}

/**
 * Send File through RTC Data Channels
 * @param {*} data fileReader e.target.result
 */
function sendFSData(data) {
    for (let peer_id in fileDataChannels) {
        if (fileDataChannels[peer_id].readyState === 'open') fileDataChannels[peer_id].send(data);
    }
}

/**
 * Abort the file transfer
 */
function abortFileTransfer() {
    if (fileReader && fileReader.readyState === 1) {
        fileReader.abort();
        sendFileDiv.style.display = 'none';
        sendInProgress = false;
        signalingSocket.emit('fileAbort', {
            peerConnections: peerConnections,
            peer_name: myPeerName,
            room_id: roomId,
        });
    }
}

/**
 * File Transfer aborted by peer
 */
function handleFileAbort() {
    receiveBuffer = [];
    incomingFileData = [];
    receivedSize = 0;
    console.log('File transfer aborted');
    userLog('toast', '⚠️ File transfer aborted');
}

/**
 * Select the File to Share
 */
function selectFileToShare() {
    // playSound('newMessage');

    Swal.fire({
        allowOutsideClick: false,
        background: swalBackground,
        imageAlt: 'mirotalk-file-sharing',
        imageUrl: fileSharingImg,
        position: 'center',
        title: 'Share the file',
        input: 'file',
        inputAttributes: {
            accept: fileSharingInput,
            'aria-label': 'Select the file',
        },
        showDenyButton: true,
        confirmButtonText: `Send`,
        denyButtonText: `Cancel`,
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
    }).then((result) => {
        if (result.isConfirmed) {
            fileToSend = result.value;
            if (fileToSend && fileToSend.size > 0) {
                // no peers in the room
                if (!thereIsPeerConnections()) {
                    userLog('info', 'No participants detected');
                    return;
                }
                // send some metadata about our file to peers in the room
                signalingSocket.emit('fileInfo', {
                    peerConnections: peerConnections,
                    peer_name: myPeerName,
                    room_id: roomId,
                    file: {
                        fileName: fileToSend.name,
                        fileSize: fileToSend.size,
                        fileType: fileToSend.type,
                    },
                });
                // send the File
                setTimeout(() => {
                    sendFileData();
                }, 1000);
            } else {
                userLog('error', 'File not selected or empty.');
            }
        }
    });
}

/**
 * Get remote file info
 * @param {*} config file
 */
function handleFileInfo(config) {
    incomingFileInfo = config;
    incomingFileData = [];
    receiveBuffer = [];
    receivedSize = 0;
    let fileToReceiveInfo =
        ' From: ' +
        incomingFileInfo.peerName +
        '\n' +
        ' incoming file: ' +
        incomingFileInfo.fileName +
        '\n' +
        ' size: ' +
        bytesToSize(incomingFileInfo.fileSize) +
        '\n' +
        ' type: ' +
        incomingFileInfo.fileType;
    console.log(fileToReceiveInfo);
    userLog('toast', fileToReceiveInfo);
}

/**
 * The file will be saved in the Blob. You will be asked to confirm if you want to save it on your PC / Mobile device.
 * https://developer.mozilla.org/en-US/docs/Web/API/Blob
 */
function endDownload() {
    playSound('download');

    // save received file into Blob
    const blob = new Blob(incomingFileData);
    const file = incomingFileInfo.fileName;

    incomingFileData = [];

    // if file is image, show the preview
    if (isImageURL(incomingFileInfo.fileName)) {
        const reader = new FileReader();
        reader.onload = (e) => {
            Swal.fire({
                allowOutsideClick: false,
                background: swalBackground,
                position: 'center',
                title: 'Received file',
                text: incomingFileInfo.fileName + ' size ' + bytesToSize(incomingFileInfo.fileSize),
                imageUrl: e.target.result,
                imageAlt: 'mirotalk-file-img-download',
                showDenyButton: true,
                confirmButtonText: `Save`,
                denyButtonText: `Cancel`,
                showClass: {
                    popup: 'animate__animated animate__fadeInDown',
                },
                hideClass: {
                    popup: 'animate__animated animate__fadeOutUp',
                },
            }).then((result) => {
                if (result.isConfirmed) saveFileFromBlob(blob, file);
            });
        };
        // blob where is stored downloaded file
        reader.readAsDataURL(blob);
    } else {
        // not img file
        Swal.fire({
            allowOutsideClick: false,
            background: swalBackground,
            imageAlt: 'mirotalk-file-download',
            imageUrl: fileSharingImg,
            position: 'center',
            title: 'Received file',
            text: incomingFileInfo.fileName + ' size ' + bytesToSize(incomingFileInfo.fileSize),
            showDenyButton: true,
            confirmButtonText: `Save`,
            denyButtonText: `Cancel`,
            showClass: {
                popup: 'animate__animated animate__fadeInDown',
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOutUp',
            },
        }).then((result) => {
            if (result.isConfirmed) saveFileFromBlob(blob, file);
        });
    }
}

/**
 * Save to PC / Mobile devices
 * https://developer.mozilla.org/en-US/docs/Web/API/Blob
 * @param {*} blob
 * @param {*} file
 */
function saveFileFromBlob(blob, file) {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = file;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }, 100);
}

/**
 * Handle peer kick out event button
 * @param {*} peer_id
 */
function handlePeerKickOutBtn(peer_id) {
    let peerKickOutBtn = getId(peer_id + '_kickOut');
    peerKickOutBtn.addEventListener('click', (e) => {
        kickOut(peer_id, peerKickOutBtn);
    });
}

/**
 * Kick out confirm
 * @param {*} peer_id
 * @param {*} peerKickOutBtn
 */
function kickOut(peer_id, peerKickOutBtn) {
    let pName = getId(peer_id + '_name').innerHTML;

    Swal.fire({
        background: swalBackground,
        position: 'center',
        imageUrl: confirmImg,
        title: 'Kick out ' + pName,
        text: 'Are you sure you want to kick out this participant?',
        showDenyButton: true,
        confirmButtonText: `Yes`,
        denyButtonText: `No`,
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
    }).then((result) => {
        if (result.isConfirmed) {
            // send peer to kick out from room
            signalingSocket.emit('kickOut', {
                room_id: roomId,
                peer_id: peer_id,
                peer_name: myPeerName,
            });
            peerKickOutBtn.style.display = 'none';
        }
    });
}

/**
 * You will be kicked out from the room and popup the peer name that performed this action
 * @param {*} config
 */
function handleKickedOut(config) {
    let peer_name = config.peer_name;

    playSound('kickedOut');

    let timerInterval;

    Swal.fire({
        allowOutsideClick: false,
        background: swalBackground,
        position: 'center',
        imageUrl: kickedOutImg,
        title: 'Kicked out!',
        html:
            `<h2 style="color: red;">` +
            `User ` +
            peer_name +
            `</h2> will kick out you after <b style="color: red;"></b> milliseconds.`,
        timer: 10000,
        timerProgressBar: true,
        didOpen: () => {
            Swal.showLoading();
            timerInterval = setInterval(() => {
                const content = Swal.getHtmlContainer();
                if (content) {
                    const b = content.querySelector('b');
                    if (b) b.textContent = Swal.getTimerLeft();
                }
            }, 100);
        },
        willClose: () => {
            clearInterval(timerInterval);
        },
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
    }).then(() => {
        window.location.href = '/newcall';
    });
}

/**
 * MiroTalk about info
 */
function getAbout() {
    // playSound('newMessage');

    Swal.fire({
        background: swalBackground,
        position: 'center',
        title: '<strong>WebRTC Made with ❤️</strong>',
        imageAlt: 'mirotalk-about',
        imageUrl: aboutImg,
        html: `
        <br/>
        <div id="about">
            <b>Open Source</b> project on
            <a href="https://github.com/miroslavpejic85/mirotalk" target="_blank"><br/></br>
            <img alt="mirotalk github" src="../images/github.png"></a><br/><br/>
            <button id="sponsorBtn" class="far fa-heart pulsate" onclick="window.open('https://github.com/sponsors/miroslavpejic85?o=esb')"> Sponsor</button>
        </div>
        </br>
        <div id="author">Author:<a href="https://www.linkedin.com/in/miroslav-pejic-976a07101/" target="_blank"> Miroslav Pejic</a></div>
        `,
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
    });
}

/**
 * Leave the Room and create a new one
 */
function leaveRoom() {
    playSound('newMessage');

    Swal.fire({
        background: swalBackground,
        position: 'center',
        imageAlt: 'mirotalk-leave',
        //imageUrl: leaveRoomImg,
        title: 'Leave this room?',
        showDenyButton: true,
        confirmButtonText: `Yes`,
        denyButtonText: `No`,
        showClass: {
            popup: 'animate__animated animate__fadeInDown',
        },
        hideClass: {
            popup: 'animate__animated animate__fadeOutUp',
        },
    }).then((result) => {
        if (result.isConfirmed) window.location.href = '/'; //after left meeting, send back to home
    });
}

/**
 * Make Obj draggable
 * https://www.w3schools.com/howto/howto_js_draggable.asp
 *
 * @param {*} elmnt
 * @param {*} dragObj
 */
function dragElement(elmnt, dragObj) {
    let pos1 = 0,
        pos2 = 0,
        pos3 = 0,
        pos4 = 0;
    if (dragObj) {
        // if present, the header is where you move the DIV from:
        dragObj.onmousedown = dragMouseDown;
    } else {
        // otherwise, move the DIV from anywhere inside the DIV:
        elmnt.onmousedown = dragMouseDown;
    }
    function dragMouseDown(e) {
        e = e || window.event;
        e.preventDefault();
        // get the mouse cursor position at startup:
        pos3 = e.clientX;
        pos4 = e.clientY;
        document.onmouseup = closeDragElement;
        // call a function whenever the cursor moves:
        document.onmousemove = elementDrag;
    }
    function elementDrag(e) {
        e = e || window.event;
        e.preventDefault();
        // calculate the new cursor position:
        pos1 = pos3 - e.clientX;
        pos2 = pos4 - e.clientY;
        pos3 = e.clientX;
        pos4 = e.clientY;
        // set the element's new position:
        elmnt.style.top = elmnt.offsetTop - pos2 + 'px';
        elmnt.style.left = elmnt.offsetLeft - pos1 + 'px';
    }
    function closeDragElement() {
        // stop moving when mouse button is released:
        document.onmouseup = null;
        document.onmousemove = null;
    }
}

/**
 * Data Formated DD-MM-YYYY-H_M_S
 * https://convertio.co/it/
 * @returns data string
 */
function getDataTimeString() {
    const d = new Date();
    const date = d.toISOString().split('T')[0];
    const time = d.toTimeString().split(' ')[0];
    return `${date}-${time}`;
}

/**
 * Convert bytes to KB-MB-GB-TB
 * @param {*} bytes
 * @returns size
 */
function bytesToSize(bytes) {
    let sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    if (bytes == 0) return '0 Byte';
    let i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
}

/**
 * Basic user logging using https://sweetalert2.github.io
 * @param {*} type
 * @param {*} message
 */
function userLog(type, message) {
    switch (type) {
        case 'error':
            Swal.fire({
                background: swalBackground,
                position: 'center',
                icon: 'error',
                title: 'Oops...',
                text: message,
            });
            playSound('error');
            break;
        case 'info':
            Swal.fire({
                background: swalBackground,
                position: 'center',
                icon: 'info',
                title: 'Info',
                text: message,
                showClass: {
                    popup: 'animate__animated animate__fadeInDown',
                },
                hideClass: {
                    popup: 'animate__animated animate__fadeOutUp',
                },
            });
            break;
        case 'success':
            Swal.fire({
                background: swalBackground,
                position: 'center',
                icon: 'success',
                title: 'Success',
                text: message,
                showClass: {
                    popup: 'animate__animated animate__fadeInDown',
                },
                hideClass: {
                    popup: 'animate__animated animate__fadeOutUp',
                },
            });
            break;
        case 'success-html':
            Swal.fire({
                background: swalBackground,
                position: 'center',
                icon: 'success',
                title: 'Success',
                html: message,
                showClass: {
                    popup: 'animate__animated animate__fadeInDown',
                },
                hideClass: {
                    popup: 'animate__animated animate__fadeOutUp',
                },
            });
            break;
        case 'toast':
            const Toast = Swal.mixin({
                background: swalBackground,
                toast: true,
                position: 'top-end',
                showConfirmButton: false,
                timer: 3000,
            });
            Toast.fire({
                icon: 'info',
                title: message,
            });
            break;
        // ......
        default:
            alert(message);
    }
}

/**
 * https://notificationsounds.com/notification-sounds
 * @param {*} name
 */
async function playSound(name) {
    if (!notifyBySound) return;
    let file_audio = '../audio/' + name + '.mp3';
    let audioToPlay = new Audio(file_audio);
    try {
        await audioToPlay.play();
    } catch (err) {
        // console.error("Cannot play sound", err);
        // Automatic playback failed. (safari)
        return;
    }
}

/**
 * Show-Hide all elements grp by class name
 * @param {*} className
 * @param {*} displayState
 */
function toggleClassElements(className, displayState) {
    let elements = getEcN(className);
    for (let i = 0; i < elements.length; i++) {
        elements[i].style.display = displayState;
    }
}

/**
 * Get Html element by Id
 * @param {*} id
 */
function getId(id) {
    return document.getElementById(id);
}

/**
 * Get Html element by selector
 * @param {*} selector
 */
function getSl(selector) {
    return document.querySelector(selector);
}

/**
 * Get Html element by class name
 * @param {*} className
 */
function getEcN(className) {
    return document.getElementsByClassName(className);
}
