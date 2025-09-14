async function deriveKey(passphrase, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits", "deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { "name": "PBKDF2", salt: enc.encode(salt), "iterations": 100000, "hash": "SHA-256" },
    keyMaterial, { "name": "AES-GCM", "length": 256 }, true, ["encrypt", "decrypt"]
  );
}

function toggleInput() {
  const type = document.getElementById('fileType').value;
  const inputContainer = document.getElementById('inputContainer');
  const fileInputContainer = document.getElementById('fileInputContainer');
  inputContainer.classList.add('hidden');
  fileInputContainer.classList.add('hidden');
  if (type === 'text') {
    inputContainer.classList.remove('hidden');
  } else if (type) {
    fileInputContainer.classList.remove('hidden');
    document.getElementById('fileInput').accept = getAccept(type);
  }
}

function getAccept(type) {
  const types = {
    image: 'image/jpeg,image/jpg,image/png,image/gif',
    audio: 'audio/wav,audio/mpeg',
    video: 'video/mp4',
    archive: 'application/zip',
    document: 'text/plain,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/pdf'
  };
  return types[type] || '*/*';
}

let fileList = [];
function handleFiles(files) {
  const newFiles = Array.from(files);
  newFiles.forEach(file => {
    if (!fileList.some(f => f.name === file.name && f.size === file.size)) {
      fileList.push(file);
    }
  });
  console.log('Files added:', fileList.map(f => f.name));
  updateFileListUI();
}

function updateFileListUI() {
  const fileListElement = document.getElementById('fileList');
  fileListElement.innerHTML = '';
  fileList.forEach((file, index) => {
    const li = document.createElement('li');
    li.className = 'flex justify-between items-center';
    li.textContent = file.name;
    const removeButton = document.createElement('button');
    removeButton.textContent = 'Remove';
    removeButton.className = 'ml-2 bg-red-600 text-white px-1.5 py-0.5 rounded hover:bg-red-700 text-xs';
    removeButton.onclick = () => removeFile(index);
    li.appendChild(removeButton);
    fileListElement.appendChild(li);
  });
}

function removeFile(index) {
  fileList.splice(index, 1);
  updateFileListUI();
}

async function saveNote() {
  const passphrase = document.getElementById('passphrase').value;
  const type = document.getElementById('fileType').value;
  if (!passphrase || !type) {
    document.getElementById('status').textContent = 'Passphrase and file type required';
    return;
  }

  const spinner = document.getElementById('spinner');
  if (type !== 'text') spinner.style.display = 'block';

  let dataArray = [];
  let mimeArray = [];
  try {
    if (type === 'text') {
      const note = document.getElementById('note').value;
      if (!note) {
        document.getElementById('status').textContent = 'Note required';
        spinner.style.display = 'none';
        return;
      }
      dataArray.push(new TextEncoder().encode(note));
      mimeArray.push('text/plain');
    } else {
      if (fileList.length === 0) {
        document.getElementById('status').textContent = 'File(s) required';
        spinner.style.display = 'none';
        return;
      }
      for (let file of fileList) {
        if (file.size > 10 * 1024 * 1024) {
          document.getElementById('status').textContent = 'File too large (max 10MB)';
          spinner.style.display = 'none';
          return;
        }
        mimeArray.push(file.type || 'application/octet-stream');
        console.log(`Reading file: ${file.name}`);
        dataArray.push(await file.arrayBuffer());
        console.log(`File ${file.name} read successfully`);
      }
    }

    const encryptedData = [];
    for (let data of dataArray) {
      const salt = btoa(Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => String.fromCharCode(b)).join(''));
      const key = await deriveKey(passphrase, salt);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      console.log('Encrypting data...');
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, key, data
      );
      encryptedData.push({ iv: btoa(Array.from(iv).map(b => String.fromCharCode(b)).join('')), data: btoa(Array.from(new Uint8Array(encrypted)).map(b => String.fromCharCode(b)).join('')), salt: salt });
      console.log('Encryption completed for one item');
    }

    const shareableData = JSON.stringify({ type: type, data: encryptedData, mime: mimeArray });
    if (shareableData) {
      localStorage.setItem('encryptedNote', shareableData);
      document.getElementById('sharedNote').value = shareableData;
      document.getElementById('status').textContent = 'Note/File(s) saved securely! Copy the text in the shared note box to share.';
    } else {
      document.getElementById('status').textContent = 'Error generating encrypted data';
    }
  } catch (e) {
    console.error('Save error:', e);
    document.getElementById('status').textContent = 'Error saving note/file: ' + e.message;
  } finally {
    spinner.style.display = 'none';
    setTimeout(() => {
      if (spinner.style.display !== 'none') {
        spinner.style.display = 'none';
        document.getElementById('status').textContent = 'Operation timed out (over 10s)';
      }
    }, 10000);
  }
}

async function loadSharedNote() {
  const passphrase = document.getElementById('passphrase').value;
  const sharedNote = document.getElementById('sharedNote').value;
  if (!sharedNote) {
    document.getElementById('status').textContent = 'Please paste a shared note';
    return;
  }

  const outputContainer = document.getElementById('outputContainer');
  outputContainer.innerHTML = '';
  try {
    const { type, data: encryptedData, mime } = JSON.parse(sharedNote);
    if (!encryptedData || !Array.isArray(encryptedData)) {
      const { iv: ivStr, data: encryptedStr, salt } = JSON.parse(sharedNote);
      const iv = new Uint8Array(atob(ivStr).split('').map(c => c.charCodeAt(0)));
      const encrypted = new Uint8Array(atob(encryptedStr).split('').map(c => c.charCodeAt(0)));
      const key = await deriveKey(passphrase, salt);
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv }, key, encrypted
      );
      document.getElementById('note').value = new TextDecoder().decode(decrypted);
      document.getElementById('status').textContent = 'Shared note loaded!';
      return;
    }

    for (let i = 0; i < encryptedData.length; i++) {
      const { iv, data, salt } = encryptedData[i];
      const ivArray = new Uint8Array(atob(iv).split('').map(c => c.charCodeAt(0)));
      const encrypted = new Uint8Array(atob(data).split('').map(c => c.charCodeAt(0)));
      const key = await deriveKey(passphrase, salt);
      console.log('Decrypting data...');
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivArray }, key, encrypted
      );
      console.log('Decryption completed for one item');

      const blob = new Blob([decrypted], { type: mime[i] || 'application/octet-stream' });
      if (type === 'text') {
        document.getElementById('note').value = new TextDecoder().decode(decrypted);
      } else {
        const container = document.createElement('div');
        container.className = 'preview-container';
        if (mime[i].startsWith('image/') || mime[i].startsWith('audio/') || mime[i].startsWith('video/')) {
          const preview = document.createElement(mime[i].startsWith('image/') ? 'img' : mime[i].startsWith('audio/') ? 'audio' : 'video');
          preview.controls = mime[i].startsWith('audio/') || mime[i].startsWith('video/');
          preview.src = URL.createObjectURL(blob);
          if (mime[i].startsWith('image/')) preview.style.maxWidth = '100%';
          container.appendChild(preview);
        } else {
          const previewLink = document.createElement('a');
          previewLink.href = URL.createObjectURL(blob);
          previewLink.textContent = `Preview ${getExtension(mime[i])}`;
          previewLink.target = '_blank';
          container.appendChild(previewLink);
        }
        const downloadLink = document.createElement('a');
        downloadLink.href = URL.createObjectURL(blob);
        downloadLink.download = `decrypted_file_${i + 1}.${getExtension(mime[i])}`;
        downloadLink.textContent = `Download ${getExtension(mime[i])}`;
        downloadLink.className = 'bg-blue-600 text-white px-4 py-2 rounded-md font-semibold hover:bg-blue-700';
        container.appendChild(downloadLink);
        outputContainer.appendChild(container);
      }
    }
    document.getElementById('status').textContent = 'Shared file(s) loaded!';
  } catch (e) {
    console.error('Decryption error:', e);
    document.getElementById('status').textContent = 'Invalid note or wrong passphrase';
  }
}

function getExtension(mime) {
  const extensions = {
    'image/jpeg': 'jpg', 'image/jpg': 'jpg', 'image/png': 'png', 'image/gif': 'gif',
    'audio/wav': 'wav', 'audio/mpeg': 'mp3',
    'video/mp4': 'mp4',
    'application/zip': 'zip',
    'text/plain': 'txt', 'application/msword': 'doc', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
    'application/vnd.ms-powerpoint': 'ppt', 'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx', 'application/pdf': 'pdf'
  };
  return extensions[mime] || 'bin';
}

function copyToClipboard() {
  const sharedNote = document.getElementById('sharedNote');
  sharedNote.select();
  document.execCommand('copy');
  document.getElementById('status').textContent = 'Copied to clipboard!';
}
