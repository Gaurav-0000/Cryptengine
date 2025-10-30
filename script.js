// === Helpers: base64 <-> ArrayBuffer (chunk-safe) ===
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let result = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    // convert chunk to string
    result += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(result);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Secure random bytes util
function generateRandomBytes(length) {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

// === WebCrypto-based PBKDF2 deriveKey -> AES-GCM CryptoKey ===
async function deriveKey(passphrase, saltBase64, iterations = 100000) {
  const enc = new TextEncoder();
  const passBytes = enc.encode(passphrase);
  const saltBytes = new Uint8Array(base64ToArrayBuffer(saltBase64));

  const baseKey = await crypto.subtle.importKey(
    "raw",
    passBytes,
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const derived = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  return derived;
}

// === Mode management + state ===
let currentMode = "encrypt";
let lastEncryptPassphrase = "";
let savedFileList = [];
let savedNote = "";
let isModeSwitch = false;
let history = [];

// For decrypt-file upload support
let decryptUploadedContent = "";
let decryptUploadedFilename = "";

function setMode(mode) {
  isModeSwitch = true;
  currentMode = mode;
  const encryptBtn = document.getElementById("encryptBtn");
  const decryptBtn = document.getElementById("decryptBtn");
  const pageTitle = document.getElementById("pageTitle");
  const encryptSection = document.getElementById("encryptSection");
  const decryptSection = document.getElementById("decryptSection");
  const sharedNote = document.getElementById("sharedNote");
  const fileTypeSelect = document.getElementById("fileType");
  const passphraseInput = document.getElementById("passphrase");
  const inputContainer = document.getElementById("inputContainer");
  const fileInputContainer = document.getElementById("fileInputContainer");
  const noteInput = document.getElementById("note");
  const decryptFileContainer = document.getElementById("decryptFileContainer");
  const CopyBtn = document.getElementById("copyBtn");

  // Manage active button glow by toggling the dedicated class instead of overwriting className
  encryptBtn.classList.remove("cyber-button-active");
  decryptBtn.classList.remove("cyber-button-active");

  if (mode === "encrypt") {
    encryptBtn.classList.add("cyber-button-active");
    pageTitle.textContent = "Encryption Terminal";
    encryptSection.style.display = "flex";
    decryptSection.style.display = "none";
    sharedNote.placeholder =
      "Your encrypted note will appear here after encryption";
    CopyBtn.style.display = "block";
    sharedNote.value = "";
    fileTypeSelect.style.display = "block";
    decryptFileContainer.style.display = "none";
    inputContainer.classList.add("hidden");
    fileInputContainer.classList.add("hidden");
    passphraseInput.value = lastEncryptPassphrase;
    passphraseInput.className = "terminal-input w-1/2 px-4 py-3 rounded";
    savedFileList = [...savedFileList];
    noteInput.value = savedNote;
    toggleInput();
    updateHistoryUI();
    document.getElementById("decryptFileLabel").textContent =
      "NO FILE SELECTED";
    document.getElementById("status").textContent = "";
    decryptUploadedContent = "";
    decryptUploadedFilename = "";
  } else {
    decryptBtn.classList.add("cyber-button-active");
    pageTitle.textContent = "Decryption Terminal";
    encryptSection.style.display = "none";
    decryptSection.style.display = "flex";
    sharedNote.placeholder =
      "Paste encrypted note here to decrypt (or upload .enc/.txt)";
    CopyBtn.style.display = "none";
    sharedNote.value = "";
    fileTypeSelect.style.display = "none";
    decryptFileContainer.style.display = "block";
    inputContainer.classList.add("hidden");
    fileInputContainer.classList.add("hidden");
    lastEncryptPassphrase = passphraseInput.value;
    passphraseInput.value = "";
    passphraseInput.className = "terminal-input w-1/2 px-4 py-3 rounded"; // half width in decrypt mode
    savedFileList = [...savedFileList];
    savedNote = noteInput.value;
    document.getElementById("status").textContent = "";
    // reset any uploaded decrypt file state when switching to decrypt
    decryptUploadedContent = "";
    decryptUploadedFilename = "";
    document.getElementById("decryptFileLabel").textContent =
      "NO FILE SELECTED";
  }

  isModeSwitch = false;
}

function toggleInput() {
  const fileTypeSelect = document.getElementById("fileType");
  const type = fileTypeSelect.value;
  const inputContainer = document.getElementById("inputContainer");
  const fileInputContainer = document.getElementById("fileInputContainer");

  if (type && fileList.length > 0 && !isModeSwitch) {
    const choice = confirm(
      'Changing file type will affect the current file list. Do you want to:\n- "OK" for New list (clear current list)\n- "Cancel" for Current list (keep current list)'
    );
    if (choice) fileList = [];
  }

  inputContainer.classList.add("hidden");
  fileInputContainer.classList.add("hidden");
  if (type === "text") inputContainer.classList.remove("hidden");
  else if (type) {
    fileInputContainer.classList.remove("hidden");
    document.getElementById("fileInput").accept = getAccept(type);
  }
  updateFileListUI();
}

function getAccept(type) {
  const types = {
    image: "image/jpeg,image/jpg,image/png,image/gif",
    audio: "audio/wav,audio/mpeg",
    video: "video/mp4",
    archive: "application/zip",
    document:
      "text/plain,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/pdf",
  };
  return types[type] || "*/*";
}

let fileList = [];
function handleFiles(files) {
  const type = document.getElementById("fileType").value;
  const accept = getAccept(type).split(",");
  const newFiles = Array.from(files);
  newFiles.forEach((file) => {
    const isValid = accept.some(
      (t) =>
        file.type === t || file.name.endsWith(t.replace("application/", "."))
    );
    if (!isValid) {
      alert("Only " + type + " files are allowed!");
      return;
    }
    if (!fileList.some((f) => f.name === file.name && f.size === file.size))
      fileList.push(file);
  });
  updateFileListUI();
}

function updateFileListUI() {
  const fileListElement = document.getElementById("fileList");
  const fileStatus = document.getElementById("fileStatus");
  fileListElement.innerHTML = "";
  if (fileList.length === 0) {
    if (fileStatus) fileStatus.textContent = "No files chosen";
    return;
  }
  if (fileStatus)
    fileStatus.textContent =
      fileList.length === 1
        ? "1 file selected"
        : fileList.length + " files selected";
  if (
    fileList.length > 0 &&
    document.getElementById("fileType").value !== "text"
  ) {
    fileList.forEach((file, index) => {
      const li = document.createElement("li");
      li.className = "flex justify-between items-center";
      li.textContent = file.name;
      const removeButton = document.createElement("button");
      removeButton.textContent = "Remove";
      removeButton.className =
        "ml-2 bg-red-600 text-white px-1.5 py-0.5 rounded hover:bg-red-700 text-xs";
      removeButton.onclick = () => removeFile(index);
      li.appendChild(removeButton);
      fileListElement.appendChild(li);
    });
  }
}

function removeFile(index) {
  fileList.splice(index, 1);
  updateFileListUI();
}

// === Encryption using SubtleCrypto (AES-GCM) ===
async function saveNote() {
  const passphrase = document.getElementById("passphrase").value;
  const type = document.getElementById("fileType").value;
  if (!passphrase || !type) {
    document.getElementById("status").textContent =
      "Passphrase and file type required";
    return;
  }
  const spinner = document.getElementById("spinner");
  if (type !== "text") spinner.style.display = "block";
  let dataArray = [];
  let mimeArray = [];
  try {
    if (type === "text") {
      const note = document.getElementById("note").value;
      if (!note) {
        document.getElementById("status").textContent = "Note required";
        spinner.style.display = "none";
        return;
      }
      dataArray.push(new TextEncoder().encode(note).buffer);
      mimeArray.push("text/plain");
    } else {
      if (fileList.length === 0) {
        document.getElementById("status").textContent = "File(s) required";
        spinner.style.display = "none";
        return;
      }
      for (let file of fileList) {
        if (file.size > 10 * 1024 * 1024) {
          document.getElementById("status").textContent =
            "File too large (max 10MB)";
          spinner.style.display = "none";
          return;
        }
        mimeArray.push(file.type || "application/octet-stream");
        dataArray.push(await file.arrayBuffer());
      }
    }

    const encryptedData = [];
    for (let dataBuf of dataArray) {
      // Generate salt (base64) and iv
      const saltBytes = generateRandomBytes(16);
      const saltB64 = arrayBufferToBase64(saltBytes.buffer);
      const iv = generateRandomBytes(12);

      const key = await deriveKey(passphrase, saltB64);
      // WebCrypto AES-GCM encrypt returns ciphertext with tag appended
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv, tagLength: 128 },
        key,
        dataBuf
      );

      encryptedData.push({
        iv: arrayBufferToBase64(iv.buffer),
        data: arrayBufferToBase64(encrypted),
        salt: saltB64,
      });
    }

    const shareableData = JSON.stringify({
      type: type,
      data: encryptedData,
      mime: mimeArray,
    });

    if (shareableData) {
      document.getElementById("sharedNote").value = shareableData;
      document.getElementById("status").textContent =
        "Note/File(s) encrypted successfully! Copy the encrypted text to share.";
      const historyCount = history.length + 1;
      history.unshift({
        id: "Encryption " + historyCount,
        data: shareableData,
        timestamp: new Date().toISOString(),
      });
      if (history.length > 5) history.pop();
      updateHistoryUI();
    }
  } catch (e) {
    console.error("Encryption error:", e);
    document.getElementById("status").textContent =
      "Error encrypting note/file: " + (e.message || e);
  } finally {
    spinner.style.display = "none";
  }
}

// DECRYPT: handle uploaded .enc/.txt file for decrypt mode
async function handleDecryptFile(files) {
  const file = files[0];
  if (!file) return;
  if (!file.name.endsWith(".enc") && !file.name.endsWith(".txt")) {
    alert("Only .enc or .txt files allowed");
    return;
  }
  try {
    const content = await file.text();
    decryptUploadedContent = content;
    decryptUploadedFilename = file.name;
    document.getElementById("decryptFileLabel").textContent = file.name;
    document.getElementById("status").textContent =
      "File loaded — ready to decrypt.";
  } catch (e) {
    console.error("File read error:", e);
    document.getElementById("status").textContent =
      "Error reading uploaded file";
  }
}

// LOAD / DECRYPT using SubtleCrypto
async function loadSharedNote() {
  const passphrase = document.getElementById("passphrase").value;
  const outputContainer = document.getElementById("outputContainer");
  outputContainer.innerHTML = "";
  document.getElementById("inputContainer").classList.add("hidden");
  if (!passphrase) {
    document.getElementById("status").textContent = "Please enter passphrase";
    return;
  }

  // prefer uploaded file content when present
  const sharedNoteRaw =
    decryptUploadedContent || document.getElementById("sharedNote").value;
  if (!sharedNoteRaw) {
    document.getElementById("status").textContent =
      "Please paste an encrypted note or upload a .enc/.txt file";
    return;
  }

  try {
    const parsed = JSON.parse(sharedNoteRaw);

    // legacy single-item format detection
    if (!parsed.data || !Array.isArray(parsed.data)) {
      const { iv: ivStr, data: encryptedStr, salt } = parsed;
      if (!ivStr || !encryptedStr || !salt)
        throw new Error("Invalid legacy encrypted format");

      const iv = new Uint8Array(base64ToArrayBuffer(ivStr));
      const encryptedBuf = base64ToArrayBuffer(encryptedStr);
      const key = await deriveKey(passphrase, salt);

      try {
        const decryptedBuf = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv, tagLength: 128 },
          key,
          encryptedBuf
        );
        document.getElementById("note").value = new TextDecoder().decode(
          decryptedBuf
        );
        document.getElementById("inputContainer").classList.remove("hidden");
        document.getElementById("status").textContent =
          "Note decrypted successfully!";
      } catch (err) {
        throw new Error("Authentication failed");
      }
      return;
    }

    // modern multi-item format
    const { type, data: encryptedData, mime } = parsed;
    if (!encryptedData || !Array.isArray(encryptedData))
      throw new Error("Invalid encrypted payload");

    // If the sender included a file-type suggestion, set it silently
    const fileTypeSelect = document.getElementById("fileType");
    if (type === "text") {
      fileTypeSelect.value = "text";
      toggleInput();
    } else {
      // don't show file input UI automatically for non-text (we'll show previews in output container)
      fileTypeSelect.value = type;
    }

    for (let i = 0; i < encryptedData.length; i++) {
      const { iv, data, salt } = encryptedData[i];
      const ivArray = new Uint8Array(base64ToArrayBuffer(iv));
      const encryptedBuf = base64ToArrayBuffer(data);
      const key = await deriveKey(passphrase, salt);

      let decryptedBuf;
      try {
        decryptedBuf = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: ivArray, tagLength: 128 },
          key,
          encryptedBuf
        );
      } catch (err) {
        throw new Error("Authentication failed");
      }

      const blob = new Blob([decryptedBuf], {
        type: mime[i] || "application/octet-stream",
      });
      if (type === "text") {
        document.getElementById("note").value = new TextDecoder().decode(
          decryptedBuf
        );
        document.getElementById("inputContainer").classList.remove("hidden");
      } else {
        const container = document.createElement("div");
        container.className =
          "preview-container mb-4 p-4 border border-green-500/30 rounded";
        if (
          mime[i].startsWith("image/") ||
          mime[i].startsWith("audio/") ||
          mime[i].startsWith("video/")
        ) {
          const preview = document.createElement(
            mime[i].startsWith("image/")
              ? "img"
              : mime[i].startsWith("audio/")
              ? "audio"
              : "video"
          );
          preview.controls =
            mime[i].startsWith("audio/") || mime[i].startsWith("video/");
          preview.src = URL.createObjectURL(blob);
          if (mime[i].startsWith("image/")) preview.style.maxWidth = "100%";
          container.appendChild(preview);
        } else {
          const previewLink = document.createElement("a");
          previewLink.href = URL.createObjectURL(blob);
          previewLink.textContent = "Preview " + getExtension(mime[i]);
          previewLink.target = "_blank";
          container.appendChild(previewLink);
        }
        const downloadLink = document.createElement("a");
        downloadLink.href = URL.createObjectURL(blob);
        downloadLink.download =
          "decrypted_file_" + (i + 1) + "." + getExtension(mime[i]);
        downloadLink.textContent = "Download " + getExtension(mime[i]);
        downloadLink.className =
          "bg-blue-600 text-white px-4 py-2 rounded-md font-semibold hover:bg-blue-700";
        container.appendChild(downloadLink);
        document.getElementById("outputContainer").appendChild(container);
      }
    }

    document.getElementById("status").textContent =
      "File(s) decrypted successfully!";
  } catch (e) {
    console.error("Decryption error:", e);
    document.getElementById("status").textContent =
      "Invalid Encrypted note or wrong passphrase.";
  }
}

function getExtension(mime) {
  const extensions = {
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "audio/wav": "wav",
    "audio/mpeg": "mp3",
    "video/mp4": "mp4",
    "application/zip": "zip",
    "text/plain": "txt",
    "application/msword": "doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
      "docx",
    "application/pdf": "pdf",
  };
  return extensions[mime] || "bin";
}

async function copyToClipboard() {
  const sharedNote = document.getElementById("sharedNote").value;
  if (!sharedNote) {
    document.getElementById("status").textContent = "Nothing to copy";
    return;
  }
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(sharedNote);
    } else {
      const ta = document.getElementById("sharedNote");
      ta.select();
      document.execCommand("copy");
      window.getSelection().removeAllRanges();
    }
    document.getElementById("status").textContent = "Copied to clipboard!";
  } catch (e) {
    console.error("Copy failed:", e);
    document.getElementById("status").textContent = "Copy failed";
  }
}

function updateHistoryUI() {
  const historyList = document.getElementById("historyList");
  historyList.innerHTML = "";
  history.forEach((entry) => {
    const li = document.createElement("li");
    li.textContent = entry.id;
    li.className = "cursor-pointer text-blue-600 hover:text-blue-800 mt-2";
    li.onclick = () => downloadEncryptedNote(entry.data, entry.id);
    historyList.appendChild(li);
  });
}

function downloadEncryptedNote(data, filename) {
  const blob = new Blob([data], { type: "application/octet-stream" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename.replace(" ", "_") + ".enc";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
}

window.onload = function () {
  // initialize in encrypt mode
  setMode("encrypt");
  fileList = [];
  updateFileListUI();
  document.getElementById("note").value = "";
  document.getElementById("sharedNote").value = "";
};
