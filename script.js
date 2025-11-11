(async function () {
  // --- Utilities ------------------------------------------------------------

  function u8ToBase64(u8) {
    // Efficient base64 for Uint8Array
    // Avoid large intermediate strings using chunking for very large arrays
    let binary = "";
    const chunkSize = 0x8000; // 32KB
    for (let i = 0; i < u8.length; i += chunkSize) {
      binary += String.fromCharCode.apply(
        null,
        u8.subarray(i, Math.min(i + chunkSize, u8.length))
      );
    }
    return btoa(binary);
  }

  function base64ToU8(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function strToU8(str) {
    return new TextEncoder().encode(str);
  }

  function u8ToStr(u8) {
    return new TextDecoder().decode(u8);
  }

  function randomBytes(length) {
    const a = new Uint8Array(length);
    crypto.getRandomValues(a);
    return a;
  }

  // --- WebCrypto wrappers --------------------------------------------------

  async function deriveKeyWebCrypto(
    passphrase,
    saltBase64,
    iterations = 100000
  ) {
    // passphrase: string, saltBase64: base64 encoded Uint8Array
    const salt = base64ToU8(saltBase64);
    const passU8 = strToU8(passphrase);
    const baseKey = await crypto.subtle.importKey(
      "raw",
      passU8,
      { name: "PBKDF2" },
      false,
      ["deriveKey", "deriveBits"]
    );
    // derive a 256-bit AES-GCM key
    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    return key;
  }

  async function deriveRawKeyBytes(
    passphrase,
    saltBase64,
    iterations = 100000
  ) {
    // If you want raw key bytes (e.g., to pass to legacy code), use deriveBits
    const salt = base64ToU8(saltBase64);
    const passU8 = strToU8(passphrase);
    const baseKey = await crypto.subtle.importKey(
      "raw",
      passU8,
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      baseKey,
      256
    ); // 256 bits
    return new Uint8Array(bits);
  }

  async function aesGcmEncrypt(
    key,
    plaintextU8,
    ivU8,
    additionalDataU8 = null
  ) {
    // key: CryptoKey (AES-GCM), plaintextU8: Uint8Array, ivU8: Uint8Array(12)
    const params = {
      name: "AES-GCM",
      iv: ivU8,
      tagLength: 128,
    };
    if (additionalDataU8) params.additionalData = additionalDataU8;
    const ctBuffer = await crypto.subtle.encrypt(params, key, plaintextU8);
    // WebCrypto returns ciphertext + tag concatenated (AES-GCM)
    return new Uint8Array(ctBuffer);
  }

  async function aesGcmDecrypt(
    key,
    ciphertextPlusTagU8,
    ivU8,
    additionalDataU8 = null
  ) {
    const params = {
      name: "AES-GCM",
      iv: ivU8,
      tagLength: 128,
    };
    if (additionalDataU8) params.additionalData = additionalDataU8;
    // If auth fails, this throws a DOMException (e.g., "OperationError" or "SecurityError")
    const ptBuffer = await crypto.subtle.decrypt(
      params,
      key,
      ciphertextPlusTagU8
    );
    return new Uint8Array(ptBuffer);
  }

  // --- Backwards compatibility helpers (exposed API) -----------------------

  // We will produce the same JSON envelope structure as before:
  // { type, data: [{ iv, data, salt }, ...], mime: [...] }
  // where iv/data/salt are base64-encoded Uint8Array blobs

  // --- Mode management + state (unchanged/adjusted) -------------------------
  let currentMode = "encrypt";
  let lastEncryptPassphrase = "";
  let savedFileList = [];
  let savedNote = "";
  let isModeSwitch = false;
  let history = [];

  let decryptUploadedContent = "";
  let decryptUploadedFilename = "";

  // --- UI helper functions reused from original file (simplified where possible)
  // Assumes the HTML ids referenced exist in your page (same as original).

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
    const decryptFileContainer = document.getElementById(
      "decryptFileContainer"
    );
    const CopyBtn = document.getElementById("copyBtn");

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
      passphraseInput.className =
        "terminal-input w-full sm:w-1/2 px-4 py-3 rounded";
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
      passphraseInput.className =
        "terminal-input w-full sm:w-1/2 px-4 py-3 rounded"; // responsive width in decrypt mode
      savedFileList = [...savedFileList];
      savedNote = noteInput.value;
      document.getElementById("status").textContent = "";
      decryptUploadedContent = "";
      decryptUploadedFilename = "";
      document.getElementById("decryptFileLabel").textContent =
        "NO FILE SELECTED";
    }

    isModeSwitch = false;
  }

  // File UI helpers (kept same behaviour)
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

  // --- ENCRYPT (saveNote) --------------------------------------------------
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
        dataArray.push(strToU8(note));
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
          dataArray.push(new Uint8Array(await file.arrayBuffer()));
        }
      }

      const encryptedData = [];
      for (let data of dataArray) {
        const saltBytes = randomBytes(16);
        const saltB64 = u8ToBase64(saltBytes);
        const key = await deriveKeyWebCrypto(passphrase, saltB64, 100000);
        const iv = randomBytes(12);
        const ivB64 = u8ToBase64(iv);
        // WebCrypto AES-GCM returns ciphertext concatenated with tag
        const ciphertextWithTag = await aesGcmEncrypt(key, data, iv);
        const dataB64 = u8ToBase64(ciphertextWithTag);

        encryptedData.push({
          iv: ivB64,
          data: dataB64,
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
          "✅ Note/File(s) encrypted successfully! Copy the encrypted text to share.";
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
        "Error encrypting note/file: " + e.message;
    } finally {
      spinner.style.display = "none";
    }
  }

  // --- DECRYPT file upload support -----------------------------------------
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

  // --- LOAD / DECRYPT (secure) ---------------------------------------------
  // IMPORTANT: do not expose any decrypted data to the UI unless authentication succeeded.
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
        // fallback legacy structure which had iv, data, salt at top-level
        const { iv: ivStr, data: encryptedStr, salt } = parsed;
        if (!ivStr || !encryptedStr || !salt)
          throw new Error("⚠️ Invalid legacy encrypted format");

        const ivU8 = base64ToU8(ivStr);
        const ciphertextWithTag = base64ToU8(encryptedStr);
        const key = await deriveKeyWebCrypto(passphrase, salt);
        // Attempt decryption; WebCrypto will throw on auth failure — we catch and fail without exposing plaintext
        let decrypted;
        try {
          decrypted = await aesGcmDecrypt(key, ciphertextWithTag, ivU8);
        } catch (err) {
          // Authentication/Integrity failed (wrong passphrase or tampered)
          console.warn("Decryption/auth failed (legacy):", err);
          document.getElementById("status").textContent =
            "⚠️ Invalid Encrypted note or wrong passphrase.";
          return;
        }

        // Only expose plaintext now that decryption & auth succeeded
        document.getElementById("note").value = u8ToStr(decrypted);
        document.getElementById("inputContainer").classList.remove("hidden");
        document.getElementById("status").textContent =
          "Note decrypted successfully!";
        return;
      }

      // modern multi-item format
      const { type, data: encryptedData, mime } = parsed;
      if (!encryptedData || !Array.isArray(encryptedData))
        throw new Error("⚠️ Invalid encrypted payload");

      // If the sender included a file-type suggestion, set it silently
      const fileTypeSelect = document.getElementById("fileType");
      if (type === "text") {
        fileTypeSelect.value = "text";
      }

      // We'll collect decrypted blobs but will NOT expose them until all items decrypt successfully.
      const decryptedResults = [];

      for (let i = 0; i < encryptedData.length; i++) {
        const { iv, data, salt } = encryptedData[i];
        if (!iv || !data || !salt) throw new Error("Malformed encrypted item");
        const ivU8 = base64ToU8(iv);
        const ciphertextWithTag = base64ToU8(data);
        const key = await deriveKeyWebCrypto(passphrase, salt);

        let decrypted;
        try {
          decrypted = await aesGcmDecrypt(key, ciphertextWithTag, ivU8);
        } catch (err) {
          // Authentication/Integrity failed for this item
          console.warn("Decryption/auth failed for item", i, err);
          document.getElementById("status").textContent =
            "⚠️ Invalid Encrypted note or wrong passphrase.";
          return;
        }

        decryptedResults.push({
          decrypted,
          mime: mime && mime[i] ? mime[i] : "application/octet-stream",
        });
      }

      // Only after all items decrypted successfully do we expose them to the UI:
      for (let i = 0; i < decryptedResults.length; i++) {
        const { decrypted, mime: m } = decryptedResults[i];
        const blob = new Blob([decrypted], { type: m });
        if (type === "text") {
          document.getElementById("note").value = u8ToStr(decrypted);
          document.getElementById("inputContainer").classList.remove("hidden");
        } else {
          const container = document.createElement("div");
          container.className =
            "preview-container mb-4 p-4 border border-green-500/30 rounded";
          if (
            m.startsWith("image/") ||
            m.startsWith("audio/") ||
            m.startsWith("video/")
          ) {
            const preview = document.createElement(
              m.startsWith("image/")
                ? "img"
                : m.startsWith("audio/")
                ? "audio"
                : "video"
            );
            preview.controls = m.startsWith("audio/") || m.startsWith("video/");
            preview.src = URL.createObjectURL(blob);
            if (m.startsWith("image/")) preview.style.maxWidth = "100%";
            container.appendChild(preview);
          } else {
            const previewLink = document.createElement("a");
            previewLink.href = URL.createObjectURL(blob);
            previewLink.textContent = "Preview " + getExtension(m);
            previewLink.target = "_blank";
            container.appendChild(previewLink);
          }
          const downloadLink = document.createElement("a");
          downloadLink.href = URL.createObjectURL(blob);
          downloadLink.download =
            "decrypted_file_" + (i + 1) + "." + getExtension(m);
          downloadLink.textContent = "Download " + getExtension(m);
          downloadLink.className =
            "bg-blue-600 text-white px-4 py-2 rounded-md font-semibold hover:bg-blue-700";
          container.appendChild(downloadLink);
          document.getElementById("outputContainer").appendChild(container);
        }
      }

      document.getElementById("status").textContent =
        "✅ File(s) decrypted successfully!";
    } catch (e) {
      console.error("Decryption error:", e);
      document.getElementById("status").textContent =
        "⚠️ Invalid Encrypted note or wrong passphrase.";
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

  function copyToClipboard() {
    const sharedNote = document.getElementById("sharedNote");
    sharedNote.select();
    document.execCommand("copy");
    document.getElementById("status").textContent = "Copied to clipboard!";
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

  // --- Self-tests -----------------------------------------------------------
  // These are lightweight automated checks you can run in the browser console
  // or trigger from the UI for demonstrations. They use the same public API
  // (deriveKeyWebCrypto + aesGcmEncrypt/aesGcmDecrypt).

  async function runSelfTests() {
    const tests = [];
    // 1) Round-trip text
    tests.push(
      (async () => {
        const pass = "test-pass-" + Math.random().toString(36).slice(2);
        const plain = strToU8("Hello WebCrypto round-trip ✓");
        const salt = randomBytes(16);
        const saltB64 = u8ToBase64(salt);
        const key = await deriveKeyWebCrypto(pass, saltB64);
        const iv = randomBytes(12);
        const ct = await aesGcmEncrypt(key, plain, iv);
        const key2 = await deriveKeyWebCrypto(pass, saltB64);
        const dec = await aesGcmDecrypt(key2, ct, iv);
        const ok = u8ToStr(dec) === u8ToStr(plain);
        return { name: "Round-trip text", ok };
      })()
    );

    // 2) Wrong passphrase detection
    tests.push(
      (async () => {
        const pass = "correct-pass";
        const wrongPass = "wrong-pass";
        const plain = strToU8("Secret data");
        const salt = randomBytes(16);
        const saltB64 = u8ToBase64(salt);
        const key = await deriveKeyWebCrypto(pass, saltB64);
        const iv = randomBytes(12);
        const ct = await aesGcmEncrypt(key, plain, iv);
        try {
          const wrongKey = await deriveKeyWebCrypto(wrongPass, saltB64);
          await aesGcmDecrypt(wrongKey, ct, iv);
          // if decrypt succeeds with wrong key, that's a failure
          return { name: "Wrong-passphrase test", ok: false };
        } catch (e) {
          // expected: decryption fails
          return { name: "Wrong-passphrase test", ok: true };
        }
      })()
    );

    // 3) Cross-browser-ish: deriveKey yields consistent 32-byte derived raw bits
    tests.push(
      (async () => {
        const pass = "cross-browser-pass";
        const salt = randomBytes(16);
        const saltB64 = u8ToBase64(salt);
        const raw1 = await deriveRawKeyBytes(pass, saltB64);
        const raw2 = await deriveRawKeyBytes(pass, saltB64);
        const same =
          raw1.length === raw2.length && raw1.every((v, i) => v === raw2[i]);
        return { name: "Derive deterministic", ok: same };
      })()
    );

    const results = await Promise.all(tests);
    // Summarize
    console.group("Self-test results");
    let allOK = true;
    results.forEach((r) => {
      console.log(`${r.name}: ${r.ok ? "PASS" : "FAIL"}`);
      if (!r.ok) allOK = false;
    });
    console.groupEnd();
    return { allOK, results };
  }

  // Expose some functions for manual/console use (for demo or tests)
  window.cryptoUtilities = {
    u8ToBase64,
    base64ToU8,
    deriveKeyWebCrypto,
    deriveRawKeyBytes,
    aesGcmEncrypt,
    aesGcmDecrypt,
    runSelfTests,
    randomBytes,
  };

  // --- Attach UI bindings to global scope (so HTML can call them) ----------
  window.setMode = setMode;
  window.toggleInput = toggleInput;
  window.handleFiles = handleFiles;
  window.saveNote = saveNote;
  window.handleDecryptFile = handleDecryptFile;
  window.loadSharedNote = loadSharedNote;
  window.copyToClipboard = copyToClipboard;
  window.updateHistoryUI = updateHistoryUI;
  window.downloadEncryptedNote = downloadEncryptedNote;
  window.runSelfTests = runSelfTests;

  // --- Initialization on load ---------------------------------------------
  window.addEventListener("load", () => {
    try {
      setMode("encrypt");
      fileList = [];
      updateFileListUI();
      const noteEl = document.getElementById("note");
      const sharedNoteEl = document.getElementById("sharedNote");
      if (noteEl) noteEl.value = "";
      if (sharedNoteEl) sharedNoteEl.value = "";
      console.info("Crypto utilities (WebCrypto) initialized.");
    } catch (e) {
      console.error("Initialization error:", e);
    }
  });
})();
