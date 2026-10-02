"use strict";
// app.ts — Extension Fixer
// Scans a chosen folder/files, reads each file's byte signature ("magic number"),
// shows what needs fixing, lets you filter to only-changed, and builds zips
// (preserving folder structure) — either everything, or only what needs renaming.
// Compiled to app.js via `tsc` (see tsconfig.json). No logic lives in the HTML.
function bytesStartWith(bytes, pattern, offset = 0) {
    if (bytes.length < offset + pattern.length)
        return false;
    for (let i = 0; i < pattern.length; i++) {
        if (bytes[offset + i] !== pattern[i])
            return false;
    }
    return true;
}
function asciiAt(bytes, offset, text) {
    if (bytes.length < offset + text.length)
        return false;
    for (let i = 0; i < text.length; i++) {
        if (bytes[offset + i] !== text.charCodeAt(i))
            return false;
    }
    return true;
}
// Order matters: more specific formats are checked before generic containers (e.g. ZIP).
const SIGNATURES = [
    { extension: "png", mimeType: "image/png", match: (b) => bytesStartWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
    { extension: "jpg", mimeType: "image/jpeg", match: (b) => bytesStartWith(b, [0xff, 0xd8, 0xff]) },
    { extension: "gif", mimeType: "image/gif", match: (b) => asciiAt(b, 0, "GIF87a") || asciiAt(b, 0, "GIF89a") },
    { extension: "webp", mimeType: "image/webp", match: (b) => asciiAt(b, 0, "RIFF") && asciiAt(b, 8, "WEBP") },
    { extension: "wav", mimeType: "audio/wav", match: (b) => asciiAt(b, 0, "RIFF") && asciiAt(b, 8, "WAVE") },
    { extension: "bmp", mimeType: "image/bmp", match: (b) => bytesStartWith(b, [0x42, 0x4d]) },
    { extension: "pdf", mimeType: "application/pdf", match: (b) => asciiAt(b, 0, "%PDF") },
    {
        extension: "mp3",
        mimeType: "audio/mpeg",
        match: (b) => asciiAt(b, 0, "ID3") ||
            bytesStartWith(b, [0xff, 0xfb]) ||
            bytesStartWith(b, [0xff, 0xf3]) ||
            bytesStartWith(b, [0xff, 0xf2]),
    },
    { extension: "flac", mimeType: "audio/flac", match: (b) => asciiAt(b, 0, "fLaC") },
    { extension: "webm", mimeType: "video/webm", match: (b) => bytesStartWith(b, [0x1a, 0x45, 0xdf, 0xa3]) },
    // Covers MP4, MOV, M4A, M4V — all share the "ftyp" box at byte offset 4.
    { extension: "mp4", mimeType: "video/mp4", match: (b) => asciiAt(b, 4, "ftyp") },
    { extension: "gz", mimeType: "application/gzip", match: (b) => bytesStartWith(b, [0x1f, 0x8b]) },
    { extension: "7z", mimeType: "application/x-7z-compressed", match: (b) => bytesStartWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
    { extension: "rar", mimeType: "application/vnd.rar", match: (b) => asciiAt(b, 0, "Rar!") },
    {
        // Generic ZIP container — also matches APK, DOCX, XLSX, PPTX, JAR.
        extension: "zip",
        mimeType: "application/zip",
        match: (b) => bytesStartWith(b, [0x50, 0x4b, 0x03, 0x04]) ||
            bytesStartWith(b, [0x50, 0x4b, 0x05, 0x06]) ||
            bytesStartWith(b, [0x50, 0x4b, 0x07, 0x08]),
    },
];
async function readHeaderBytes(file, length = 16) {
    const buffer = await file.slice(0, length).arrayBuffer();
    return new Uint8Array(buffer);
}
function detectSignature(bytes) {
    for (const signature of SIGNATURES) {
        if (signature.match(bytes))
            return signature;
    }
    return null;
}
function hasKnownExtension(name, extension) {
    return name.toLowerCase().endsWith("." + extension.toLowerCase());
}
async function scanFiles(files) {
    const results = [];
    for (const file of files) {
        const bytes = await readHeaderBytes(file);
        const signature = detectSignature(bytes);
        const relativePath = file.webkitRelativePath || file.name;
        results.push({
            file,
            relativePath,
            detectedExtension: signature ? signature.extension : null,
            mimeType: signature ? signature.mimeType : null,
        });
    }
    return results;
}
function buildOutputName(result) {
    const originalName = result.file.name;
    if (result.detectedExtension === null)
        return originalName; // unknown: leave as-is
    if (hasKnownExtension(originalName, result.detectedExtension))
        return originalName; // already correct
    return `${originalName}.${result.detectedExtension}`;
}
function isChanged(result) {
    return buildOutputName(result) !== result.file.name;
}
function isImageMime(mimeType) {
    return mimeType !== null && mimeType.startsWith("image/");
}
function splitPath(relativePath) {
    const idx = relativePath.lastIndexOf("/");
    if (idx === -1)
        return { dir: "", base: relativePath };
    return { dir: relativePath.slice(0, idx), base: relativePath.slice(idx + 1) };
}
// Where the corrected copy goes inside a zip — same folder it came from, corrected filename.
function buildOutputRelativePath(result) {
    const { dir } = splitPath(result.relativePath);
    const correctedBase = buildOutputName(result);
    return dir ? `${dir}/${correctedBase}` : correctedBase;
}
function formatBytes(size) {
    if (size < 1024)
        return `${size} B`;
    if (size < 1024 * 1024)
        return `${(size / 1024).toFixed(1)} KB`;
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}
// --- State ----------------------------------------------------------------
let currentItems = [];
let previewVisible = false;
let filterMode = "all";
let celebrationTimeoutId;
function revokeAllPreviewUrls() {
    for (const item of currentItems) {
        if (item.previewUrl)
            URL.revokeObjectURL(item.previewUrl);
    }
}
function getFilteredItems() {
    return filterMode === "changed" ? currentItems.filter((i) => isChanged(i.result)) : currentItems;
}
// --- Rendering --------------------------------------------------------------
function renderTable(items) {
    const tableBody = document.getElementById("results-body");
    if (!tableBody)
        return;
    tableBody.innerHTML = "";
    if (items.length === 0) {
        const emptyRow = document.createElement("tr");
        const emptyCell = document.createElement("td");
        emptyCell.colSpan = 4;
        emptyCell.className = "empty-state";
        emptyCell.textContent =
            filterMode === "changed" ? "Nothing needs renaming — all clear 🎉" : "No files scanned yet.";
        emptyRow.appendChild(emptyCell);
        tableBody.appendChild(emptyRow);
        return;
    }
    items.forEach((item, index) => {
        const result = item.result;
        const changed = isChanged(result);
        const row = document.createElement("tr");
        row.className = changed ? "changed row-in" : "row-in";
        row.style.animationDelay = `${Math.min(index * 25, 400)}ms`;
        const pathCell = document.createElement("td");
        const { dir, base } = splitPath(result.relativePath);
        pathCell.innerHTML = dir
            ? `<span class="dir">${dir}/</span><span class="base">${base}</span>`
            : `<span class="base">${base}</span>`;
        row.appendChild(pathCell);
        const detectedCell = document.createElement("td");
        detectedCell.textContent = result.detectedExtension ? result.detectedExtension.toUpperCase() : "Unknown";
        detectedCell.className = result.detectedExtension ? "detected" : "unknown";
        row.appendChild(detectedCell);
        const newNameCell = document.createElement("td");
        if (changed) {
            newNameCell.innerHTML = `<span class="arrow">→</span> ${buildOutputName(result)}`;
            newNameCell.className = "will-change";
        }
        else {
            newNameCell.textContent = "✓ already correct";
            newNameCell.className = "ok";
        }
        row.appendChild(newNameCell);
        const sizeCell = document.createElement("td");
        sizeCell.textContent = formatBytes(result.file.size);
        row.appendChild(sizeCell);
        tableBody.appendChild(row);
    });
}
function renderPreviewGrid(items) {
    const grid = document.getElementById("preview-grid");
    if (!grid)
        return;
    grid.innerHTML = "";
    const imageItems = items.filter((i) => i.previewUrl !== null);
    if (imageItems.length === 0) {
        const empty = document.createElement("p");
        empty.className = "empty-state";
        empty.textContent =
            filterMode === "changed" ? "No changed images in this selection." : "No images to preview.";
        grid.appendChild(empty);
        return;
    }
    imageItems.forEach((item, index) => {
        var _a;
        const result = item.result;
        const changed = isChanged(result);
        const card = document.createElement("div");
        card.className = changed ? "card changed card-in" : "card card-in";
        card.style.animationDelay = `${Math.min(index * 30, 400)}ms`;
        const img = document.createElement("img");
        img.src = item.previewUrl;
        img.loading = "lazy";
        img.alt = result.file.name;
        card.appendChild(img);
        const meta = document.createElement("div");
        meta.className = "card-meta";
        const nameEl = document.createElement("div");
        nameEl.className = "card-name";
        nameEl.textContent = result.file.name;
        meta.appendChild(nameEl);
        const tagEl = document.createElement("div");
        tagEl.className = changed ? "card-tag will-change" : "card-tag ok";
        tagEl.textContent = changed ? `→ ${(_a = result.detectedExtension) === null || _a === void 0 ? void 0 : _a.toUpperCase()}` : "correct";
        meta.appendChild(tagEl);
        const sizeEl = document.createElement("div");
        sizeEl.className = "card-size";
        sizeEl.textContent = formatBytes(result.file.size);
        meta.appendChild(sizeEl);
        card.appendChild(meta);
        grid.appendChild(card);
    });
}
function updateSummaryAndButtons() {
    const summary = document.getElementById("summary");
    const downloadAllButton = document.getElementById("download-all-button");
    const downloadChangedButton = document.getElementById("download-changed-button");
    const previewToggleButton = document.getElementById("preview-toggle-button");
    const filterAllButton = document.getElementById("filter-all-button");
    const filterChangedButton = document.getElementById("filter-changed-button");
    const total = currentItems.length;
    const changedCount = currentItems.filter((i) => isChanged(i.result)).length;
    if (summary) {
        summary.textContent =
            total === 0
                ? ""
                : `${total} file${total === 1 ? "" : "s"} scanned — ${changedCount} need renaming.`;
    }
    if (downloadAllButton)
        downloadAllButton.disabled = total === 0;
    if (downloadChangedButton) {
        downloadChangedButton.disabled = changedCount === 0;
        downloadChangedButton.textContent =
            changedCount === 0 ? "Download changed only" : `Download changed only (${changedCount})`;
    }
    const filteredImageCount = getFilteredItems().filter((i) => i.previewUrl !== null).length;
    if (previewToggleButton)
        previewToggleButton.disabled = filteredImageCount === 0;
    if (filterAllButton)
        filterAllButton.textContent = `All files (${total})`;
    if (filterChangedButton)
        filterChangedButton.textContent = `Only changed (${changedCount})`;
}
function refreshViews() {
    const filtered = getFilteredItems();
    renderTable(filtered);
    renderPreviewGrid(filtered);
    updateSummaryAndButtons();
}
function renderResults(results) {
    revokeAllPreviewUrls();
    currentItems = results.map((result) => ({
        result,
        previewUrl: isImageMime(result.mimeType) ? URL.createObjectURL(result.file) : null,
    }));
    refreshViews();
}
// --- Zip building (always uses the full set, independent of the display filter) --
async function buildZipBlob(items, onlyChanged) {
    const zip = new JSZip();
    for (const item of items) {
        if (onlyChanged && !isChanged(item.result))
            continue;
        zip.file(buildOutputRelativePath(item.result), item.result.file);
    }
    return zip.generateAsync({ type: "blob" });
}
function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
}
function setStatus(text, busy = false) {
    const status = document.getElementById("status");
    const statusText = document.getElementById("status-text");
    if (statusText)
        statusText.textContent = text;
    if (status)
        status.classList.toggle("busy", busy);
}
function initBackgroundAnimation() {
    const canvas = document.getElementById("bg-canvas");
    if (!canvas)
        return;
    const ctx = canvas.getContext("2d");
    if (!ctx)
        return;
    let width = window.innerWidth;
    let height = window.innerHeight;
    function resize() {
        width = window.innerWidth;
        height = window.innerHeight;
        if (canvas) {
            canvas.width = width;
            canvas.height = height;
        }
    }
    resize();
    window.addEventListener("resize", resize);
    const orbs = [];
    const orbCount = 7;
    for (let i = 0; i < orbCount; i++) {
        const angle = (i / orbCount) * Math.PI * 2;
        orbs.push({
            x: Math.random() * width,
            y: Math.random() * height,
            vx: Math.cos(angle) * (0.5 + Math.random() * 0.6),
            vy: Math.sin(angle) * (0.5 + Math.random() * 0.6),
            radius: 160 + Math.random() * 200,
            hue: i % 2 === 0 ? 145 : 28, // alternate accent green / warm ember
        });
    }
    // The canvas repaints the whole backdrop every frame, so it never depends on
    // CSS stacking order elsewhere on the page — it IS the background, always.
    function draw() {
        if (!ctx || !canvas)
            return;
        ctx.fillStyle = "#f7f5f1";
        ctx.fillRect(0, 0, width, height);
        ctx.globalCompositeOperation = "lighter";
        for (const orb of orbs) {
            orb.x += orb.vx;
            orb.y += orb.vy;
            if (orb.x < -orb.radius)
                orb.x = width + orb.radius;
            if (orb.x > width + orb.radius)
                orb.x = -orb.radius;
            if (orb.y < -orb.radius)
                orb.y = height + orb.radius;
            if (orb.y > height + orb.radius)
                orb.y = -orb.radius;
            const gradient = ctx.createRadialGradient(orb.x, orb.y, 0, orb.x, orb.y, orb.radius);
            gradient.addColorStop(0, `hsla(${orb.hue}, 60%, 55%, 0.16)`);
            gradient.addColorStop(1, "hsla(0, 0%, 100%, 0)");
            ctx.fillStyle = gradient;
            ctx.beginPath();
            ctx.arc(orb.x, orb.y, orb.radius, 0, Math.PI * 2);
            ctx.fill();
        }
        ctx.globalCompositeOperation = "source-over";
        requestAnimationFrame(draw);
    }
    requestAnimationFrame(draw);
}
function burstConfetti() {
    var _a;
    const canvas = document.getElementById("confetti-canvas");
    if (!canvas)
        return;
    const ctx = canvas.getContext("2d");
    if (!ctx)
        return;
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    canvas.classList.add("active");
    const colors = ["#3a5a40", "#dce7dd", "#b5482f", "#f4ded8", "#1c1b19", "#ffd166"];
    const particleCount = 100;
    const particles = [];
    const originX = canvas.width / 2;
    const originY = canvas.height * 0.5;
    for (let i = 0; i < particleCount; i++) {
        const angle = Math.random() * Math.PI - Math.PI * 1.5;
        const speed = 4 + Math.random() * 7;
        particles.push({
            x: originX + (Math.random() - 0.5) * 140,
            y: originY,
            vx: Math.cos(angle) * speed,
            vy: Math.sin(angle) * speed - 6,
            size: 5 + Math.random() * 5,
            rotation: Math.random() * 360,
            rotationSpeed: (Math.random() - 0.5) * 16,
            color: (_a = colors[Math.floor(Math.random() * colors.length)]) !== null && _a !== void 0 ? _a : "#3a5a40",
            life: 1,
        });
    }
    const gravity = 0.2;
    const maxFrames = 130;
    let frame = 0;
    function step() {
        if (!ctx || !canvas)
            return;
        frame++;
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (const p of particles) {
            p.vy += gravity;
            p.x += p.vx;
            p.y += p.vy;
            p.rotation += p.rotationSpeed;
            p.life = Math.max(0, 1 - frame / maxFrames);
            ctx.save();
            ctx.translate(p.x, p.y);
            ctx.rotate((p.rotation * Math.PI) / 180);
            ctx.globalAlpha = p.life;
            ctx.fillStyle = p.color;
            ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size * 0.6);
            ctx.restore();
        }
        if (frame < maxFrames) {
            requestAnimationFrame(step);
        }
        else {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            canvas.classList.remove("active");
        }
    }
    requestAnimationFrame(step);
}
function showCelebrationPopup(totalCount, changedCount) {
    const popup = document.getElementById("celebration-popup");
    const title = document.getElementById("celebration-title");
    const subtitle = document.getElementById("celebration-subtitle");
    if (!popup)
        return;
    if (title)
        title.textContent = "🎉 Scan Complete!";
    if (subtitle) {
        subtitle.textContent =
            changedCount > 0
                ? `${totalCount} file${totalCount === 1 ? "" : "s"} scanned — ${changedCount} ready to fix`
                : `${totalCount} file${totalCount === 1 ? "" : "s"} scanned — all already correct`;
    }
    popup.classList.remove("show");
    void popup.offsetWidth; // force reflow so the pop-in / floater animations replay
    popup.classList.add("show");
    if (celebrationTimeoutId !== undefined)
        window.clearTimeout(celebrationTimeoutId);
    celebrationTimeoutId = window.setTimeout(() => {
        popup.classList.remove("show");
    }, 3200);
}
function triggerCelebration(totalCount, changedCount) {
    showCelebrationPopup(totalCount, changedCount);
    burstConfetti();
}
// --- Event handlers ----------------------------------------------------------
async function handleFolderSelected(event) {
    const input = event.target;
    const fileList = input.files;
    if (!fileList || fileList.length === 0)
        return;
    setStatus("Scanning…", true);
    const files = Array.from(fileList);
    const results = await scanFiles(files);
    renderResults(results);
    setStatus(`Done — ${results.length} file${results.length === 1 ? "" : "s"} scanned.`, false);
    const changedCount = results.filter(isChanged).length;
    triggerCelebration(results.length, changedCount);
}
async function handleDownloadAll() {
    if (currentItems.length === 0)
        return;
    setStatus("Building zip…", true);
    const blob = await buildZipBlob(currentItems, false);
    triggerDownload(blob, "fixed-files-all.zip");
    setStatus("Downloaded fixed-files-all.zip", false);
}
async function handleDownloadChanged() {
    const changedCount = currentItems.filter((i) => isChanged(i.result)).length;
    if (changedCount === 0)
        return;
    setStatus("Building zip…", true);
    const blob = await buildZipBlob(currentItems, true);
    triggerDownload(blob, "fixed-files-changed.zip");
    setStatus("Downloaded fixed-files-changed.zip", false);
}
function handlePreviewToggle() {
    previewVisible = !previewVisible;
    const grid = document.getElementById("preview-grid");
    const tableScroll = document.getElementById("table-scroll");
    const button = document.getElementById("preview-toggle-button");
    if (grid)
        grid.classList.toggle("visible", previewVisible);
    if (tableScroll)
        tableScroll.classList.toggle("hidden", previewVisible);
    if (button)
        button.textContent = previewVisible ? "Show list" : "Preview images";
    if (previewVisible)
        renderPreviewGrid(getFilteredItems());
}
function setFilterMode(mode) {
    filterMode = mode;
    const filterAllButton = document.getElementById("filter-all-button");
    const filterChangedButton = document.getElementById("filter-changed-button");
    if (filterAllButton)
        filterAllButton.classList.toggle("active", mode === "all");
    if (filterChangedButton)
        filterChangedButton.classList.toggle("active", mode === "changed");
    refreshViews();
}
// --- Setup ----------------------------------------------------------
function supportsDirectoryPicker() {
    // iOS Safari (and some other mobile browsers) don't support webkitdirectory —
    // selecting it there just opens the normal single/multi file picker with no folders.
    return "webkitdirectory" in document.createElement("input");
}
function configurePicker() {
    const folderInput = document.getElementById("folder-input");
    const pickerLabel = document.getElementById("picker-label");
    if (!folderInput)
        return;
    if (supportsDirectoryPicker()) {
        folderInput.setAttribute("webkitdirectory", "");
        folderInput.setAttribute("directory", "");
        if (pickerLabel)
            pickerLabel.textContent = "Choose folder";
    }
    else {
        folderInput.removeAttribute("webkitdirectory");
        folderInput.removeAttribute("directory");
        if (pickerLabel)
            pickerLabel.textContent = "Choose files";
    }
}
function init() {
    configurePicker();
    initBackgroundAnimation();
    const folderInput = document.getElementById("folder-input");
    const downloadAllButton = document.getElementById("download-all-button");
    const downloadChangedButton = document.getElementById("download-changed-button");
    const previewToggleButton = document.getElementById("preview-toggle-button");
    const filterAllButton = document.getElementById("filter-all-button");
    const filterChangedButton = document.getElementById("filter-changed-button");
    if (folderInput)
        folderInput.addEventListener("change", handleFolderSelected);
    if (downloadAllButton)
        downloadAllButton.addEventListener("click", handleDownloadAll);
    if (downloadChangedButton)
        downloadChangedButton.addEventListener("click", handleDownloadChanged);
    if (previewToggleButton)
        previewToggleButton.addEventListener("click", handlePreviewToggle);
    if (filterAllButton)
        filterAllButton.addEventListener("click", () => setFilterMode("all"));
    if (filterChangedButton)
        filterChangedButton.addEventListener("click", () => setFilterMode("changed"));
}
document.addEventListener("DOMContentLoaded", init);
