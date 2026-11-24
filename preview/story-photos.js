"use strict";

if (["localhost", "127.0.0.1", "[::1]"].includes(location.hostname)) {
  loadFamilyPhotos();
  enablePhotoDrafts();
}

function updatePhotoPlaceholder() {
  const galleries = document.querySelectorAll(".story-photos");
  document.querySelector("#photo-placeholder").hidden =
    Array.from(galleries).some(gallery => !gallery.hidden);
}

function loadFamilyPhotos() {
  const gallery = document.querySelector("#family-photos");
  const descriptions = [
    "Nala being held close",
    "Nala sitting with a blanket during treatment",
    "Nala dressed in a superhero costume",
    "Nala waving by a window",
    "Nala smiling",
  ];
  for (const [index, description] of descriptions.entries()) {
    const figure = document.createElement("figure");
    const photo = new Image();
    figure.hidden = true;
    photo.alt = description;
    photo.onload = () => {
      figure.hidden = false;
      gallery.hidden = false;
      updatePhotoPlaceholder();
    };
    figure.append(photo);
    gallery.append(figure);
    photo.src = "family-photos/nala-" + (index + 1) + ".jpg";
  }
}

async function enablePhotoDrafts() {
  const controls = document.querySelector("#photo-controls");
  const input = document.querySelector("#photo-files");
  const status = document.querySelector("#photo-status");
  const gallery = document.querySelector("#story-photos");
  const allowed = new Set(["image/jpeg", "image/png", "image/webp"]);
  let photos = [];
  let urls = [];
  let database;

  controls.hidden = false;

  function transact(mode, operation) {
    return new Promise((resolve, reject) => {
      const transaction = database.transaction("draft", mode);
      const request = operation(transaction.objectStore("draft"));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onabort = () => reject(transaction.error);
    });
  }

  function render() {
    gallery.replaceChildren();
    urls.forEach(url => URL.revokeObjectURL(url));
    urls = photos.map(photo => URL.createObjectURL(photo));
    urls.forEach((url, index) => {
      const figure = document.createElement("figure");
      const photo = document.createElement("img");
      photo.src = url;
      photo.alt = "Family photo " + (index + 1);
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Remove photo " + (index + 1);
      remove.addEventListener("click", () => {
        save(photos.filter((_, position) => position !== index), "Photo removed.");
      });
      figure.append(photo, remove);
      gallery.append(figure);
    });
    gallery.hidden = photos.length === 0;
    updatePhotoPlaceholder();
  }

  async function save(nextPhotos, message) {
    if (input.disabled) return;
    input.disabled = true;
    gallery.querySelectorAll("button").forEach(button => { button.disabled = true; });
    try {
      await transact("readwrite", store => store.put(nextPhotos, "photos"));
      photos = nextPhotos;
      render();
      status.textContent = message;
    } catch {
      status.textContent = "The changes could not be saved in this browser.";
    } finally {
      input.disabled = false;
      gallery.querySelectorAll("button").forEach(button => { button.disabled = false; });
    }
  }

  try {
    database = await new Promise((resolve, reject) => {
      const request = indexedDB.open("nalastrong-photo-preview", 1);
      request.onupgradeneeded = () => request.result.createObjectStore("draft");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    photos = (await transact("readonly", store => store.get("photos"))) ?? [];
    render();
    input.disabled = false;
  } catch {
    status.textContent = "Photo storage is unavailable in this browser.";
    return;
  }

  input.addEventListener("change", () => {
    const files = Array.from(input.files);
    input.value = "";
    if (!files.length) return;
    if (files.length + photos.length > 6) {
      status.textContent = "Choose up to six photos total.";
    } else if (files.some(file => !allowed.has(file.type) || file.size === 0 || file.size > 10_000_000)) {
      status.textContent = "Choose JPG, PNG, or WebP photos under 10 MB each.";
    } else {
      save([...photos, ...files], "Photos saved to this browser.");
    }
  });
}
