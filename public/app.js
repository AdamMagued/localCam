const error = document.querySelector("#error");
if (error) error.hidden = !new URLSearchParams(location.search).has("wrong");

const feed = document.querySelector("#feed");
if (feed) {
  const waiting = document.querySelector("#waiting");
  const refresh = () => {
    const next = new Image();
    next.onload = () => { feed.src = next.src; waiting.hidden = true; };
    next.onerror = () => { waiting.hidden = false; };
    next.src = `/frame?t=${Date.now()}`;
  };
  refresh();
  setInterval(refresh, 250);
}

const start = document.querySelector("#start");
if (start) {
  const camera = document.querySelector("#camera");
  const preview = document.querySelector("#preview");
  const canvas = document.querySelector("#canvas");
  const status = document.querySelector("#status");
  let stream;
  let timer;

  async function listCameras() {
    const selected = camera.value;
    const devices = (await navigator.mediaDevices.enumerateDevices()).filter(d => d.kind === "videoinput");
    camera.replaceChildren(...devices.map((d, i) => new Option(d.label || `Camera ${i + 1}`, d.deviceId)));
    if (devices.some(device => device.deviceId === selected)) camera.value = selected;
  }

  async function begin() {
    try {
      if (stream) stream.getTracks().forEach(track => track.stop());
      clearInterval(timer);
      stream = await navigator.mediaDevices.getUserMedia({
        video: camera.value ? { deviceId: { exact: camera.value } } : true,
        audio: false,
      });
      preview.srcObject = stream;
      await preview.play();
      await listCameras();
      status.textContent = "Broadcasting";
      timer = setInterval(publish, 200);
    } catch (problem) {
      status.textContent = `Camera error: ${problem.message}`;
    }
  }

  function publish() {
    if (!preview.videoWidth) return;
    canvas.width = Math.min(preview.videoWidth, 1280);
    canvas.height = Math.round(preview.videoHeight * canvas.width / preview.videoWidth);
    canvas.getContext("2d").drawImage(preview, 0, 0, canvas.width, canvas.height);
    canvas.toBlob(blob => {
      if (blob) fetch("/publish", { method: "POST", headers: { "Content-Type": "image/jpeg" }, body: blob });
    }, "image/jpeg", 0.75);
  }

  start.addEventListener("click", begin);
  camera.addEventListener("change", begin);
  listCameras();
}
