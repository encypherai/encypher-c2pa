import init, { verify } from "../../bindings/wasm/pkg/encypher_c2pa_wasm.js";

const assetInput = document.querySelector("#asset");
const verifyButton = document.querySelector("#verify");
const result = document.querySelector("#result");

await init();
result.textContent = "Ready. Choose a file to verify.";
assetInput.disabled = false;

assetInput.addEventListener("change", () => {
  verifyButton.disabled = assetInput.files.length !== 1;
});

verifyButton.addEventListener("click", async () => {
  const [file] = assetInput.files;
  if (!file) return;
  verifyButton.disabled = true;
  result.className = "";
  result.textContent = "Verifying locally...";
  try {
    const report = verify(new Uint8Array(await file.arrayBuffer()), file.type || inferMime(file.name));
    result.className = report.integrity === "valid" ? "valid" : "invalid";
    result.textContent = JSON.stringify({
      profile: report.profile,
      provenance: report.present ? "present" : "absent",
      integrity: report.integrity,
      signature: report.signature,
      hard_binding: report.hard_binding,
      trust: report.trust,
      failures: report.validation_results.failure,
    }, null, 2);
  } catch (error) {
    result.className = "invalid";
    result.textContent = String(error);
  } finally {
    verifyButton.disabled = false;
  }
});

function inferMime(name) {
  const extension = name.split(".").pop()?.toLowerCase();
  return ({
    jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp",
    mp4: "video/mp4", mov: "video/quicktime", wav: "audio/wav", mp3: "audio/mpeg",
    pdf: "application/pdf", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  })[extension] || "application/octet-stream";
}
