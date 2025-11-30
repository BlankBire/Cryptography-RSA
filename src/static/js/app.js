const API_URL = `${window.location.origin}/api`;
const state = {
  publicKey: null,
  privateKey: null,
};

const byId = (id) => document.getElementById(id);

function toggleVisibility(id, show) {
  const el = byId(id);
  if (!el) {
    return;
  }
  if (show) {
    el.style.removeProperty("display");
  } else {
    el.style.display = "none";
  }
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) {
    const message = data.error || response.statusText;
    throw new Error(message);
  }
  return data;
}

async function generateKeys() {
  toggleVisibility("keyGenerationLoading", true);
  toggleVisibility("keyGenerationResult", false);
  try {
    const data = await fetchJson(`${API_URL}/generate-keys`, {
      method: "POST",
    });
    state.publicKey = data.public_key;
    state.privateKey = data.private_key;
    if (state.publicKey) {
      byId("publicKey").textContent = JSON.stringify(state.publicKey, null, 2);
    }
    toggleVisibility("keyGenerationResult", true);
  } catch (error) {
    byId("publicKey").textContent = `Error: ${error.message}`;
    toggleVisibility("keyGenerationResult", true);
  } finally {
    toggleVisibility("keyGenerationLoading", false);
  }
}

async function encryptMessage() {
  if (!state.publicKey) {
    byId("encryptedMessage").textContent =
      "Error: Generate the public key first.";
    toggleVisibility("encryptionResult", true);
    return;
  }

  const message = byId("messageToEncrypt").value.trim();
  if (!message) {
    alert("Please enter a message to encrypt.");
    return;
  }

  try {
    const data = await fetchJson(`${API_URL}/encrypt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, public_key: state.publicKey }),
    });
    byId("encryptedMessage").textContent = data.encrypted;
  } catch (error) {
    byId("encryptedMessage").textContent = `Error: ${error.message}`;
  } finally {
    toggleVisibility("encryptionResult", true);
  }
}

async function getSignedMessage() {
  const resultDiv = byId("verificationResult");
  try {
    const data = await fetchJson(`${API_URL}/get-signed-message`);
    byId("serverMessage").value = data.message || "";
    byId("serverSignature").value = data.signature || "";
    resultDiv.className = "alert alert-success";
    resultDiv.textContent = "Received signed message from server.";
  } catch (error) {
    resultDiv.className = "alert alert-danger";
    resultDiv.textContent = `Error: ${error.message}`;
  } finally {
    resultDiv.style.display = "block";
  }
}

async function verifySignature() {
  const resultDiv = byId("verificationResult");
  try {
    const message = byId("serverMessage").value;
    const signature = byId("serverSignature").value;

    if (!message || !signature) {
      throw new Error("Fetch the signed message first.");
    }
    if (!state.publicKey) {
      throw new Error("Generate the public key first.");
    }

    const data = await fetchJson(`${API_URL}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, signature }),
    });

    if (data.is_valid) {
      resultDiv.className = "alert alert-success";
      resultDiv.textContent = "Signature is valid.";
    } else {
      resultDiv.className = "alert alert-danger";
      resultDiv.textContent = "Signature is invalid.";
    }
  } catch (error) {
    resultDiv.className = "alert alert-danger";
    resultDiv.textContent = `Error: ${error.message}`;
  } finally {
    resultDiv.style.display = "block";
  }
}

async function factorizeNumber() {
  const n = byId("nToFactor").value.trim();
  const method = byId("factorMethod").value;
  if (!n) {
    alert("Enter a modulus to factor.");
    return;
  }
  toggleVisibility("factorizationLoading", true);
  toggleVisibility("factorizationResult", false);
  try {
    const data = await fetchJson(`${API_URL}/factorize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ n, method }),
    });
    const resultContent = byId("factorizationOutput");
    if (data.success) {
      resultContent.innerHTML = `
                <p class="text-success">Factorization successful.</p>
                <p>Method used: ${data.method}</p>
                <ul>
                    <li>p = ${data.factors.p}</li>
                    <li>q = ${data.factors.q}</li>
                </ul>
                <p>Execution time: ${data.execution_time.toFixed(3)} s</p>
            `;
    } else {
      resultContent.innerHTML = `
                <p class="text-danger">Factorization failed.</p>
                <p>${data.message}</p>
                <p>Execution time: ${data.execution_time.toFixed(3)} s</p>
            `;
    }
    toggleVisibility("factorizationResult", true);
  } catch (error) {
    byId(
      "factorizationOutput"
    ).innerHTML = `<p class="text-danger">Error: ${error.message}</p>`;
    toggleVisibility("factorizationResult", true);
  } finally {
    toggleVisibility("factorizationLoading", false);
  }
}

async function runTimingAttack() {
  const n = byId("timingN").value.trim();
  const e = byId("timingE").value.trim();
  const trials = byId("timingTrials").value;

  if (!n || !e) {
    alert("Provide both modulus and public exponent.");
    return;
  }

  toggleVisibility("timingLoading", true);
  toggleVisibility("timingAttackResult", false);
  byId("timingAttackOutput").innerHTML = "";
  byId("timingInferenceOutput").innerHTML = "";

  try {
    const data = await fetchJson(`${API_URL}/timing-attack`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ n, e, trials }),
    });

    const resultContent = byId("timingAttackOutput");
    const inferenceContent = byId("timingInferenceOutput");

    let rows = data.results
      .map(
        (item) => `
                <tr>
                    <td>${item.trial}</td>
                    <td>${item.duration.toFixed(8)}</td>
                    <td>${item.plaintext}</td>
                </tr>`
      )
      .join("");

    resultContent.innerHTML = `
            <p class="text-success">Timing attack completed.</p>
            <h6>Statistics</h6>
            <ul>
                <li>Trials: ${data.statistics.trials}</li>
                <li>Average: ${data.statistics.average_time.toFixed(8)} s</li>
                <li>Min: ${data.statistics.min_time.toFixed(8)} s</li>
                <li>Max: ${data.statistics.max_time.toFixed(8)} s</li>
                <li>Variance: ${data.statistics.time_variance.toFixed(8)} s</li>
            </ul>
            <h6>Detailed Trials</h6>
            <div class="table-responsive">
                <table class="table table-sm align-middle">
                    <thead class="table-light">
                        <tr><th>#</th><th>Duration (s)</th><th>Plaintext</th></tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
            <p>Total time: ${data.execution_time.toFixed(3)} s</p>
        `;

    if (data.inference) {
      inferenceContent.innerHTML = `
                <ul>
                    <li>Target bit index: ${
                      data.inference.target_bit_index
                    }</li>
                    <li>Actual value: ${
                      data.inference.actual_bit_value ?? "N/A"
                    }</li>
                    <li>Inferred value: ${
                      data.inference.inferred_bit_value ?? "N/A"
                    }</li>
                    <li>Correct: <span class="${
                      data.inference.inference_correct
                        ? "text-success"
                        : "text-danger"
                    }">${
        data.inference.inference_correct ? "Yes" : "No"
      }</span></li>
                </ul>
            `;
    }

    toggleVisibility("timingAttackResult", true);
  } catch (error) {
    byId(
      "timingAttackOutput"
    ).innerHTML = `<p class="text-danger">Error: ${error.message}</p>`;
    toggleVisibility("timingAttackResult", true);
  } finally {
    toggleVisibility("timingLoading", false);
  }
}

async function runCCAAttack() {
  if (!state.publicKey) {
    alert("Generate the public key first.");
    return;
  }
  const ciphertext = byId("ccaCiphertext").value.trim();
  if (!ciphertext) {
    alert("Provide a ciphertext.");
    return;
  }
  toggleVisibility("ccaLoading", true);
  toggleVisibility("ccaResult", false);
  try {
    const data = await fetchJson(`${API_URL}/cca-attack`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext }),
    });
    byId("ccaOutput").textContent = JSON.stringify(data.result, null, 2);
    if (data.result.attack_log) {
      byId("ccaAttackLog").textContent = data.result.attack_log
        .map((entry) => JSON.stringify(entry, null, 2))
        .join("\n\n");
    } else {
      byId("ccaAttackLog").textContent = "";
    }
    toggleVisibility("ccaResult", true);
  } catch (error) {
    byId("ccaOutput").textContent = `Error: ${error.message}`;
    byId("ccaAttackLog").textContent = "";
    toggleVisibility("ccaResult", true);
  } finally {
    toggleVisibility("ccaLoading", false);
  }
}

async function runWienerAttack() {
  const n = byId("wienerN").value.trim();
  const e = byId("wienerE").value.trim();
  if (!n || !e) {
    alert("Provide both modulus and public exponent.");
    return;
  }
  toggleVisibility("wienerLoading", true);
  toggleVisibility("wienerResult", false);
  try {
    const data = await fetchJson(`${API_URL}/wiener-attack`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ n, e }),
    });
    byId("wienerAttackOutput").textContent = JSON.stringify(
      data.result,
      null,
      2
    );
    toggleVisibility("wienerResult", true);
  } catch (error) {
    byId("wienerAttackOutput").textContent = `Error: ${error.message}`;
    toggleVisibility("wienerResult", true);
  } finally {
    toggleVisibility("wienerLoading", false);
  }
}

async function generateSmallWienerKey() {
  try {
    const data = await fetchJson(`${API_URL}/generate-small-wiener-key`);
    byId("wienerSmallKeyN").value = data.n || "";
    byId("wienerSmallKeyE").value = data.e || "";
    byId("wienerSmallKeyD").value = data.d || "";
  } catch (error) {
    alert(`Unable to generate Wiener demo key: ${error.message}`);
  }
}

async function runHastadAttack() {
  toggleVisibility("hastadLoading", true);
  toggleVisibility("hastadResult", false);
  try {
    const payload = {
      public_key: {
        n: byId("hastadN").value.trim(),
        e: byId("hastadE").value.trim(),
      },
    };
    const ciphertexts = byId("hastadCiphertexts").value.trim();
    if (ciphertexts) {
      payload.ciphertexts = JSON.parse(ciphertexts);
    }
    const data = await fetchJson(`${API_URL}/attacks/hastad`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (data.success) {
      const messageText = data.message_text
        ? `\nMessage Text: ${data.message_text}`
        : "";
      byId(
        "hastadOutput"
      ).textContent = `Attack successful!\n\nDecrypted Message: ${
        data.decrypted_message
      }${messageText}\nExecution Time: ${
        data.execution_time?.toFixed?.(2) ?? "N/A"
      } s`;
    } else {
      byId("hastadOutput").textContent = `Attack failed: ${
        data.message
      }\nExecution Time: ${data.execution_time?.toFixed?.(2) ?? "N/A"} s`;
    }
    toggleVisibility("hastadResult", true);
  } catch (error) {
    byId("hastadOutput").textContent = `Error: ${error.message}`;
    toggleVisibility("hastadResult", true);
  } finally {
    toggleVisibility("hastadLoading", false);
  }
}

async function runChosenPlaintextAttack() {
  const ciphertext = byId("cpaTargetCiphertext").value.trim();
  const maxQueries = Number(byId("cpaMaxQueries").value) || 1000;
  if (!ciphertext) {
    alert("Provide a target ciphertext.");
    return;
  }
  toggleVisibility("cpaLoading", true);
  toggleVisibility("cpaResult", false);
  try {
    const data = await fetchJson(`${API_URL}/chosen-plaintext-attack`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_ciphertext: ciphertext,
        max_queries: maxQueries,
      }),
    });
    byId("cpaOutput").textContent = JSON.stringify(data.result, null, 2);
    if (data.result.attack_log) {
      byId("cpaAttackLog").textContent = data.result.attack_log
        .map((entry) => JSON.stringify(entry, null, 2))
        .join("\n\n");
    } else {
      byId("cpaAttackLog").textContent = "";
    }
    toggleVisibility("cpaResult", true);
  } catch (error) {
    byId("cpaOutput").textContent = `Error: ${error.message}`;
    byId("cpaAttackLog").textContent = "";
    toggleVisibility("cpaResult", true);
  } finally {
    toggleVisibility("cpaLoading", false);
  }
}

// expose handlers for inline attributes
Object.assign(window, {
  generateKeys,
  encryptMessage,
  getSignedMessage,
  verifySignature,
  factorizeNumber,
  runTimingAttack,
  runCCAAttack,
  runWienerAttack,
  generateSmallWienerKey,
  runHastadAttack,
  runChosenPlaintextAttack,
});
