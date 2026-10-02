/* ==========================================================================
   BIDABOT — CYBER SOC CLIENT ENGINE (CHARTS, AUDIO, LIVE ALERTS & TERMINAL)
   ========================================================================== */

// ── 1. Synthétiseur Audio Web Audio API (Zéro fichier externe requis) ──
let audioCtx = null;
let soundEnabled = localStorage.getItem('bidabot_sound') !== 'false';

function getAudioContext() {
  if (!audioCtx) {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (AudioContextClass) audioCtx = new AudioContextClass();
  }
  if (audioCtx && audioCtx.state === 'suspended') {
    audioCtx.resume();
  }
  return audioCtx;
}

window.toggleAudioAlerts = function() {
  soundEnabled = !soundEnabled;
  localStorage.setItem('bidabot_sound', soundEnabled);
  const btn = document.getElementById('audio-toggle-btn');
  if (btn) {
    btn.innerHTML = soundEnabled ? '🔊 Son : ON' : '🔇 Son : OFF';
    btn.classList.toggle('btn-secondary', soundEnabled);
    btn.classList.toggle('btn-warning', !soundEnabled);
  }
  if (soundEnabled) {
    playCyberAlert('info');
    showSocToast('Alertes Audio Activées', 'Le carillon cyber-sécurité résonnera lors des attaques interceptées.', 'info');
  }
};

function playCyberAlert(severity = 'warning') {
  if (!soundEnabled) return;
  try {
    const ctx = getAudioContext();
    if (!ctx) return;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    const now = ctx.currentTime;
    if (severity === 'critical') {
      // Bip d'urgence à deux tons
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.exponentialRampToValueAtTime(440, now + 0.12);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
      osc.start(now);
      osc.stop(now + 0.25);
    } else {
      // Carillon doux de sécurité
      osc.type = 'sine';
      osc.frequency.setValueAtTime(587.33, now); // D5
      osc.frequency.setValueAtTime(880, now + 0.08); // A5
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
      osc.start(now);
      osc.stop(now + 0.3);
    }
  } catch (e) {
    console.debug('Web Audio non disponible', e);
  }
}

// ── 2. Système de Notifications Flottantes (Toasts SOC) ──
window.showSocToast = function(title, desc, level = 'info') {
  const container = document.getElementById('soc-toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `soc-toast ${level}`;

  const icons = {
    critical: '🚨',
    warning: '⚠️',
    success: '🛡️',
    info: '🛰️'
  };

  toast.innerHTML = `
    <div style="font-size: 18px; line-height: 1;">${icons[level] || '🛡️'}</div>
    <div style="flex: 1;">
      <div style="font-weight: 700; font-size: 12.5px; color: #fff; margin-bottom: 2px;">${title}</div>
      <div style="font-size: 11.5px; color: #cbd5e1; line-height: 1.4;">${desc}</div>
    </div>
    <button onclick="this.parentElement.remove()" style="background:none; border:none; color:#64748b; font-size:16px; cursor:pointer; padding:0 4px;">&times;</button>
  `;

  container.appendChild(toast);
  playCyberAlert(level);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(15px)';
    setTimeout(() => toast.remove(), 250);
  }, 5000);
};

// ── 3. Initialisation des Graphiques Interactifs (Chart.js) ──
let timelineChartInstance = null;
let distributionChartInstance = null;

window.initDashboardCharts = async function(guildId) {
  const timelineCanvas = document.getElementById('timelineChart');
  const distributionCanvas = document.getElementById('distributionChart');

  if (!timelineCanvas || !distributionCanvas) return;

  try {
    // A. Graphique Heure par Heure (Timeline 24h)
    const resTimeline = await fetch(`/api/guild/${guildId}/stats/timeline`);
    if (resTimeline.ok) {
      const dataTimeline = await resTimeline.json();
      
      const ctx = timelineCanvas.getContext('2d');
      const gradientCyan = ctx.createLinearGradient(0, 0, 0, 220);
      gradientCyan.addColorStop(0, 'rgba(6, 182, 212, 0.35)');
      gradientCyan.addColorStop(1, 'rgba(6, 182, 212, 0.00)');

      if (timelineChartInstance) timelineChartInstance.destroy();

      timelineChartInstance = new Chart(timelineCanvas, {
        type: 'line',
        data: {
          labels: dataTimeline.labels,
          datasets: [
            {
              label: 'Menaces Bloquées',
              data: dataTimeline.total,
              borderColor: '#06b6d4',
              backgroundColor: gradientCyan,
              borderWidth: 2,
              fill: true,
              tension: 0.35,
              pointBackgroundColor: '#06b6d4',
              pointRadius: 2,
              pointHoverRadius: 5
            },
            {
              label: 'Critiques (Nuke/Malware)',
              data: dataTimeline.critical,
              borderColor: '#f43f5e',
              backgroundColor: 'transparent',
              borderWidth: 1.5,
              borderDash: [4, 4],
              pointRadius: 0
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: true,
              position: 'top',
              labels: {
                boxWidth: 10,
                color: '#94a3b8',
                font: { family: 'JetBrains Mono', size: 10 }
              }
            },
            tooltip: {
              backgroundColor: 'rgba(13, 16, 23, 0.95)',
              titleFont: { family: 'JetBrains Mono', size: 11 },
              bodyFont: { family: 'Inter', size: 11 },
              borderColor: 'rgba(255, 255, 255, 0.1)',
              borderWidth: 1
            }
          },
          scales: {
            x: {
              grid: { color: 'rgba(255, 255, 255, 0.03)' },
              ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 9.5 } }
            },
            y: {
              beginAtZero: true,
              grid: { color: 'rgba(255, 255, 255, 0.04)' },
              ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 9.5 }, stepSize: 1 }
            }
          }
        }
      });
    }

    // B. Graphique Répartition des Menaces (Doughnut)
    const resDist = await fetch(`/api/guild/${guildId}/stats/distribution`);
    if (resDist.ok) {
      const dataDist = await resDist.json();

      if (distributionChartInstance) distributionChartInstance.destroy();

      distributionChartInstance = new Chart(distributionCanvas, {
        type: 'doughnut',
        data: {
          labels: dataDist.labels,
          datasets: [{
            data: dataDist.values,
            backgroundColor: dataDist.colors,
            borderWidth: 1,
            borderColor: '#0d1017'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: {
              display: true,
              position: 'right',
              labels: {
                boxWidth: 8,
                color: '#94a3b8',
                font: { family: 'Inter', size: 10 }
              }
            },
            tooltip: {
              backgroundColor: 'rgba(13, 16, 23, 0.95)',
              bodyFont: { family: 'JetBrains Mono', size: 11 }
            }
          }
        }
      });
    }
  } catch (err) {
    console.error('Erreur initialisation graphiques:', err);
  }
};

// ── 4. Simulateur Red Team Pentest en direct ──
window.runRedTeamSimulation = async function(guildId, threatType, btnElement) {
  if (btnElement) {
    btnElement.disabled = true;
    btnElement.style.opacity = '0.6';
  }

  try {
    const formData = new FormData();
    formData.append('threat_type', threatType);

    const res = await fetch(`/api/guild/${guildId}/simulate-attack`, {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    if (res.ok && data.status === 'success') {
      showSocToast(data.title, `${data.message} (Latence: ${data.defense_latency_ms}ms)`, data.level);

      // Met à jour les graphiques
      if (typeof initDashboardCharts === 'function') {
        initDashboardCharts(guildId);
      }

      // Rafraîchit le Live SOC Matrix s'il est présent
      if (typeof refreshSocMatrix === 'function') {
        refreshSocMatrix(guildId);
      }
    } else {
      showSocToast('Erreur Simulation', data.detail || 'Échec du test pentest', 'critical');
    }
  } catch (e) {
    showSocToast('Erreur Réseau', 'Impossible de contacter le cœur de défense.', 'critical');
  } finally {
    if (btnElement) {
      btnElement.disabled = false;
      btnElement.style.opacity = '1';
    }
  }
};

// ── 5. Terminal CLI Interactif (Console Shell) ──
let commandHistory = [];
let historyIndex = -1;

window.handleCliKeyDown = function(event, guildId) {
  const input = document.getElementById('cli-input');
  if (!input) return;

  if (event.key === 'Enter') {
    event.preventDefault();
    submitCliCommand(guildId);
  } else if (event.key === 'ArrowUp') {
    if (commandHistory.length > 0 && historyIndex < commandHistory.length - 1) {
      historyIndex++;
      input.value = commandHistory[commandHistory.length - 1 - historyIndex];
    }
  } else if (event.key === 'ArrowDown') {
    if (historyIndex > 0) {
      historyIndex--;
      input.value = commandHistory[commandHistory.length - 1 - historyIndex];
    } else if (historyIndex === 0) {
      historyIndex = -1;
      input.value = '';
    }
  }
};

window.executeQuickCommand = function(cmd) {
  const input = document.getElementById('cli-input');
  if (input) {
    input.value = cmd;
    input.focus();
  }
};

window.clearTerminalScreen = function() {
  const screen = document.getElementById('terminal-screen');
  if (screen) {
    screen.innerHTML = '<div style="color: #64748b;">Terminal effacé. Tapez "help" pour la liste des commandes.</div>';
  }
};

window.submitCliCommand = async function(guildId) {
  const input = document.getElementById('cli-input');
  const screen = document.getElementById('terminal-screen');
  if (!input || !screen) return;

  const command = input.value.trim();
  if (!command) return;

  commandHistory.push(command);
  historyIndex = -1;
  input.value = '';

  // Ajout de la commande tapée dans l'écran
  const userRow = document.createElement('div');
  userRow.style.marginTop = '8px';
  userRow.innerHTML = `<span style="color: #06b6d4; font-weight: 600;">bidabot@core:~$</span> <span style="color: #fff;">${command}</span>`;
  screen.appendChild(userRow);

  const loadingRow = document.createElement('div');
  loadingRow.style.color = '#64748b';
  loadingRow.innerText = '⚙️ Exécution en cours...';
  screen.appendChild(loadingRow);
  screen.scrollTop = screen.scrollHeight;

  try {
    const formData = new FormData();
    formData.append('command', command);

    const res = await fetch(`/api/guild/${guildId}/cli`, {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    loadingRow.remove();

    const outputRow = document.createElement('div');
    outputRow.style.lineHeight = '1.5';
    outputRow.style.marginTop = '4px';

    if (data.status === 'ok') {
      outputRow.innerHTML = `<pre style="color: #4ade80; margin: 0; white-space: pre-wrap;">${data.output || data.message || 'Succès.'}</pre>`;
    } else {
      outputRow.innerHTML = `<pre style="color: #fb7185; margin: 0; white-space: pre-wrap;">[ERREUR] ${data.message || data.output || 'Instruction non reconnue.'}</pre>`;
    }
    screen.appendChild(outputRow);
  } catch (e) {
    loadingRow.remove();
    const errRow = document.createElement('div');
    errRow.style.color = '#fb7185';
    errRow.innerText = 'Échec de connexion au bot Discord.';
    screen.appendChild(errRow);
  }
  screen.scrollTop = screen.scrollHeight;
};

// ── 6. Modération Directe en 1 Clic ──
window.quickBanUser = async function(guildId, userId) {
  if (!confirm(`Confirmer le BAN IMMÉDIAT de l'utilisateur #${userId} ?`)) return;
  try {
    const res = await fetch(`/api/guild/${guildId}/ban/${userId}`, { method: 'POST' });
    const data = await res.json();
    if (res.ok && data.status === 'ok') {
      showSocToast('Bannissement Exécuté', `Utilisateur #${userId} banni du serveur.`, 'critical');
    } else {
      showSocToast('Erreur', data.detail || 'Action refusée', 'warning');
    }
  } catch (e) {
    showSocToast('Erreur Réseau', 'Impossible de contacter le serveur.', 'warning');
  }
};

window.quickKickUser = async function(guildId, userId) {
  if (!confirm(`Confirmer l'EXPULSION de l'utilisateur #${userId} ?`)) return;
  try {
    const res = await fetch(`/api/guild/${guildId}/kick/${userId}`, { method: 'POST' });
    const data = await res.json();
    if (res.ok && data.status === 'ok') {
      showSocToast('Expulsion Exécutée', `Utilisateur #${userId} expulsé du serveur.`, 'warning');
    } else {
      showSocToast('Erreur', data.detail || 'Action refusée', 'warning');
    }
  } catch (e) {
    showSocToast('Erreur Réseau', 'Impossible de contacter le serveur.', 'warning');
  }
};

window.quickTimeoutUser = async function(guildId, userId, minutes = 60) {
  try {
    const formData = new FormData();
    formData.append('duration_minutes', minutes);
    const res = await fetch(`/api/guild/${guildId}/timeout/${userId}`, { method: 'POST', body: formData });
    const data = await res.json();
    if (res.ok && data.status === 'ok') {
      showSocToast('Mute / Timeout Appliqué', `Utilisateur #${userId} réduit au silence pour ${minutes} min.`, 'warning');
    } else {
      showSocToast('Erreur', data.detail || 'Action refusée', 'warning');
    }
  } catch (e) {
    showSocToast('Erreur Réseau', 'Impossible de contacter le serveur.', 'warning');
  }
};

window.unquarantineUser = async function(guildId, userId) {
  try {
    const res = await fetch(`/api/guild/${guildId}/unquarantine/${userId}`, { method: 'POST' });
    const data = await res.json();
    if (res.ok && data.status === 'ok') {
      showSocToast('Quarantaine Levée', `L'accès a été restitué pour #${userId}.`, 'success');
    } else {
      showSocToast('Erreur', data.detail || 'Action refusée', 'warning');
    }
  } catch (e) {
    showSocToast('Erreur Réseau', 'Impossible de contacter le serveur.', 'warning');
  }
};

// ── 7. Initialisation Globale & Scanner Vitrine ──
document.addEventListener('DOMContentLoaded', () => {
  // Sync état bouton audio
  const audioBtn = document.getElementById('audio-toggle-btn');
  if (audioBtn) {
    audioBtn.innerHTML = soundEnabled ? '🔊 Son : ON' : '🔇 Son : OFF';
    audioBtn.classList.toggle('btn-secondary', soundEnabled);
    audioBtn.classList.toggle('btn-warning', !soundEnabled);
  }

  // Scanner Vitrine (Landing Page)
  const scanBtn = document.getElementById('run-scan-btn');
  const scanInput = document.getElementById('scan-text-input');
  const scanResults = document.getElementById('scan-results-box');

  if (scanBtn && scanInput && scanResults) {
    scanBtn.addEventListener('click', async () => {
      const text = scanInput.value.trim();
      if (!text) return;

      scanBtn.disabled = true;
      scanBtn.innerText = '⚡ Analyse Heuristique & ML...';

      try {
        const resp = await fetch('/api/simulate-scam', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: text })
        });
        const data = await resp.json();

        scanResults.style.display = 'block';
        if (data.is_threat) {
          playCyberAlert('critical');
          scanResults.innerHTML = `
            <div style="color: #fb7185; font-weight: 700; margin-bottom: 4px; font-family: var(--font-mono);">
              🚨 [MENACE DÉTECTÉE] ${data.category} (Score Risque : ${(data.score * 100).toFixed(0)}%)
            </div>
            <div style="color: #cbd5e1; font-size: 12.5px;">
              🛡️ Action automatique Sentinel : <strong>${data.action}</strong>
            </div>
          `;
        } else {
          playCyberAlert('info');
          scanResults.innerHTML = `
            <div style="color: #34d399; font-weight: 700; margin-bottom: 4px; font-family: var(--font-mono);">
              ✅ [CONFORME] Message Légitime (Risque : ${(data.score * 100).toFixed(0)}%)
            </div>
            <div style="color: #94a3b8; font-size: 12.5px;">
              Aucun pattern de phishing, domaine suspect ou obfusquage détecté.
            </div>
          `;
        }
      } catch (e) {
        scanResults.style.display = 'block';
        scanResults.innerHTML = `<span style="color: #fb7185;">Erreur d'analyse.</span>`;
      } finally {
        scanBtn.disabled = false;
        scanBtn.innerText = 'Analyser l\'échantillon';
      }
    });
  }
});
