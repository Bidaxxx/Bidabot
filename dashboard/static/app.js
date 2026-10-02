document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('cmd-search');
  const commandCards = document.querySelectorAll('.command-card');
  const tabButtons = document.querySelectorAll('.cat-btn');
  let currentCategory = 'all';

  // 1. Filtrage instantané des commandes
  function filterCommands() {
    const query = searchInput ? searchInput.value.toLowerCase().trim() : '';

    commandCards.forEach(card => {
      const name = card.getAttribute('data-name').toLowerCase();
      const desc = card.getAttribute('data-desc').toLowerCase();
      const category = card.getAttribute('data-category');

      const matchesSearch = name.includes(query) || desc.includes(query);
      const matchesCategory = currentCategory === 'all' || category === currentCategory;

      if (matchesSearch && matchesCategory) {
        card.style.display = 'grid';
      } else {
        card.style.display = 'none';
      }
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', filterCommands);
  }

  // 2. Boutons de catégories
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentCategory = btn.getAttribute('data-cat');
      filterCommands();
    });
  });

  // 3. Copie rapide de commande (Monochrome, zéro emoji)
  window.copyCommand = function(text, element) {
    navigator.clipboard.writeText(text).then(() => {
      const originalHTML = element.innerHTML;
      element.innerHTML = 'COPIÉ';
      element.style.color = '#ffffff';
      setTimeout(() => {
        element.innerHTML = originalHTML;
        element.style.color = '';
      }, 1200);
    });
  };

  // 4. Simulateur d'analyse en direct (Monochrome, zéro emoji)
  const scanBtn = document.getElementById('run-scan-btn');
  const scanInput = document.getElementById('scan-text-input');
  const scanResults = document.getElementById('scan-results-box');

  if (scanBtn && scanInput && scanResults) {
    scanBtn.addEventListener('click', async () => {
      const text = scanInput.value.trim();
      if (!text) return;

      scanBtn.disabled = true;
      scanBtn.innerText = 'Analyse en cours...';

      try {
        const resp = await fetch('/api/simulate-scam', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: text })
        });
        const data = await resp.json();

        scanResults.style.display = 'block';
        if (data.is_threat) {
          scanResults.innerHTML = `
            <div style="color: #ffffff; font-weight: 600; margin-bottom: 4px; font-family: var(--font-mono);">
              [MENACE DÉTECTÉE] ${data.category} (Score : ${(data.score * 100).toFixed(0)}%)
            </div>
            <div style="color: #888888; font-size: 12px;">
              Action automatique : ${data.action}
            </div>
          `;
        } else {
          scanResults.innerHTML = `
            <div style="color: #ffffff; font-weight: 600; margin-bottom: 4px; font-family: var(--font-mono);">
              [CONFORME] Message sain (aucune menace détectée)
            </div>
            <div style="color: #888888; font-size: 12px;">
              Le message ne contient aucun pattern frauduleux connu.
            </div>
          `;
        }
      } catch (e) {
        scanResults.style.display = 'block';
        scanResults.innerHTML = `<span style="color: #888888;">Erreur lors de l'analyse.</span>`;
      } finally {
        scanBtn.disabled = false;
        scanBtn.innerText = 'Analyser l\'échantillon';
      }
    });
  }
});
