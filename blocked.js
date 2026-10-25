(function () {
  'use strict';
  const reasons = {
    adult: 'This domain is on the adult-content blocklist.',
    phishing: 'This domain is flagged as phishing or malware.',
    keyword: 'The address matched your adult-content keyword settings.'
  };
  const params = new URLSearchParams(location.search);
  const hostname = params.get('host') || 'Unknown site';
  document.getElementById('reason').textContent = reasons[params.get('reason')] || 'Blockem blocked this site.';
  document.getElementById('host').textContent = hostname;
  document.getElementById('hostLine').classList.remove('hidden');
  document.getElementById('backButton').addEventListener('click', () => {
    if (history.length > 1) history.back();
    else location.replace('about:blank');
  });
})();
