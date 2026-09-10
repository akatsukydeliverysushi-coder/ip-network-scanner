const weakPatterns = [
  /^123456$/i, /^12345678$/i, /^123456789$/i, /^password$/i, /^senha$/i,
  /^admin$/i, /^admin123$/i, /^1234$/i, /^qwerty$/i, /^abc123$/i,
  /^letmein$/i, /^welcome$/i, /^changeme$/i
];

function auditCredential(username, password) {
  const findings = [];
  const user = String(username || '').trim();
  const pass = String(password || '');

  if (!user) findings.push('Usuário não informado');
  if (!pass) findings.push('Senha não informada');
  if (pass.length > 0 && pass.length < 8) findings.push('Senha com menos de 8 caracteres');
  if (weakPatterns.some(re => re.test(pass))) findings.push('Senha está em uma lista de senhas muito comuns');
  if (/^(.)\1+$/.test(pass) && pass.length > 2) findings.push('Senha usa o mesmo caractere repetidamente');
  if (/^(\d+|[a-zA-Z]+)$/.test(pass) && pass.length < 12) findings.push('Senha usa apenas um tipo simples de caractere');
  if (user && pass && user.toLowerCase() === pass.toLowerCase()) findings.push('Usuário e senha são iguais');

  const score = Math.max(0, Math.min(100,
    (pass.length >= 8 ? 25 : pass.length * 3) +
    (/[a-z]/.test(pass) ? 15 : 0) +
    (/[A-Z]/.test(pass) ? 15 : 0) +
    (/\d/.test(pass) ? 15 : 0) +
    (/[^A-Za-z0-9]/.test(pass) ? 20 : 0) +
    (pass.length >= 14 ? 10 : 0) -
    (findings.length * 10)
  ));

  return {
    username: user || '-',
    score,
    level: score >= 80 ? 'FORTE' : score >= 55 ? 'MÉDIA' : 'FRACA',
    findings
  };
}

window.auditCredential = auditCredential;
