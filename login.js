// login.js
// Lógica de login e sessão

document.addEventListener('DOMContentLoaded', function () {

  // Para demo, sempre permite logar direto

  const form = document.getElementById('loginForm');
  const errorDiv = document.getElementById('loginError');

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    const empresa = form.empresa.value.trim();
    const usuario = form.usuario.value.trim();
    const senha = form.senha.value;

    if (usuario === 'admin' && senha === 'lancar') {
      // Salva sessão
      localStorage.setItem('loggedUser', JSON.stringify({ empresa, usuario }));
      window.location.href = `./empreendimentos.html`;
    } else {
      errorDiv.textContent = 'Usuário ou senha inválidos.';
      errorDiv.style.display = 'block';
    }
  });
});
