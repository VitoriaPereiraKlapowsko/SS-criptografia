Outras formas de segurança na parte de usuários:

Hash de Senhas: Utilização do bcrypt para proteger senhas com hashing seguro.
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

Autenticação com JWT: Uso de tokens JWT com expiração para autenticação.
  const token = jwt.sign({ id: user.id }, secret, { expiresIn: '1h' });
  res.json({ token });

Validação de Entrada: Antes de processar os dados, são feitas validações para garantir que as entradas do usuário sejam seguras, evitando injeções de código.
if (!email || !password || !name) {
    ctx.status = 400;
    ctx.body = { error: 'Todos os campos são obrigatórios' };
    return;
}

Proteção contra Brute Force: O sistema limita as tentativas de login por IP para impedir ataques de força bruta.
  const limiter = new RateLimiter({
      points: 5, // 5 tentativas
      duration: 60 * 15 // por 15 minutos
  });
await limiter.consume(ip);

Senhas Fortes: Exigir que as senhas tenham pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres esp
  if (password.length < 8 || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
      ctx.status = 400;
      ctx.body = { error: 'Senha fraca. Siga as diretrizes.' };
      return;
  }

Notificações de Atividades Suspeitas: Alerta ao usuário sobre tentativas de login estranhos.
  if (suspiciousLoginAttempt) {
      sendEmail(user.email, 'Atividade suspeita detectada em sua conta');
  }

Entre outros...
