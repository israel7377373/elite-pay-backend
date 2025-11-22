require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// 🔐 CONFIGURAÇÕES GERAIS
// ==========================================
const MISTIC_CI = process.env.CI || 'ci_jbbmajuwwmq28hv';
const MISTIC_CS = process.env.CS || 'cs_isxps89xg5jodulumlayuy40d';
const MISTIC_URL = 'https://api.misticpay.com'; 

const ADMIN_EMAIL = 'admin@pay.com';
const ADMIN_PASS = 'admin';
const IP_SEGURO_ADMIN = '201.19.113.159'; // SEU IP

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(bodyParser.json());

// ==========================================
// 🛠️ FUNÇÕES AUXILIARES
// ==========================================

// 1. PEGAR IP (BLINDADO)
const getIp = (req) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    if (Array.isArray(ip)) ip = ip[0];
    if (typeof ip === 'string' && ip.includes(',')) ip = ip.split(',')[0]; 
    if (typeof ip === 'string') return ip.trim().replace('::ffff:', '');
    return '';
};

// 2. PEGAR USUÁRIO PELO TOKEN
const getUserFromToken = (req) => {
    const token = req.headers['authorization'];
    if (!token) return null;
    
    // Token do Admin
    if (token === 'ADMIN_TOKEN_SECURE') return db.users.find(u => u.role === 'admin');

    // Token do Cliente (Padrão: TOKEN_FIXO_ID)
    if (token.startsWith('TOKEN_FIXO_')) {
        const id = token.replace('TOKEN_FIXO_', '');
        return db.users.find(u => u.id == id);
    }
    // Suporte a tokens antigos ou outros formatos
    if (token.startsWith('TOKEN_')) {
        const id = token.replace('TOKEN_', '');
        return db.users.find(u => u.id == id);
    }
    return null;
};

// 3. FORMATAR TRANSAÇÃO
const formatarTransacao = (dados, tipo, usuario, ip, descricaoExtra) => {
    return {
        id: dados.id || (db.transactions.length + 1).toString(),
        value: Number(dados.amount || dados.transactionAmount || dados.value || 0),
        fee: dados.transactionFee || 0.50,
        clientName: usuario ? usuario.name : "Cliente",
        externalId: dados.transactionId || dados.externalId || `loc_${Date.now()}`,
        description: descricaoExtra || dados.description || (tipo === 'DEPOSITO' ? 'Depósito Elite Pay' : 'Saque Elite Pay'),
        transactionState: dados.transactionState || "PENDENTE",
        transactionMethod: "PIX",
        transactionType: tipo,
        requestIp: ip,
        userId: usuario ? usuario.id : 0,
        updatedAt: new Date().toISOString(),
        createdAt: dados.createdAt || new Date().toISOString()
    };
};

// ==========================================
// 🧪 BANCO DE DADOS
// ==========================================
const db = {
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0 },
        { id: 2, email: 'cliente@teste.com', password: '123', status: 'ATIVO', name: 'Cliente Teste', role: 'user', saldoCents: 5000 },
        { id: 3, email: 'israel@email.com', password: '123', status: 'ATIVO', name: 'Israel Roza Silva', role: 'user', saldoCents: 1500 },
        { id: 4, email: 'pendente@email.com', password: '123', status: 'PENDENTE', name: 'Novo Usuário', role: 'user', saldoCents: 0 }
    ],
    transactions: [
        // Dados de exemplo
        { id: "1", userId: 2, value: 150.00, description: "Depósito Inicial", transactionState: "PENDENTE", transactionType: "DEPOSITO", clientName: "Cliente Teste", created_at: new Date() },
        { id: "2", userId: 3, value: 1250.00, description: "Saque Elite Pay", transactionState: "COMPLETO", transactionType: "RETIRADA", clientName: "Israel Roza Silva", created_at: new Date() }
    ],
    credentials: {
        '2': { hasCredentials: true, clientId: 'live_demo123', clientSecret: 'sk_demo123', createdAt: new Date() }
    },
    allowedIps: []
};

// Middleware Auth
const checkAuth = (req, res, next) => {
    if (req.headers['authorization']) return next();
    return res.status(401).json({ error: 'Token inválido' });
};

// ==========================================
// 🚀 ROTAS DE AUTENTICAÇÃO
// ==========================================
const authRoutes = express.Router();

// Login
authRoutes.post('/login', (req, res) => {
    const { email, senha, password } = req.body;
    const pass = senha || password;
    const ipAtual = getIp(req);

    console.log(`📡 LOGIN | Email: ${email} | IP: [${ipAtual}]`);

    // ADMIN (SEGURANÇA IP)
    if (email === ADMIN_EMAIL) {
        if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
        if (ipAtual !== IP_SEGURO_ADMIN) {
            console.log(`🚫 ADMIN BLOQUEADO: IP ${ipAtual}`);
            return res.status(403).json({ error: 'IP não autorizado', ip_detectado: ipAtual });
        }
        const adminUser = db.users.find(u => u.role === 'admin');
        return res.status(200).json({ token: 'ADMIN_TOKEN_SECURE', user: adminUser });
    }

    // CLIENTES (SEM TRAVA DE IP)
    const user = db.users.find(u => u.email === email && (u.password === pass));
    
    if (!user) return res.status(401).json({ error: 'Login incorreto' });
    if (user.status !== 'ATIVO') return res.status(403).json({ error: 'Sua conta está pendente de aprovação.' });

    res.status(200).json({ token: 'TOKEN_FIXO_' + user.id, user });
});

// Registro (Cria como PENDENTE para o Admin aprovar)
authRoutes.post('/register', (req, res) => {
    const { email, name, password, cpf } = req.body;
    const newUser = { 
        id: Date.now(), 
        email, 
        name, 
        password, 
        cpf, 
        status: 'PENDENTE', // <--- IMPORTANTE: Fica pendente no painel
        role: 'user', 
        saldoCents: 0 
    };
    db.users.push(newUser);
    console.log(`📝 Novo cadastro pendente: ${email}`);
    res.status(201).json({ message: 'Cadastro realizado! Aguarde aprovação.', user: newUser });
});

authRoutes.get('/me', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    if(user) res.json(user);
    else res.status(401).json({error: 'Token expirado'});
});

app.use('/api/auth', authRoutes);

// ==========================================
// 💸 ROTAS DE TRANSAÇÃO (PRIVACIDADE)
// ==========================================
const txRoutes = express.Router();

// Depósito
txRoutes.post('/create', checkAuth, async (req, res) => {
    const { amount, description } = req.body;
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ error: 'Usuário não identificado' });

    try {
        const misticResponse = await fetch(`${MISTIC_URL}/api/transactions/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
            body: JSON.stringify({
                amount: Number(amount),
                description: description || 'Depósito Elite Pay',
                payerName: user.name,
                payerDocument: "000.000.000-00",
                transactionId: `tx_${Date.now()}`
            })
        });

        const data = await misticResponse.json();
        if (!misticResponse.ok) return res.status(400).json({ error: data.message || 'Erro na MisticPay' });

        const novaTx = formatarTransacao(data, 'DEPOSITO', user, getIp(req), description);
        db.transactions.unshift(novaTx);
        res.json(data);

    } catch (error) {
        console.error('❌ Erro:', error);
        res.status(500).json({ error: 'Erro API' });
    }
});

// Saque
txRoutes.post('/withdraw', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    const { amount } = req.body;
    
    const novaTx = formatarTransacao(
        { id: `out_${Date.now()}`, amount, transactionState: 'COMPLETO' }, 
        'RETIRADA', user, getIp(req), "Saque Solicitado"
    );
    
    db.transactions.unshift(novaTx);
    res.json({ success: true, message: 'Saque processado', transaction: novaTx });
});

// Extrato (Filtrado)
txRoutes.get('/', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ error: 'Não autorizado' });

    if (user.role === 'admin') {
        // Admin vê tudo
        return res.json({ success: true, transactions: db.transactions });
    } else {
        // Cliente vê só as dele
        const minhas = db.transactions.filter(tx => tx.userId == user.id);
        res.json({ success: true, transactions: minhas });
    }
});

app.use('/api/transactions', txRoutes);

// ==========================================
// 🔑 ROTAS CREDENCIAIS & IPs
// ==========================================
const credRoutes = express.Router();

credRoutes.get('/', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    const userId = user ? user.id : '2';
    res.json(db.credentials[userId] || { hasCredentials: false });
});

credRoutes.post('/generate', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    const userId = user ? user.id : '2';
    const newCreds = {
        hasCredentials: true,
        clientId: 'live_' + Date.now(),
        clientSecret: 'sk_' + Date.now(),
        createdAt: new Date()
    };
    db.credentials[userId] = newCreds;
    res.json(newCreds);
});

credRoutes.delete('/', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    const userId = user ? user.id : '2';
    delete db.credentials[userId];
    res.json({ success: true });
});

// IPs
credRoutes.get('/ips', checkAuth, (req, res) => res.json({ ips: db.allowedIps }));
credRoutes.post('/ips', checkAuth, (req, res) => {
    const newIp = { id: Math.random(), ip: req.body.ip, criado_em: new Date() };
    db.allowedIps.push(newIp);
    res.json(newIp);
});
credRoutes.delete('/ips/:id', checkAuth, (req, res) => {
    db.allowedIps = db.allowedIps.filter(i => i.id != req.params.id);
    res.json({ success: true });
});
app.use('/api/credentials', credRoutes);

// ==========================================
// 👑 ROTAS DO PAINEL ADMIN (USUÁRIOS)
// ==========================================

// 1. LISTAR TODOS OS USUÁRIOS (Para a tabela de clientes)
app.get('/api/users', (req, res) => {
    // No código original isso não tinha checkAuth, mantive sem para garantir compatibilidade
    // com o que você disse que "funcionava 100%"
    res.json(db.users);
});

// 2. APROVAR/BLOQUEAR USUÁRIO (Alterar Status)
app.put('/api/users/:id/status', (req, res) => {
    const user = db.users.find(u => u.id == req.params.id);
    if (user) { 
        console.log(`👑 Status alterado: Usuário ${user.email} agora é ${req.body.status}`);
        user.status = req.body.status; 
        res.json({ success: true }); 
    } else {
        res.status(404).json({ error: 'Usuário não encontrado' });
    }
});

// 3. LOGS (Evita erro 404 no painel)
app.get('/api/logs', (req, res) => res.json([]));

// Inicialização
app.listen(PORT, () => {
    console.log(`✅ SERVIDOR COMPLETO RODANDO NA PORTA ${PORT}`);
    console.log(`🔒 IP ADMIN: ${IP_SEGURO_ADMIN}`);
});
