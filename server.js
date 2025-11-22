require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// 🔐 CONFIGURAÇÕES
// ==========================================
const MISTIC_CI = process.env.CI || 'ci_jbbmajuwwmq28hv';
const MISTIC_CS = process.env.CS || 'cs_isxps89xg5jodulumlayuy40d';
const MISTIC_URL = 'https://api.misticpay.com'; 

const ADMIN_EMAIL = 'admin@pay.com';
const ADMIN_PASS = 'admin';
const IP_SEGURO_ADMIN = '201.19.113.159'; 

app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());

// ==========================================
// 🛠️ FUNÇÕES AUXILIARES (IP e USER)
// ==========================================

// 1. PEGAR IP (BLINDADO)
const getIp = (req) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    if (Array.isArray(ip)) ip = ip[0];
    if (typeof ip === 'string' && ip.includes(',')) ip = ip.split(',')[0]; 
    if (typeof ip === 'string') return ip.trim().replace('::ffff:', '');
    return '';
};

// 2. PEGAR USUÁRIO PELO TOKEN (NOVA FUNÇÃO IMPORTANTE)
const getUserFromToken = (req) => {
    const token = req.headers['authorization'];
    if (!token) return null;

    // O token é algo tipo "TOKEN_1", "TOKEN_2"
    // Se for admin tem um token especial
    if (token === 'ADMIN_TOKEN_SECURE') {
        return db.users.find(u => u.role === 'admin');
    }

    const userId = token.replace('TOKEN_', '');
    return db.users.find(u => u.id == userId);
};

// 3. FORMATAR TRANSAÇÃO
const formatarTransacao = (dados, tipo, usuario, ip, descricaoExtra) => {
    return {
        id: dados.id || (db.transactions.length + 1).toString(),
        value: Number(dados.amount || dados.transactionAmount || dados.value || 0),
        fee: dados.transactionFee || 0.50,
        clientName: usuario ? usuario.name : "Cliente",
        clientDocument: "000.000.000-00",
        externalId: dados.transactionId || dados.externalId || `loc_${Date.now()}`,
        description: descricaoExtra || dados.description || (tipo === 'DEPOSITO' ? 'Depósito Elite Pay' : 'Saque Elite Pay'),
        transactionState: dados.transactionState || "PENDENTE",
        transactionMethod: "PIX",
        transactionType: tipo,
        requestIp: ip,
        userId: usuario ? usuario.id : 0, // VINCULA AO ID DO USUÁRIO
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
        { id: 2, email: 'cliente@teste.com', password: '123', status: 'ATIVO', name: 'Cliente Teste', role: 'user', saldoCents: 10000 },
        { id: 3, email: 'israel@email.com', password: '123', status: 'ATIVO', name: 'Israel Roza Silva', role: 'user', saldoCents: 50000 },
        { id: 4, email: 'janislene@email.com', password: '123', status: 'ATIVO', name: 'JANISLENE ROSA', role: 'user', saldoCents: 25000 },
    ],
    // Dados Mockados JÁ COM O USER ID CORRETO
    transactions: [
        // Transações do Cliente Teste (ID 2)
        { id: "1", value: 150.00, description: "Depósito Inicial", transactionState: "PENDENTE", transactionType: "DEPOSITO", userId: 2, clientName: "Cliente Teste", created_at: new Date() },
        
        // Transações do Israel (ID 3)
        { id: "2", value: 1250.00, description: "Saque Elite Pay", transactionState: "COMPLETO", transactionType: "RETIRADA", userId: 3, clientName: "Israel Roza Silva", created_at: new Date() },
        { id: "3", value: 1000.00, description: "Pix Recebido", transactionState: "COMPLETO", transactionType: "DEPOSITO", userId: 3, clientName: "Israel Roza Silva", created_at: new Date() },

        // Transações da Janislene (ID 4)
        { id: "4", value: 300.00, description: "Depósito Elite", transactionState: "COMPLETO", transactionType: "DEPOSITO", userId: 4, clientName: "JANISLENE ROSA", created_at: new Date() }
    ],
    credentials: { '2': { hasCredentials: true } },
    allowedIps: []
};

// Middleware Auth Simples
const checkAuth = (req, res, next) => {
    if (req.headers['authorization']) return next();
    return res.status(401).json({ error: 'Token inválido' });
};

// ==========================================
// 🚀 ROTAS DE LOGIN
// ==========================================
const authRoutes = express.Router();

authRoutes.post('/login', (req, res) => {
    const { email, password, senha } = req.body;
    const pass = password || senha;
    const ipAtual = getIp(req);

    console.log(`📡 LOGIN | Email: ${email} | IP: [${ipAtual}]`);

    // ADMIN
    if (email === ADMIN_EMAIL) {
        if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
        if (ipAtual !== IP_SEGURO_ADMIN) return res.status(403).json({ error: 'IP não autorizado', ip: ipAtual });
        
        const adminUser = db.users.find(u => u.role === 'admin');
        return res.status(200).json({ token: 'ADMIN_TOKEN_SECURE', user: adminUser });
    }

    // CLIENTES
    const user = db.users.find(u => u.email === email && u.password === pass);
    if (!user) return res.status(401).json({ error: 'Login incorreto' });
    if (user.status !== 'ATIVO') return res.status(403).json({ error: 'Conta pendente' });

    res.status(200).json({ token: 'TOKEN_' + user.id, user });
});

authRoutes.post('/register', (req, res) => {
    const { email, name, password, cpf } = req.body;
    const newUser = { id: Date.now(), email, name, password, cpf, status: 'PENDENTE', role: 'user', saldoCents: 0 };
    db.users.push(newUser);
    res.status(201).json({ message: 'Cadastro realizado', user: newUser });
});
app.use('/api/auth', authRoutes);

// ==========================================
// 💸 ROTAS DE TRANSAÇÃO (CORRIGIDAS PARA FILTRAR)
// ==========================================
const txRoutes = express.Router();

// 1. CRIAR DEPÓSITO (Vincula ao Usuário Logado)
txRoutes.post('/create', checkAuth, async (req, res) => {
    const { amount, description } = req.body;
    const user = getUserFromToken(req); // <--- PEGA O USUÁRIO REAL
    const ip = getIp(req);

    if (!user) return res.status(401).json({ error: "Usuário não encontrado" });

    try {
        const misticRes = await fetch(`${MISTIC_URL}/api/transactions/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
            body: JSON.stringify({
                amount: Number(amount),
                description: description || 'Depósito Elite Pay',
                payerName: user.name,
                payerDocument: "000.000.000-00",
                transactionId: `in_${Date.now()}`
            })
        });

        const data = await misticRes.json();
        if (!misticRes.ok) return res.status(400).json({ error: data.message || 'Erro API' });

        const novaTx = formatarTransacao({ ...data, transactionState: 'PENDENTE' }, 'DEPOSITO', user, ip, description);
        db.transactions.unshift(novaTx);
        res.json(novaTx);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Erro de conexão' });
    }
});

// 2. CRIAR SAQUE (Vincula ao Usuário Logado)
txRoutes.post('/withdraw', checkAuth, async (req, res) => {
    const { amount, pixKey, pixKeyType, description } = req.body;
    const user = getUserFromToken(req); // <--- PEGA O USUÁRIO REAL
    const ip = getIp(req);

    if (!user) return res.status(401).json({ error: "Usuário não encontrado" });

    try {
        const misticRes = await fetch(`${MISTIC_URL}/api/transactions/withdraw`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
            body: JSON.stringify({
                amount: Number(amount), pixKey, pixKeyType,
                description: description || "Saque Elite Pay"
            })
        });

        const data = await misticRes.json();
        if (!misticRes.ok) return res.status(400).json({ error: data.message || 'Erro API' });

        const novaTx = formatarTransacao(data, 'RETIRADA', user, ip, description);
        if(!novaTx.transactionState) novaTx.transactionState = "COMPLETO";
        db.transactions.unshift(novaTx);
        res.json(novaTx);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Erro de conexão' });
    }
});

// 3. LISTAR (AQUI ESTÁ A MÁGICA DO FILTRO)
txRoutes.get('/', checkAuth, (req, res) => {
    const user = getUserFromToken(req);
    
    if (!user) return res.status(401).json({ error: "Acesso negado" });

    // SE FOR ADMIN (Role 'admin') -> VÊ TUDO
    if (user.role === 'admin') {
        return res.json({ success: true, transactions: db.transactions });
    }

    // SE FOR CLIENTE -> VÊ SÓ AS DELE (userId == user.id)
    const minhasTransacoes = db.transactions.filter(tx => tx.userId == user.id);
    
    res.json({ success: true, transactions: minhasTransacoes });
});

app.use('/api/transactions', txRoutes);

// ==========================================
// 🔑 OUTRAS ROTAS
// ==========================================
const credRoutes = express.Router();
credRoutes.get('/', checkAuth, (req, res) => res.json(db.credentials['2'] || {}));
// ... (Restante das rotas de credenciais mantidas iguais para economizar espaço) ...
app.use('/api/credentials', credRoutes);

// Rotas Admin (Para a lista de sugestões funcionar)
app.get('/api/users', (req, res) => res.json(db.users));
app.put('/api/users/:id/status', (req, res) => {
    const u = db.users.find(x => x.id == req.params.id);
    if(u) { u.status = req.body.status; res.json({success:true}); } 
    else res.status(404).json({error:'User not found'});
});

app.listen(PORT, () => {
    console.log(`✅ SERVIDOR: Porta ${PORT}`);
    console.log(`🔒 IP ADMIN: ${IP_SEGURO_ADMIN}`);
    console.log(`👥 FILTRO INDIVIDUAL: ATIVADO`);
});
