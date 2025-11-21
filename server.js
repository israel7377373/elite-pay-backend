require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// --- SUAS CREDENCIAIS REAIS (FALLBACK) ---
const MISTIC_CI = process.env.CI || 'ci_jbbmajuwwmq28hv';
const MISTIC_CS = process.env.CS || 'cs_isxps89xg5jodulumlayuy40d';
const MISTIC_URL = 'https://api.misticpay.com'; 

app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());

// --- BANCO DE DADOS MOCK (Tudo em memória) ---
const db = {
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0 },
        { id: 2, email: 'cliente@pay.com', password: '123', status: 'ATIVO', name: 'Cliente Teste', role: 'user', saldoCents: 5000 }
    ],
    transactions: [],
    // 👇 AQUI ESTAVA FALTANDO: Onde guardamos as credenciais
    credentials: {
        // Exemplo: '2': { hasCredentials: true, clientId: '...', clientSecret: '...' }
    },
    allowedIps: []
};

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
const checkAuth = (req, res, next) => {
    if (req.headers['authorization']) return next();
    return res.status(401).json({ error: 'Token inválido' });
};

// --- ROTAS DE LOGIN ---
const authRoutes = express.Router();

authRoutes.post('/login', (req, res) => {
    const { email, senha } = req.body;
    const user = db.users.find(u => u.email === email && (u.password === senha || u.password === req.body.password));
    
    if (!user) return res.status(401).json({ error: 'Login incorreto' });
    if (user.status !== 'ATIVO') return res.status(403).json({ error: 'Conta pendente' });

    res.status(200).json({ token: 'TOKEN_FIXO_' + user.id, user });
});

authRoutes.post('/register', (req, res) => {
    const { email, name, password, cpf } = req.body;
    const newUser = { id: Date.now(), email, name, password, cpf, status: 'PENDENTE', role: 'user', saldoCents: 0 };
    db.users.push(newUser);
    res.status(201).json({ message: 'Cadastro realizado', user: newUser });
});

authRoutes.get('/me', checkAuth, (req, res) => res.json(db.users[1]));
app.use('/api/auth', authRoutes);

// --- ROTAS DE TRANSAÇÃO ---
const txRoutes = express.Router();

// 1. CRIAR DEPÓSITO (Conecta na MisticPay)
txRoutes.post('/create', checkAuth, async (req, res) => {
    const { amount, description } = req.body;
    console.log(`🔄 [Backend] Gerando PIX de R$ ${amount}...`);

    try {
        const misticResponse = await fetch(`${MISTIC_URL}/api/transactions/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'ci': MISTIC_CI, 'cs': MISTIC_CS },
            body: JSON.stringify({
                amount: Number(amount),
                description: description || 'Depósito Elite Pay',
                payerName: "Cliente Teste", 
                payerDocument: "000.000.000-00",
                transactionId: `tx_${Date.now()}`
                // splitTax removido para não dar erro
            })
        });

        const data = await misticResponse.json();
        if (!misticResponse.ok) return res.status(400).json({ error: data.message || 'Erro na MisticPay' });

        db.transactions.push({ ...data, created_at: new Date() });
        res.json(data);

    } catch (error) {
        console.error('❌ Erro:', error);
        res.status(500).json({ error: 'Erro ao conectar API' });
    }
});

txRoutes.get('/', checkAuth, (req, res) => res.json({ success: true, transactions: db.transactions }));
txRoutes.post('/withdraw', checkAuth, (req, res) => res.json({ success: true, message: 'Saque solicitado' }));

app.use('/api/transactions', txRoutes);

// --- ROTAS DE CREDENCIAIS (AS QUE FALTAVAM!) ---
const credRoutes = express.Router();

// Buscar Credenciais
credRoutes.get('/', checkAuth, (req, res) => {
    // Retorna as credenciais do usuário 2 (Cliente Teste) ou vazio
    const creds = db.credentials['2'] || { hasCredentials: false };
    res.json(creds);
});

// Gerar Novas Credenciais
credRoutes.post('/generate', checkAuth, (req, res) => {
    const newCreds = {
        hasCredentials: true,
        clientId: 'live_' + Math.random().toString(36).substr(2, 16),
        clientSecret: 'sk_' + Math.random().toString(36).substr(2, 32),
        createdAt: new Date()
    };
    // Salva para o usuário 2
    db.credentials['2'] = newCreds;
    
    console.log('🔑 Credenciais geradas:', newCreds.clientId);
    res.json(newCreds);
});

// Deletar Credenciais
credRoutes.delete('/', checkAuth, (req, res) => {
    delete db.credentials['2'];
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

// --- ROTAS DO ADMIN ---
app.get('/api/users', (req, res) => res.json(db.users));
app.get('/api/logs', (req, res) => res.json([]));
app.put('/api/users/:id/status', (req, res) => {
    const user = db.users.find(u => u.id == req.params.id);
    if (user) { user.status = req.body.status; res.json({ success: true }); }
    else res.status(404).json({ error: 'User not found' });
});

app.listen(PORT, () => {
    console.log(`✅ SERVIDOR COMPLETO RODANDO NA PORTA ${PORT}`);
});
