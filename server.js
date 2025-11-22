require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// 🔐 CREDENCIAIS E SEGURANÇA (IP FIXO)
// ==========================================
const MISTIC_CI = process.env.CI || 'ci_jbbmajuwwmq28hv';
const MISTIC_CS = process.env.CS || 'cs_isxps89xg5jodulumlayuy40d';
const MISTIC_URL = 'https://api.misticpay.com'; 

const ADMIN_EMAIL = 'admin@pay.com';
const ADMIN_PASS = 'admin';

// 🛑 SEU IP REAL (PROTEÇÃO DO ADMIN)
const IP_SEGURO_ADMIN = '201.19.113.159'; 

app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());

// ==========================================
// 🛠️ FUNÇÃO DE IP BLINDADA (CORRIGIDA)
// ==========================================
const getIp = (req) => {
    // Pega o IP, seja direto ou via Proxy (Render)
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    
    // 1. Se vier como Array, pega o primeiro
    if (Array.isArray(ip)) ip = ip[0];

    // 2. CORREÇÃO CRÍTICA: Se vier lista (ex: "201.19..., 172.71..."), corta na vírgula
    if (typeof ip === 'string' && ip.includes(',')) {
        ip = ip.split(',')[0]; 
    }

    // 3. Limpa espaços e prefixos estranhos
    if (typeof ip === 'string') {
        return ip.trim().replace('::ffff:', '');
    }
    
    return '';
};

// ==========================================
// 🧪 BANCO DE DADOS (COM LISTA DE SUGESTÕES)
// ==========================================
const db = {
    // 👇 AQUI ESTÁ A LISTA QUE FAZ AS SUGESTÕES APARECEREM NO FRONTEND
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0 },
        { id: 2, email: 'cliente@teste.com', password: '123', status: 'ATIVO', name: 'Cliente Teste', role: 'user', saldoCents: 10000 },
        { id: 3, email: 'israel@email.com', password: '123', status: 'ATIVO', name: 'Israel Roza Silva', role: 'user', saldoCents: 50000 },
        { id: 4, email: 'janislene@email.com', password: '123', status: 'ATIVO', name: 'JANISLENE ROSA DE ASSIS', role: 'user', saldoCents: 25000 },
        { id: 5, email: 'inacio@email.com', password: '123', status: 'PENDENTE', name: 'INACIO LENNON MORAES', role: 'user', saldoCents: 0 },
    ],
    // Histórico inicial para a tabela não ficar vazia
    transactions: [
        { id: "1", amount: 150.00, description: "Depósito Inicial", transactionState: "PENDENTE", transactionType: "DEPOSITO", created_at: new Date() },
        { id: "2", amount: 1250.00, description: "Saque Elite Pay", transactionState: "COMPLETO", transactionType: "RETIRADA", created_at: new Date() }
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
// 🚀 ROTAS DE LOGIN (COM A TRAVA DE IP)
// ==========================================
const authRoutes = express.Router();

authRoutes.post('/login', (req, res) => {
    const { email, password, senha } = req.body;
    const pass = password || senha;
    const ipAtual = getIp(req); // Pega o IP limpo

    console.log(`📡 LOGIN | Email: ${email} | IP Detectado: [${ipAtual}]`);

    // --- BLOQUEIO DE SEGURANÇA ADMIN ---
    if (email === ADMIN_EMAIL) {
        if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
        
        // Verifica se o IP é EXATAMENTE o permitido
        if (ipAtual !== IP_SEGURO_ADMIN) {
            console.log(`🚫 ADMIN BLOQUEADO: IP ${ipAtual} não é ${IP_SEGURO_ADMIN}`);
            return res.status(403).json({ 
                error: 'ACESSO NEGADO: IP não autorizado.',
                ip_detectado: ipAtual 
            });
        }

        console.log(`✅ ADMIN LIBERADO: IP ${ipAtual}`);
        const adminUser = db.users.find(u => u.email === ADMIN_EMAIL);
        return res.status(200).json({ token: 'ADMIN_TOKEN_SECURE', user: adminUser });
    }

    // --- LOGIN DE CLIENTES (SEM BLOQUEIO DE IP) ---
    const user = db.users.find(u => u.email === email && (u.password === pass));
    
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

authRoutes.get('/me', checkAuth, (req, res) => res.json(db.users[1]));
app.use('/api/auth', authRoutes);

// ==========================================
// 💸 ROTAS DE TRANSAÇÃO (SEU CÓDIGO ORIGINAL)
// ==========================================
const txRoutes = express.Router();

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
            })
        });

        const data = await misticResponse.json();
        if (!misticResponse.ok) return res.status(400).json({ error: data.message || 'Erro na MisticPay' });

        // Adiciona à lista em memória
        db.transactions.unshift({ ...data, created_at: new Date(), transactionType: 'DEPOSITO', transactionState: 'PENDENTE' });
        res.json(data);

    } catch (error) {
        console.error('❌ Erro:', error);
        res.status(500).json({ error: 'Erro ao conectar API' });
    }
});

txRoutes.post('/withdraw', checkAuth, async (req, res) => {
    // Simulação de saque mantendo estrutura
    const { amount } = req.body;
    const novaTx = { 
        id: `out_${Date.now()}`, 
        amount: Number(amount), 
        description: "Saque Solicitado", 
        transactionType: "RETIRADA", 
        transactionState: "COMPLETO", 
        created_at: new Date() 
    };
    db.transactions.unshift(novaTx);
    res.json(novaTx);
});

txRoutes.get('/', checkAuth, (req, res) => res.json({ success: true, transactions: db.transactions }));

app.use('/api/transactions', txRoutes);

// ==========================================
// 🔑 ROTAS AUXILIARES E ADMIN (LISTA DE USUÁRIOS)
// ==========================================
const credRoutes = express.Router();

credRoutes.get('/', checkAuth, (req, res) => {
    const creds = db.credentials['2'] || { hasCredentials: false };
    res.json(creds);
});

credRoutes.post('/generate', checkAuth, (req, res) => {
    const newCreds = {
        hasCredentials: true,
        clientId: 'live_' + Math.random().toString(36).substr(2, 16),
        clientSecret: 'sk_' + Math.random().toString(36).substr(2, 32),
        createdAt: new Date()
    };
    db.credentials['2'] = newCreds;
    res.json(newCreds);
});

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

// --- ROTAS DO ADMIN (ESSENCIAL PARA SUGESTÕES) ---
// É esta rota que o frontend chama para preencher a lista de clientes!
app.get('/api/users', (req, res) => res.json(db.users));

app.get('/api/logs', (req, res) => res.json([]));
app.put('/api/users/:id/status', (req, res) => {
    const user = db.users.find(u => u.id == req.params.id);
    if (user) { user.status = req.body.status; res.json({ success: true }); }
    else res.status(404).json({ error: 'User not found' });
});

app.listen(PORT, () => {
    console.log(`✅ SERVIDOR RODANDO NA PORTA ${PORT}`);
    console.log(`🔒 SEGURANÇA ATIVA: IP ${IP_SEGURO_ADMIN}`);
});
