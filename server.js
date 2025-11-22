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

// --- CONFIGURAÇÃO DO ADMIN ---
const ADMIN_EMAIL = 'admin@pay.com';
const ADMIN_PASS = 'admin';

// 🛑 IP DE SEGURANÇA (SEU IP REAL)
const IP_SEGURO_ADMIN = '201.19.113.159'; 

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(bodyParser.json());

// ==========================================
// 🛠️ FUNÇÃO DE DETECÇÃO DE IP (BLINDADA)
// ==========================================
const getIp = (req) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    
    // 1. Se vier Array, pega o primeiro
    if (Array.isArray(ip)) ip = ip[0];

    // 2. Se vier lista (ex: "201.19..., 172.71..."), corta na vírgula e pega o REAL
    if (typeof ip === 'string' && ip.includes(',')) {
        ip = ip.split(',')[0]; 
    }

    // 3. Limpa espaços e lixo do IPv6
    if (typeof ip === 'string') {
        return ip.trim().replace('::ffff:', '');
    }
    
    return '';
};

// Formatar Transação para o padrão do Painel
const formatarTransacao = (dados, tipo, usuario, ip, descricaoExtra) => {
    return {
        id: dados.id || (db.transactions.length + 1).toString(),
        value: Number(dados.amount || dados.transactionAmount || dados.value || 0),
        fee: dados.transactionFee || 0.50,
        clientName: usuario ? usuario.name : (dados.clientName || "Cliente Desconhecido"),
        clientDocument: "000.000.000-00",
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
// 🧪 DADOS INICIAIS (SUGESTÕES DE CLIENTES E TRANSAÇÕES)
// ==========================================

// Lista rica baseada no seu print para preencher o painel
const transacoesIniciais = [
    {
        id: "019506c8-d275-429", value: 150.00, fee: 0.50, clientName: "Cliente Teste", 
        description: "Depósito Elite Pay", externalId: "019506c8-d275...", 
        transactionState: "PENDENTE", transactionMethod: "PIX", transactionType: "DEPOSITO", 
        requestIp: "127.0.0.1", userId: 2, createdAt: new Date().toISOString()
    },
    {
        id: "35e4b3b5-f573-410", value: 500.00, fee: 0.50, clientName: "Cliente Teste", 
        description: "Depósito Elite Pay", externalId: "35e4b3b5-f573...", 
        transactionState: "PENDENTE", transactionMethod: "PIX", transactionType: "DEPOSITO", 
        requestIp: "127.0.0.1", userId: 2, createdAt: new Date(Date.now() - 100000).toISOString()
    },
    {
        id: "c73841b5-c8e3-493", value: 1250.00, fee: 1.00, clientName: "Israel Roza Silva", 
        description: "Saque Elite Pay", externalId: "c73841b5-c8e3...", 
        transactionState: "COMPLETO", transactionMethod: "PIX", transactionType: "RETIRADA", 
        requestIp: "201.19.113.159", userId: 3, createdAt: new Date(Date.now() - 3600000).toISOString()
    },
    {
        id: "2ddce17e-66a6-489", value: 300.00, fee: 0.50, clientName: "JANISLENE ROSA DE ASSIS", 
        description: "Depósito Elite Pay", externalId: "2ddce17e-66a6...", 
        transactionState: "COMPLETO", transactionMethod: "PIX", transactionType: "DEPOSITO", 
        requestIp: "189.22.10.55", userId: 4, createdAt: new Date(Date.now() - 7200000).toISOString()
    },
    {
        id: "b19b83b9-16d4-473", value: 75.90, fee: 1.00, clientName: "INACIO LENNON MORAES", 
        description: "Pix mais rápido do Brasil", externalId: "b19b83b9-16d4...", 
        transactionState: "COMPLETO", transactionMethod: "PIX", transactionType: "RETIRADA", 
        requestIp: "177.55.20.10", userId: 5, createdAt: new Date(Date.now() - 86400000).toISOString()
    },
    {
        id: "2b3ddfa3-a1a7-485", value: 1000.00, fee: 0.50, clientName: "Israel Roza Silva", 
        description: "Recebimento via PIX", externalId: "2b3ddfa3-a1a7...", 
        transactionState: "COMPLETO", transactionMethod: "PIX", transactionType: "DEPOSITO", 
        requestIp: "201.19.113.159", userId: 3, createdAt: new Date(Date.now() - 90000000).toISOString()
    }
];

const db = {
    // Adicionando usuários fictícios para popular a lista de Clientes
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0 },
        { id: 2, email: 'cliente@teste.com', password: '123', status: 'ATIVO', name: 'Cliente Teste', role: 'user', saldoCents: 10000 },
        { id: 3, email: 'israel@email.com', password: '123', status: 'ATIVO', name: 'Israel Roza Silva', role: 'user', saldoCents: 50000 },
        { id: 4, email: 'janislene@email.com', password: '123', status: 'ATIVO', name: 'JANISLENE ROSA', role: 'user', saldoCents: 25000 },
        { id: 5, email: 'inacio@email.com', password: '123', status: 'PENDENTE', name: 'INACIO LENNON', role: 'user', saldoCents: 0 },
    ],
    transactions: [...transacoesIniciais],
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
// 🚀 ROTAS DE LOGIN
// ==========================================
const authRoutes = express.Router();

authRoutes.post('/login', (req, res) => {
    const { email, password, senha } = req.body;
    const pass = password || senha;
    const ipAtual = getIp(req);

    console.log(`📡 LOGIN | Email: ${email} | IP: [${ipAtual}]`);

    // --- ADMIN (COM BLOQUEIO IP) ---
    if (email === ADMIN_EMAIL) {
        if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
        
        if (ipAtual !== IP_SEGURO_ADMIN) {
            console.log(`🚫 ADMIN BLOQUEADO: IP ${ipAtual} difere de ${IP_SEGURO_ADMIN}`);
            return res.status(403).json({ error: 'ACESSO NEGADO: IP não autorizado.', seu_ip: ipAtual });
        }

        console.log(`✅ ADMIN LIBERADO: IP ${ipAtual}`);
        const adminUser = db.users.find(u => u.email === ADMIN_EMAIL);
        return res.status(200).json({ token: 'ADMIN_TOKEN_SECURE', user: adminUser });
    }

    // --- CLIENTES ---
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

authRoutes.get('/me', checkAuth, (req, res) => res.json(db.users[1]));
app.use('/api/auth', authRoutes);

// ==========================================
// 💸 ROTAS DE TRANSAÇÃO
// ==========================================
const txRoutes = express.Router();

txRoutes.post('/create', checkAuth, async (req, res) => {
    const { amount, description } = req.body;
    const user = db.users[1];
    const ip = getIp(req);

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

txRoutes.post('/withdraw', checkAuth, async (req, res) => {
    const { amount, pixKey, pixKeyType, description } = req.body;
    const user = db.users[1];
    const ip = getIp(req);

    if (!amount || !pixKey || !pixKeyType) return res.status(400).json({ error: "Dados incompletos" });

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
        if (!misticRes.ok) return res.status(400).json({ error: data.message || 'Erro MisticPay' });

        const novaTx = formatarTransacao(data, 'RETIRADA', user, ip, description);
        if(!novaTx.transactionState) novaTx.transactionState = "COMPLETO";
        db.transactions.unshift(novaTx);
        res.json(novaTx);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Erro de conexão' });
    }
});

txRoutes.get('/', checkAuth, (req, res) => {
    // Retorna a lista completa para preencher a tabela do Dashboard
    res.json({ success: true, transactions: db.transactions });
});

app.use('/api/transactions', txRoutes);

// ==========================================
// 🔑 ROTAS AUXILIARES E ADMIN
// ==========================================
const credRoutes = express.Router();
credRoutes.get('/', checkAuth, (req, res) => res.json(db.credentials['2'] || { hasCredentials: false }));
credRoutes.post('/generate', checkAuth, (req, res) => {
    const nc = { hasCredentials: true, clientId: 'live_'+Date.now(), clientSecret: 'sk_'+Date.now(), createdAt: new Date() };
    db.credentials['2'] = nc; 
    res.json(nc);
});
credRoutes.delete('/', checkAuth, (req, res) => { delete db.credentials['2']; res.json({success:true});});
app.use('/api/credentials', credRoutes);

// Rotas de Usuários (Para a aba de Clientes)
app.get('/api/users', (req, res) => res.json(db.users));
app.put('/api/users/:id/status', (req, res) => {
    const u = db.users.find(x => x.id == req.params.id);
    if(u) { u.status = req.body.status; res.json({success:true}); } 
    else res.status(404).json({error:'User not found'});
});

// Inicialização
app.listen(PORT, () => {
    console.log(`✅ SERVIDOR COMPLETO RODANDO NA PORTA ${PORT}`);
    console.log(`🔒 SEGURANÇA IP: ATIVA [${IP_SEGURO_ADMIN}]`);
    console.log(`📊 DADOS: ${db.transactions.length} transações e ${db.users.length} usuários carregados.`);
});
