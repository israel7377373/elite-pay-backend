require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// 🔐 CREDENCIAIS E CONFIGURAÇÕES DE SEGURANÇA
// ==========================================
const MISTIC_CI = process.env.CI || 'ci_jbbmajuwwmq28hv'; 
const MISTIC_CS = process.env.CS || 'cs_isxps89xg5jodulumlayuy40d'; 
const MISTIC_URL = 'https://api.misticpay.com'; 

// --- CONFIGURAÇÃO DO ADMIN ---
const ADMIN_EMAIL = 'admin@pay.com';
const ADMIN_PASS = 'admin';

// 🛑 IP DE SEGURANÇA MÁXIMA (SEU IP)
const IP_SEGURO_ADMIN = '201.19.113.159'; 

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(bodyParser.json());

// ==========================================
// 🛠️ FUNÇÃO DE IP CORRIGIDA (AGORA VAI FUNCIONAR)
// ==========================================

const getIp = (req) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    
    // 1. Se vier como Array (caso raro), pega o primeiro elemento
    if (Array.isArray(ip)) {
        ip = ip[0];
    }

    // 2. Se vier como string com vírgula (O SEU CASO: "201.xx, 172.xx"), corta na vírgula
    if (typeof ip === 'string' && ip.includes(',')) {
        ip = ip.split(',')[0]; // Pega só a primeira parte antes da vírgula
    }

    // 3. Limpa espaços e prefixos IPv6
    if (typeof ip === 'string') {
        return ip.trim().replace('::ffff:', '');
    }
    
    return '';
};

// 2. Formatar Transação
const formatarTransacao = (dados, tipo, usuario, ip, descricaoExtra) => {
    return {
        id: (db.transactions.length + 1).toString(),
        value: Number(dados.amount || dados.transactionAmount || dados.value || 0),
        fee: dados.transactionFee || 0.50,
        clientName: usuario.name,
        clientDocument: "000.000.000-00",
        externalId: dados.transactionId || dados.externalId || dados.id || `loc_${Date.now()}`,
        description: descricaoExtra || dados.description || (tipo === 'DEPOSITO' ? 'Depósito Elite Pay' : 'Saque Elite Pay'),
        transactionState: dados.transactionState || "PENDENTE",
        transactionMethod: "PIX",
        transactionType: tipo,
        requestIp: ip,
        userId: usuario.id,
        updatedAt: new Date().toISOString(),
        createdAt: dados.createdAt || new Date().toISOString()
    };
};

// ==========================================
// 🧪 DADOS INICIAIS
// ==========================================

const transacoesIniciais = [
    {
        id: "1", value: 50.00, fee: 0.50, clientName: "Cliente Teste", 
        description: "Depósito Inicial", externalId: "019506c8-d275...", 
        transactionState: "PENDENTE", transactionMethod: "PIX", transactionType: "DEPOSITO", 
        requestIp: "127.0.0.1", userId: 2, createdAt: new Date().toISOString()
    },
    {
        id: "2", value: 120.00, fee: 1.00, clientName: "Israel Roza Silva", 
        description: "Saque Elite Pay", externalId: "c73841b5-c8e3...", 
        transactionState: "COMPLETO", transactionMethod: "PIX", transactionType: "RETIRADA", 
        requestIp: "127.0.0.1", userId: 2, createdAt: new Date(Date.now() - 3600000).toISOString()
    }
];

const db = {
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0 },
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
    
    // Obtém o IP limpo
    const ipAtual = getIp(req);

    console.log(`📡 LOGIN TENTATIVA | Email: ${email} | IP Detectado: [${ipAtual}]`);

    // --- LÓGICA DE ADMIN ---
    if (email === ADMIN_EMAIL) {
        if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
        
        // Compara o IP limpo com o IP seguro
        if (ipAtual !== IP_SEGURO_ADMIN) {
            console.log(`🚫 ALERTA: IP ${ipAtual} BLOQUEADO (Esperado: ${IP_SEGURO_ADMIN})`);
            return res.status(403).json({ 
                error: 'ACESSO NEGADO: IP não autorizado.',
                seu_ip: ipAtual 
            });
        }

        console.log(`✅ SUCESSO: Admin logado pelo IP ${ipAtual}`);
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
    res.json({ success: true, transactions: db.transactions });
});

app.use('/api/transactions', txRoutes);

// ==========================================
// 🔑 ROTAS AUXILIARES
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

// Rotas Admin Simples
app.get('/api/users', (req, res) => res.json(db.users));
app.put('/api/users/:id/status', (req, res) => {
    const u = db.users.find(x => x.id == req.params.id);
    if(u) { u.status = req.body.status; res.json({success:true}); } 
    else res.status(404).json({error:'User not found'});
});

// Inicialização
app.listen(PORT, () => {
    console.log(`✅ SERVIDOR COMPLETO RODANDO NA PORTA ${PORT}`);
    console.log(`🔒 SEGURANÇA MÁXIMA ATIVA: IP ${IP_SEGURO_ADMIN}`);
});
