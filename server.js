require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 🔐 CREDENCIAIS E CONFIGURAÇÕES
// ==========================================
const MISTIC_CI = process.env.CI || 'ci_jbbmajuwwmq28hv'; // Seu CI Real ou Fallback
const MISTIC_CS = process.env.CS || 'cs_isxps89xg5jodulumlayuy40d'; // Seu CS Real ou Fallback
const MISTIC_URL = 'https://api.misticpay.com'; 

// Configurações do Admin
const ADMIN_EMAIL = 'admin@pay.com';
const ADMIN_PASS = 'admin';
const IP_SEGURO_ADMIN = '201.19.113.159'; // IP web
const SIMULAR_HACKER = false; // Mude para true para testar bloqueio

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(bodyParser.json());

// ==========================================
// 🛠️ FUNÇÕES AUXILIARES
// ==========================================

// 1. Pegar IP Real
function getIp(req) {
    if (SIMULAR_HACKER) return '192.168.55.99';
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    return (ip === '::1') ? '127.0.0.1' : ip;
}

// 2. Formatar Transação (ESSENCIAL PARA A TABELA FICAR BONITA)
// Transforma dados da Mistic ou Mock no formato padrão que o site espera
const formatarTransacao = (dados, tipo, usuario, ip, descricaoExtra) => {
    return {
        id: (db.transactions.length + 1).toString(),
        value: Number(dados.amount || dados.transactionAmount || dados.value || 0),
        fee: dados.transactionFee || 0.50,
        clientName: usuario.name,
        clientDocument: "000.000.000-00",
        externalId: dados.transactionId || dados.externalId || dados.id || `loc_${Date.now()}`,
        description: descricaoExtra || dados.description || (tipo === 'DEPOSITO' ? 'Depósito Elite Pay' : 'Saque Elite Pay'),
        transactionState: dados.transactionState || "PENDENTE", // PENDENTE, COMPLETO, FALHA
        transactionMethod: "PIX",
        transactionType: tipo, // "DEPOSITO" ou "RETIRADA"
        requestIp: ip,
        userId: usuario.id,
        updatedAt: new Date().toISOString(),
        createdAt: dados.createdAt || new Date().toISOString()
    };
};

// ==========================================
// 🧪 DADOS INICIAIS (MOCK DB)
// ==========================================

// Transações de exemplo para a tabela já começar cheia
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
    },
    {
        id: "3", value: 1500.00, fee: 0.00, clientName: "JANISLENE ROSA", 
        description: "Depósito Grande", externalId: "2ddce17e-66a6...", 
        transactionState: "COMPLETO", transactionMethod: "PIX", transactionType: "DEPOSITO", 
        requestIp: "127.0.0.1", userId: 2, createdAt: new Date(Date.now() - 86400000).toISOString()
    }
];

const db = {
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0 },
    ],
    transactions: [...transacoesIniciais], // Começa com os dados acima
    credentials: {
        '2': { hasCredentials: true, clientId: 'live_demo123', clientSecret: 'sk_demo123', createdAt: new Date() }
    },
    allowedIps: []
};

// Middleware Auth (Simplificado)
const checkAuth = (req, res, next) => {
    // Para facilitar testes, aceita qualquer request que tenha header Authorization
    // Em produção, você validaria o token aqui
    if (req.headers['authorization']) return next();
    return res.status(401).json({ error: 'Token inválido' });
};

// ==========================================
// 🚀 ROTAS DE LOGIN (COM BLOQUEIO IP)
// ==========================================
const authRoutes = express.Router();

authRoutes.post('/login', (req, res) => {
    const { email, password, senha } = req.body;
    const pass = password || senha;
    const ipAtual = getIp(req);

    console.log(`👤 Tentativa Login: ${email} | IP: ${ipAtual}`);

    // --- ADMIN (Bloqueio IP) ---
    if (email === ADMIN_EMAIL) {
        if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
        
        if (ipAtual !== IP_SEGURO_ADMIN) {
            console.log(`❌ BLOQUEIO ADMIN: IP ${ipAtual} não autorizado.`);
            return res.status(403).json({ error: 'ACESSO BLOQUEADO: IP não autorizado.' });
        }

        const adminUser = db.users.find(u => u.email === ADMIN_EMAIL);
        return res.status(200).json({ token: 'ADMIN_TOKEN_SECURE', user: adminUser });
    }

    // --- CLIENTES (Livre de IP) ---
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
// 💸 ROTAS DE TRANSAÇÃO (MISTIC PAY + FORMAT)
// ==========================================
const txRoutes = express.Router();

// 1. CRIAR DEPÓSITO (Cash-In)
txRoutes.post('/create', checkAuth, async (req, res) => {
    const { amount, description } = req.body;
    const user = db.users[1]; // Simula usuário logado
    const ip = getIp(req);

    console.log(`🔄 Gerando Depósito PIX R$ ${amount}...`);

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

        // Salva Formatado
        const novaTx = formatarTransacao(
            { ...data, transactionState: 'PENDENTE' }, 
            'DEPOSITO', user, ip, description
        );
        
        db.transactions.unshift(novaTx); // Adiciona no topo
        res.json(novaTx);

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Erro de conexão' });
    }
});

// 2. CRIAR SAQUE (Cash-Out)
txRoutes.post('/withdraw', checkAuth, async (req, res) => {
    const { amount, pixKey, pixKeyType, description } = req.body;
    const user = db.users[1];
    const ip = getIp(req);

    console.log(`💸 Solicitando Saque R$ ${amount} para ${pixKey}...`);

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

        // Salva Formatado
        const novaTx = formatarTransacao(
            data, // Geralmente a resposta já vem completa no saque
            'RETIRADA', user, ip, description
        );
        
        // Ajuste de status se necessário
        if(!novaTx.transactionState) novaTx.transactionState = "COMPLETO";

        db.transactions.unshift(novaTx);
        res.json(novaTx);

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Erro de conexão' });
    }
});

// 3. LISTAR TODAS (Para a tabela)
txRoutes.get('/', checkAuth, (req, res) => {
    res.json({ success: true, transactions: db.transactions });
});

app.use('/api/transactions', txRoutes);

// ==========================================
// 🔑 ROTAS DE CREDENCIAIS E IPS (MANTIDAS)
// ==========================================
const credRoutes = express.Router();

credRoutes.get('/', checkAuth, (req, res) => res.json(db.credentials['2'] || { hasCredentials: false }));

credRoutes.post('/generate', checkAuth, (req, res) => {
    const nc = { hasCredentials: true, clientId: 'live_'+Date.now(), clientSecret: 'sk_'+Date.now(), createdAt: new Date() };
    db.credentials['2'] = nc; 
    res.json(nc);
});

credRoutes.delete('/', checkAuth, (req, res) => { delete db.credentials['2']; res.json({success:true});});

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
// 📊 ROTAS DO ADMIN (LISTAR E ALTERAR STATUS)
// ==========================================
app.get('/api/users', (req, res) => res.json(db.users));
app.get('/api/logs', (req, res) => res.json([])); // Logs vazio por enquanto

app.put('/api/users/:id/status', (req, res) => {
    const u = db.users.find(x => x.id == req.params.id);
    if(u) { u.status = req.body.status; res.json({success:true}); } 
    else res.status(404).json({error:'User not found'});
});

// Iniciar
app.listen(PORT, () => {
    console.log(`✅ SERVIDOR COMPLETO RODANDO NA PORTA ${PORT}`);
    console.log(`🔒 Proteção Admin IP: ATIVADA`);
});

