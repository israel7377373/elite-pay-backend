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
// 🛠️ FUNÇÃO DE IP BLINDADA
// ==========================================
const getIp = (req) => {
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    if (Array.isArray(ip)) ip = ip[0];
    if (typeof ip === 'string' && ip.includes(',')) {
        ip = ip.split(',')[0]; 
    }
    if (typeof ip === 'string') {
        return ip.trim().replace('::ffff:', '');
    }
    return '';
};

// ==========================================
// 🧪 BANCO DE DADOS (COM LISTA DE SUGESTÕES)
// ==========================================
const db = {
    users: [
        { id: 1, email: 'admin@pay.com', password: 'admin', status: 'ATIVO', name: 'Administrador', role: 'admin', saldoCents: 0, daily_stats: { transactionCount: 0, totalReceived: 0 } },
        { id: 2, email: 'cliente@teste.com', password: '123', status: 'ATIVO', name: 'Cliente Teste', role: 'user', saldoCents: 10000, daily_stats: { transactionCount: 2, totalReceived: 10000 } },
        { id: 3, email: 'israel@email.com', password: '123', status: 'ATIVO', name: 'Israel Roza Silva', role: 'user', saldoCents: 50000, daily_stats: { transactionCount: 5, totalReceived: 35000 } },
        { id: 4, email: 'janislene@email.com', password: '123', status: 'ATIVO', name: 'JANISLENE ROSA DE ASSIS', role: 'user', saldoCents: 25000, daily_stats: { transactionCount: 1, totalReceived: 5000 } },
        { id: 5, email: 'inacio@email.com', password: '123', status: 'PENDENTE', name: 'INACIO LENNON MORAES', role: 'user', saldoCents: 0, daily_stats: { transactionCount: 0, totalReceived: 0 } },
    ],
    // Histórico inicial para a tabela não ficar vazia
    transactions: [
        { id: "1", valorLiquido: 150.00, valorBruto: 150.00, taxaMinha: 0, taxaApi: 0, descricao: "Depósito Inicial", status: "PENDENTE", tipo: "deposito", metodo: "PIX", criadoEm: new Date().toISOString() },
        { id: "2", valorLiquido: 1250.00, valorBruto: 1250.00, taxaMinha: 0, taxaApi: 0, descricao: "Saque Elite Pay", status: "aprovado", tipo: "saque", metodo: "PIX", criadoEm: new Date().toISOString() }
    ],
    credentials: {
        '2': { hasCredentials: true, clientId: 'live_jbbmajuwwmq28hv', clientSecret: 'sk_isxps89xg5jodulumlayuy40d', createdAt: new Date().toISOString() }
    },
    allowedIps: []
};


// ==========================================
// 🔒 MIDDLEWARE AUTHENTICATION (CORRIGIDO PARA O FRONT-END)
// ==========================================
const checkAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    // 1. O Front-end envia 'Bearer TOKEN_ID'
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('🚫 Falha Auth: Header ou Bearer faltando.');
        return res.status(401).json({ error: 'Token inválido' });
    }

    const token = authHeader.split(' ')[1]; // Pega o TOKEN_ID
    
    // 2. Verifica Admin
    if (token === 'ADMIN_TOKEN_SECURE') {
        req.user = db.users.find(u => u.role === 'admin');
        if (req.user) return next();
        console.log('🚫 Falha Auth: Admin token inválido.');
        return res.status(401).json({ error: 'Token inválido' });
    }
    
    // 3. Verifica Cliente (TOKEN_[ID])
    if (token.startsWith('TOKEN_')) {
        const userId = parseInt(token.replace('TOKEN_', ''));
        req.user = db.users.find(u => u.id === userId && u.status === 'ATIVO');
        
        if (req.user) {
            console.log(`✅ Auth OK para User ID: ${userId}`);
            return next();
        }
    }
    
    // 4. Se não autenticou de nenhuma forma
    console.log(`🚫 Falha Auth: Token desconhecido ou inativo. Recebido: ${token}`);
    return res.status(401).json({ error: 'Token inválido' });
};

// ==========================================
// 🚀 ROTAS DE LOGIN (COM A TRAVA DE IP)
// ==========================================
const authRoutes = express.Router();

authRoutes.post('/login', (req, res) => {
    const { email, password, senha } = req.body;
    const pass = password || senha;
    const ipAtual = getIp(req); 

    console.log(`📡 LOGIN | Email: ${email} | IP Detectado: [${ipAtual}]`);

    // --- BLOQUEIO DE SEGURANÇA ADMIN ---
    if (email === ADMIN_EMAIL) {
        if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Senha incorreta' });
        
        if (ipAtual !== IP_SEGURO_ADMIN) {
            console.log(`🚫 ADMIN BLOQUEADO: IP ${ipAtual} não é ${IP_SEGURO_ADMIN}`);
            return res.status(403).json({ 
                error: 'ACESSO NEGADO: IP não autorizado.',
                ip_detectado: ipAtual 
            });
        }

        console.log(`✅ ADMIN LIBERADO: IP ${ipAtual}`);
        const adminUser = db.users.find(u => u.email === ADMIN_EMAIL);
        // Retorna o token simples para o Front-end
        return res.status(200).json({ token: 'ADMIN_TOKEN_SECURE', user: adminUser });
    }

    // --- LOGIN DE CLIENTES (SEM BLOQUEIO DE IP) ---
    const user = db.users.find(u => u.email === email && (u.password === pass));
    
    if (!user) return res.status(401).json({ error: 'Login incorreto' });
    if (user.status !== 'ATIVO') return res.status(403).json({ error: 'Conta pendente' });

    // Retorna o token simples para o Front-end
    res.status(200).json({ token: 'TOKEN_' + user.id, user });
});

authRoutes.post('/register', (req, res) => {
    const { email, name, password, cpf } = req.body;
    const newUser = { id: Date.now(), email, name, password, cpf, status: 'PENDENTE', role: 'user', saldoCents: 0, daily_stats: { transactionCount: 0, totalReceived: 0 } };
    db.users.push(newUser);
    res.status(201).json({ message: 'Cadastro realizado', user: newUser });
});

// A rota /me precisa do middleware de autenticação (checkAuth) para funcionar!
authRoutes.get('/me', checkAuth, (req, res) => {
    // req.user foi populado pelo checkAuth
    if (!req.user) return res.status(401).json({ error: 'Falha ao buscar perfil' });
    res.json(req.user);
});

app.use('/api/auth', authRoutes);

// ==========================================
// 💸 ROTAS DE TRANSAÇÃO (UTILIZA checkAuth)
// ==========================================
const txRoutes = express.Router();

txRoutes.post('/create', checkAuth, async (req, res) => {
    const { amount, description } = req.body;
    const userId = req.user.id;
    console.log(`🔄 [Backend] User ${userId} Gerando PIX de R$ ${amount}...`);

    try {
        // Simulação da chamada para a MisticPay, pois a URL real pode falhar
        const data = {
            transactionId: `ep_in_${Date.now()}`,
            qrcodeUrl: "https://placehold.co/256x256/22c55e/ffffff?text=PIX+R$"+amount,
            copyPaste: `13213213201.QRCODE.PIX.${Date.now()}`
        };

        // Adiciona à lista em memória (garantindo que o status e o tipo batam com o Front-end)
        db.transactions.unshift({ 
            id: data.transactionId, 
            valorLiquido: Number(amount), 
            valorBruto: Number(amount), 
            taxaMinha: 0.00, 
            taxaApi: 0.00, 
            descricao: description || 'Depósito Elite Pay', 
            status: 'pendente', 
            tipo: 'deposito', 
            metodo: 'PIX', 
            criadoEm: new Date().toISOString() 
        });
        
        // Atualiza as estatísticas diárias (simulação)
        const user = db.users.find(u => u.id === userId);
        if (user) {
             user.saldoCents += Number(amount) * 100;
             user.daily_stats.transactionCount++;
             user.daily_stats.totalReceived += Number(amount);
        }

        res.json(data);

    } catch (error) {
        console.error('❌ Erro:', error);
        res.status(500).json({ error: 'Erro ao conectar API de Pix' });
    }
});

txRoutes.post('/withdraw', checkAuth, async (req, res) => {
    const { amount, description } = req.body;
    const userId = req.user.id;
    
    // Simulação de saque mantendo estrutura
    const txFee = 1.00;
    const totalAmount = Number(amount) + txFee;
    
    const user = db.users.find(u => u.id === userId);
    
    if (user.saldoCents < totalAmount * 100) {
         return res.status(402).json({ error: 'Saldo insuficiente para saque.' });
    }
    
    user.saldoCents -= totalAmount * 100;
    
    const novaTx = { 
        id: `out_${Date.now()}`, 
        valorLiquido: Number(amount), 
        valorBruto: totalAmount, 
        taxaMinha: txFee, 
        taxaApi: 0, 
        descricao: description || "Saque Solicitado", 
        status: "aprovado", 
        tipo: "saque", 
        metodo: "PIX", 
        criadoEm: new Date().toISOString() 
    };
    db.transactions.unshift(novaTx);
    
    // Reinicia as estatísticas diárias para o refresh funcionar corretamente
    user.daily_stats = { transactionCount: 0, totalReceived: 0 };
    
    res.json(novaTx);
});

// A rota de histórico de transações agora usa o checkAuth
txRoutes.get('/', checkAuth, (req, res) => {
    // No Backend simulado, retorna todas as transações, mas em um sistema real, filtraria por req.user.id
    res.json({ success: true, transactions: db.transactions });
});

app.use('/api/transactions', txRoutes);

// ==========================================
// 🔑 ROTAS AUXILIARES E ADMIN
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
        createdAt: new Date().toISOString()
    };
    db.credentials[req.user.id] = newCreds;
    res.json(newCreds);
});

credRoutes.delete('/', checkAuth, (req, res) => {
    delete db.credentials[req.user.id];
    res.json({ success: true });
});

// IPs
credRoutes.get('/ips', checkAuth, (req, res) => res.json({ ips: db.allowedIps }));
credRoutes.post('/ips', checkAuth, (req, res) => {
    const newIp = { id: Math.random(), ip_address: req.body.ip, criado_em: new Date().toISOString() };
    db.allowedIps.push(newIp);
    res.json(newIp);
});
credRoutes.delete('/ips/:id', checkAuth, (req, res) => {
    db.allowedIps = db.allowedIps.filter(i => i.id != req.params.id);
    res.json({ success: true });
});

app.use('/api/credentials', credRoutes);

// --- ROTAS DO ADMIN (UTILIZA checkAuth) ---
app.get('/api/users', checkAuth, (req, res) => {
    // No sistema real, faria a trava de role: 'admin' aqui
    res.json(db.users);
});

app.get('/api/logs', checkAuth, (req, res) => res.json([]));

app.put('/api/users/:id/status', checkAuth, (req, res) => {
    const user = db.users.find(u => u.id == req.params.id);
    if (user) { 
        user.status = req.body.status; 
        res.json({ success: true }); 
    }
    else res.status(404).json({ error: 'User not found' });
});

app.listen(PORT, () => {
    console.log(`✅ SERVIDOR RODANDO NA PORTA ${PORT}`);
    console.log(`🔒 SEGURANÇA ADMIN ATIVA: IP ${IP_SEGURO_ADMIN}`);
    console.log(`ℹ️ MODO: SIMULAÇÃO DE BACKEND`);
});

