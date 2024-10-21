const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Função de registro
exports.register = async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ username, email, password: hashedPassword });
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, user });
    } catch (err) {
        res.status(500).json({ error: 'Erro no registro de usuário' });
    }
};

//função de login

exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ where: { email } });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Email ou senha inválidos" });
        }
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, user });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao fazer login' });
    }
};