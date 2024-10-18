import { Request, Response } from 'express';
import { User } from '../models/User';
import nodemailer, { SendMailOptions } from 'nodemailer';
import { Jwt } from 'jsonwebtoken';
const bcrypt = require('bcrypt');

const generateRandomPassword = (length = 8) => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    let password = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        password += characters[randomIndex];
    }
    return password;
};

export const register = async (req: Request, res: Response) => {
    const { email, password, name, discipline } = req.body;

    if (!email || !/\S+@\S+\.\S+/.test(email)) {
        console.error('Erro de validação: E-mail inválido.');
        return res.status(400).json({ error: 'E-mail inválido.' });
    }

    if (!password || password.length < 6) {
        console.error('Erro de validação: A senha deve ter pelo menos 6 caracteres.');
        return res.status(400).json({ error: 'A senha deve ter pelo menos 6 caracteres.' });
    }
    if (!name || name.trim().length === 0) {
        console.error('Erro de validação: O nome é obrigatório.');
        return res.status(400).json({ error: 'O nome é obrigatório.' });
    }
    
    if (!discipline || discipline.trim().length === 0) {
        console.error('Erro de validação: A disciplina é obrigatória.');
        return res.status(400).json({ error: 'A disciplina é obrigatória.' });
    }

    try {
        console.log('Verificando se o usuário já existe...');
        let hasUser = await User.findOne({ where: { email } });

        if (!hasUser) {
            console.log('Usuário não encontrado. Criando novo usuário...');
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            
            let newUser = await User.create({
                email,
                password: hashedPassword,
                name,
                discipline
            });
            console.log('Usuário cadastrado com sucesso:', newUser);
            res.status(201).json({ message: 'Usuário cadastrado com sucesso.', newUser });
        } else {
            console.log('Usuário já existe com este e-mail:', email);
            res.status(400).json({ error: 'Usuário já existe.' });
        }
    } catch (error) {
        console.error('Erro ao cadastrar usuário:', error);
        res.status(500).json({ error: 'Erro interno ao processar o registro.' });
    }
};

    export const login = async (req: Request, res: Response) => {
        const { email, password } = req.body;
    
        if (email && password) {
            try {
                console.log('Buscando usuário para login com e-mail:', email);
                let user = await User.findOne({ where: { email } });
    
                if (user && await bcrypt.compare(password, user.password)) {
                    console.log('Login bem-sucedido para o usuário:', email);
                    res.json({ status: true });
                } else {
                    console.log('Falha no login. Credenciais inválidas para:', email);
                    res.status(401).json({ status: false, error: 'Credenciais inválidas.' });
                }
            } catch (error) {
                console.error('Erro ao fazer login:', error);
                res.status(500).json({ error: 'Erro interno ao processar o login.' });
            }
        } else {
            res.status(400).json({ error: 'E-mail e senha não fornecidos.' });
        }
    };

export const listAll = async (req: Request, res: Response) => {
    try {
        console.log('Listando todos os usuários...');
        let users = await User.findAll();
        console.log('Usuários encontrados:', users);
        res.json({ users });
    } catch (error) {
        console.error('Erro ao listar usuários:', error);
        res.status(500).json({ error: 'Erro interno ao listar usuários.' });
    }
};

export const forgotPassword = async (req: Request, res: Response) => {
    const { email } = req.params;

    try {
        console.log('Iniciando recuperação de senha para o usuário:', email);
        const hasUser = await User.findOne({ where: { email } });

        if (!hasUser) {
            console.log('Usuário não encontrado para recuperação de senha:', email);
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }
        const randomPassword = generateRandomPassword();
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(randomPassword, saltRounds);

        hasUser.password = hashedPassword; 
        await hasUser.save();
        console.log('Senha do usuário atualizada com sucesso.');
    
        const transporter = nodemailer.createTransport({
            host: 'sandbox.smtp.mailtrap.io',
            port: 2525,
            auth: {
                user: '3c06f9dbdde467',
                pass: 'b338ed92a62e61',
            },
        });

        const mailOptions = {
            from: 'seu-email@dominio.com',
            to: email,
            subject: 'Recuperação de senha',
            text: `Sua nova senha é: ${randomPassword}`, 
        };
        
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Erro ao enviar o e-mail:', error);
                res.status(500).json({ error: 'Erro ao enviar e-mail de recuperação de senha.' });
            } else {
                console.log('E-mail enviado:', info.response);
                res.status(200).json({ message: 'Nova senha enviada para o seu e-mail.' });
            }
        });
    
    } catch (error) {
        console.error('Erro ao recuperar a sennha:', error);
        res.status(500).json({ error: 'Erro interno ao processar a recuperação de senha.' });
    } 
};